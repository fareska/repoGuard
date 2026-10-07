import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import fastifyStatic from '@fastify/static';
import { ZodError, z } from 'zod';
import Fastify from 'fastify';
import { SCAN_EVENT_TYPES, SCAN_STATUSES, problem, type ScanEvent } from '@repoguard/shared';
import type { Config } from '../config/env.js';
import { ScanService } from '../application/scanService.js';
import { AppError } from '../domain/failures.js';
import type { EventBus } from '../infrastructure/events/bus.js';
import type { SqliteScanRepository } from '../infrastructure/persistence/sqlite.js';
import type { InProcessJobQueue } from '../infrastructure/queue/inProcess.js';
import { ECOSYSTEM_CATALOG } from '../infrastructure/manifests/registry.js';
import type { Metrics } from '../observability/metrics.js';
import type { AppLogger } from '../observability/logger.js';
import { openApi, privacy } from './spec.js';

const createBody = z.object({
  repoUrl: z.string().min(1),
  ref: z.string().min(1).max(250).optional(),
  mode: z.enum(['real', 'mock']).optional(),
  scanners: z.array(z.string()).optional(),
});

const listQuery = z.object({
  status: z.enum(SCAN_STATUSES).optional(),
  limit: z.coerce.number().int().positive().max(100).default(20),
  cursor: z.string().optional(),
});

const findingQuery = z.object({
  severity: z.string().optional(),
  category: z.string().optional(),
  scanner: z.string().optional(),
  limit: z.coerce.number().int().positive().max(200).default(50),
  cursor: z.string().optional(),
});

export interface AppDeps {
  config: Config;
  logger: AppLogger;
  service: ScanService;
  repository: SqliteScanRepository;
  queue: InProcessJobQueue;
  bus: EventBus;
  metrics: Metrics;
}

export async function buildApp(deps: AppDeps) {
  const app = Fastify({
    loggerInstance: deps.logger,
    bodyLimit: deps.config.BODY_LIMIT_BYTES,
  });
  await app.register(helmet, { contentSecurityPolicy: false });
  await app.register(cors, { origin: deps.config.corsOrigins });
  await app.register(rateLimit, {
    global: true,
    max: deps.config.RATE_LIMIT_READ_MAX,
    timeWindow: deps.config.RATE_LIMIT_READ_WINDOW_MS,
  });

  app.setErrorHandler((error, request, reply) => {
    if (error instanceof ZodError) {
      return reply.code(400).send(problem('INVALID_REPO_URL', 400, error.issues.map((issue) => issue.message).join('; ')));
    }
    if (error instanceof AppError) {
      if (error.code === 'QUEUE_FULL') reply.header('retry-after', '30');
      return reply.code(error.statusCode).send(problem(error.code, error.statusCode, error.message, error.scanId));
    }
    const statusCode = statusCodeOf(error);
    if (statusCode === 429) {
      reply.header('retry-after', '30');
      return reply.code(429).send(problem('QUEUE_FULL', 429, 'Too many requests.'));
    }
    request.log.error({ err: error }, 'request failed');
    return reply.code(statusCode >= 400 ? statusCode : 500).send(problem('INTERNAL', 500));
  });

  app.get('/healthz', async () => ({ ok: true }));
  app.get('/readyz', async (_request, reply) => {
    try {
      deps.repository.get('__ready__');
      if (!deps.queue.accepting) return reply.code(503).send({ ok: false });
      return { ok: true };
    } catch {
      return reply.code(503).send({ ok: false });
    }
  });
  app.get('/metrics', async (request, reply) => {
    if (deps.config.METRICS_TOKEN) {
      const header = request.headers.authorization;
      if (header !== `Bearer ${deps.config.METRICS_TOKEN}`) return reply.code(401).send(problem('REPO_PRIVATE_OR_FORBIDDEN', 401, 'Metrics require a token.'));
    }
    deps.metrics.queueDepth.set(deps.queue.stats().queued);
    deps.metrics.running.set(deps.queue.stats().running);
    deps.metrics.sse.set(deps.bus.listenerCount());
    reply.header('content-type', deps.metrics.registry.contentType);
    return reply.send(await deps.metrics.registry.metrics());
  });
  app.get('/api/v1/openapi.json', async () => openApi);
  app.get('/api/docs', async (_request, reply) => {
    reply.type('text/html');
    return `<!doctype html><html><head><title>RepoGuard API</title><link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css"></head><body><div id="ui"></div><script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script><script>SwaggerUIBundle({url:'/api/v1/openapi.json',dom_id:'#ui'})</script></body></html>`;
  });
  app.get('/api/v1/privacy', async () => privacy);
  app.get('/api/v1/scanners', async () => ({
    scanners: deps.service.infos(),
    ecosystems: ECOSYSTEM_CATALOG,
    allowMockMode: deps.config.ALLOW_MOCK_MODE,
    defaultMode: deps.config.SCAN_MODE,
  }));

  app.post('/api/v1/scans', { config: { rateLimit: { max: deps.config.RATE_LIMIT_SCAN_MAX, timeWindow: deps.config.RATE_LIMIT_SCAN_WINDOW_MS } } }, async (request, reply) => {
    const body = createBody.parse(request.body);
    const key = headerValue(request.headers['idempotency-key']);
    const result = deps.service.create(body, key);
    deps.metrics.scans.inc({ status: result.created ? 'submitted' : 'deduped' });
    reply.header('location', result.snapshot.links.self);
    return reply.code(result.created ? 202 : 200).send(result.snapshot);
  });

  app.get('/api/v1/scans', async (request) => {
    const query = listQuery.parse(request.query);
    return deps.service.list(query);
  });

  app.get('/api/v1/scans/:id', async (request, reply) => {
    const snapshot = deps.service.get((request.params as { id: string }).id);
    if (snapshot.status !== 'completed' && snapshot.status !== 'failed' && snapshot.status !== 'cancelled') {
      reply.header('retry-after', '2');
    }
    return snapshot;
  });

  app.get('/api/v1/scans/:id/result', async (request) => deps.service.result((request.params as { id: string }).id));
  app.get('/api/v1/scans/:id/findings', async (request) => {
    const query = findingQuery.parse(request.query);
    return deps.service.findings((request.params as { id: string }).id, query);
  });
  app.post('/api/v1/scans/:id/cancel', async (request, reply) => {
    const snapshot = deps.service.cancel((request.params as { id: string }).id);
    return reply.code(202).send(snapshot);
  });
  app.delete('/api/v1/scans/:id', async (request, reply) => {
    deps.service.delete((request.params as { id: string }).id);
    return reply.code(204).send();
  });

  app.get('/api/v1/scans/:id/events', async (request, reply) => {
    const scanId = (request.params as { id: string }).id;
    const after = Math.max(numberHeader(request.headers['last-event-id']), Number((request.query as { afterSeq?: string }).afterSeq ?? 0));
    deps.service.get(scanId);
    const ip = request.ip;
    if (deps.bus.listenerCount(scanId) >= deps.config.SSE_MAX_PER_SCAN || !claimStream(ip, deps.config.SSE_MAX_PER_IP)) {
      reply.header('retry-after', '2');
      return reply.code(429).send(problem('QUEUE_FULL', 429, 'Too many streams for this scan.'));
    }
    reply.hijack();
    deps.metrics.sse.inc();
    reply.raw.writeHead(200, {
      'content-type': 'text/event-stream; charset=utf-8',
      'cache-control': 'no-cache, no-transform',
      connection: 'keep-alive',
      'x-accel-buffering': 'no',
    });
    let closed = false;
    let maxSeq = after;
    const write = (event: ScanEvent) => {
      if (closed || event.seq <= maxSeq) return;
      maxSeq = event.seq;
      reply.raw.write(`id: ${event.seq}\nevent: ${event.type}\ndata: ${JSON.stringify(event.payload)}\n\n`);
      if (event.type === 'scan.completed' || event.type === 'scan.failed' || event.type === 'scan.cancelled') close();
    };
    const pending: ScanEvent[] = [];
    let ready = false;
    const unsubscribe = deps.bus.subscribe(scanId, (event) => {
      if (!ready) pending.push(event);
      else write(event);
    });
    for (const event of deps.repository.listEvents(scanId, after)) write(event);
    ready = true;
    for (const event of pending) write(event);
    const snapshot = deps.repository.get(scanId);
    if (snapshot && (snapshot.snapshot.status === 'completed' || snapshot.snapshot.status === 'failed' || snapshot.snapshot.status === 'cancelled')) close();
    const keepalive = setInterval(() => {
      if (!closed) reply.raw.write(': keepalive\n\n');
    }, deps.config.SSE_KEEPALIVE_MS);
    request.raw.on('close', close);
    function close() {
      if (closed) return;
      closed = true;
      clearInterval(keepalive);
      unsubscribe();
      releaseStream(ip);
      deps.metrics.sse.dec();
      reply.raw.end();
    }
  });

  const webDist = deps.config.WEB_DIST ?? resolve(process.cwd(), 'apps/web/dist');
  if (existsSync(webDist)) {
    await app.register(fastifyStatic, { root: webDist });
    app.setNotFoundHandler((request, reply) => {
      if (request.url.startsWith('/api/') || request.url.startsWith('/metrics')) {
        return reply.code(404).send(problem('NOT_FOUND', 404, 'That route does not exist.'));
      }
      return reply.sendFile('index.html');
    });
  }

  return app;
}

const streamsByIp = new Map<string, number>();

function claimStream(ip: string, max: number): boolean {
  const current = streamsByIp.get(ip) ?? 0;
  if (current >= max) return false;
  streamsByIp.set(ip, current + 1);
  return true;
}

function releaseStream(ip: string): void {
  const next = (streamsByIp.get(ip) ?? 1) - 1;
  if (next <= 0) streamsByIp.delete(ip);
  else streamsByIp.set(ip, next);
}

function statusCodeOf(error: unknown): number {
  if (typeof error === 'object' && error && 'statusCode' in error && typeof error.statusCode === 'number') return error.statusCode;
  return 500;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  const trimmed = raw?.trim();
  return trimmed || undefined;
}

function numberHeader(value: string | string[] | undefined): number {
  const raw = Array.isArray(value) ? value[0] : value;
  const parsed = Number(raw ?? 0);
  return Number.isFinite(parsed) ? parsed : 0;
}

export const eventTypes = SCAN_EVENT_TYPES;
