import { resolve } from 'node:path';
import { loadConfig, type Config } from './config/env.js';
import { ScanOrchestrator } from './application/orchestrator.js';
import { ScanService } from './application/scanService.js';
import { AppError } from './domain/failures.js';
import { EnrichmentClient } from './infrastructure/enrichment/client.js';
import { CircuitBreaker } from './infrastructure/enrichment/http.js';
import { EventBus } from './infrastructure/events/bus.js';
import { GitHubClient } from './infrastructure/github/client.js';
import { openDatabase, SqliteScanRepository } from './infrastructure/persistence/sqlite.js';
import { InProcessJobQueue } from './infrastructure/queue/inProcess.js';
import { createScanners } from './infrastructure/scanners/registry.js';
import { createLogger } from './observability/logger.js';
import { createMetrics } from './observability/metrics.js';
import { buildApp } from './http/app.js';
import { assertTransition } from './domain/stateMachine.js';
import { ScanWriter } from './application/reporter.js';

export interface Application {
  app: Awaited<ReturnType<typeof buildApp>>;
  config: Config;
  shutdown: () => Promise<void>;
}

export async function createApplication(config: Config = loadConfig()): Promise<Application> {
  const logger = createLogger(config);
  const db = openDatabase(config.DATABASE_URL === ':memory:' ? ':memory:' : resolve(config.DATABASE_URL));
  const repository = new SqliteScanRepository(db);
  const bus = new EventBus();
  const queue = new InProcessJobQueue({ maxConcurrent: config.MAX_CONCURRENT_SCANS, maxQueueLength: config.MAX_QUEUE_LENGTH });
  const breakers = {
    osv: new CircuitBreaker(config.CIRCUIT_FAILURES, config.CIRCUIT_OPEN_MS),
    deps: new CircuitBreaker(config.CIRCUIT_FAILURES, config.CIRCUIT_OPEN_MS),
    epss: new CircuitBreaker(config.CIRCUIT_FAILURES, config.CIRCUIT_OPEN_MS),
    kev: new CircuitBreaker(config.CIRCUIT_FAILURES, config.CIRCUIT_OPEN_MS),
    github: new CircuitBreaker(config.CIRCUIT_FAILURES, config.CIRCUIT_OPEN_MS),
  };
  const fetchOptions = { retries: config.UPSTREAM_RETRIES, timeoutMs: config.UPSTREAM_TIMEOUT_MS };
  const enrichment = new EnrichmentClient({
    osvBaseUrl: config.OSV_BASE_URL,
    depsDevBaseUrl: config.DEPS_DEV_BASE_URL,
    epssUrl: config.EPSS_URL,
    kevUrl: config.KEV_URL,
    osvTtlMs: config.ENRICHMENT_CACHE_TTL_OSV_MS,
    depsTtlMs: config.ENRICHMENT_CACHE_TTL_DEPS_MS,
    exploitTtlMs: config.ENRICHMENT_CACHE_TTL_EXPLOIT_MS,
    batchSize: config.OSV_BATCH_SIZE,
    fetch: fetchOptions,
    breakers,
  });
  const github = new GitHubClient(config, breakers.github);
  const scanners = createScanners(config, enrichment, github);
  const orchestrator = new ScanOrchestrator(config, repository, bus, github, scanners, logger);
  const service = new ScanService(config, repository, queue, scanners, bus);
  const metrics = createMetrics();
  recover(repository, queue, bus);
  queue.process((job, signal) => orchestrator.run(job.scanId, signal));
  const watchdog = setInterval(() => failStale(repository, queue, bus, config.STALE_AFTER_MS), config.WATCHDOG_INTERVAL_MS);
  const retention = setInterval(() => repository.prune(new Date(), config.RETENTION_EVENT_DAYS, config.RETENTION_REPORT_DAYS), 6 * 60 * 60 * 1000);
  const app = await buildApp({ config, logger, service, repository, queue, bus, metrics });
  return {
    app,
    config,
    shutdown: async () => {
      clearInterval(watchdog);
      clearInterval(retention);
      orchestrator.markShuttingDown();
      queue.pause();
      await queue.drain(config.SHUTDOWN_GRACE_MS);
      await app.close();
      db.close();
    },
  };
}

function recover(repository: SqliteScanRepository, queue: InProcessJobQueue, bus: EventBus): void {
  const writer = new ScanWriter(repository, bus);
  for (const record of repository.listActive()) {
    if (record.snapshot.status === 'queued') {
      try {
        queue.enqueue({ scanId: record.snapshot.id });
      } catch {
        writer.emit(record.snapshot.id, 'scan.failed', { error: { code: 'QUEUE_FULL', message: 'Could not restore the queued scan' } });
      }
      continue;
    }
    try {
      assertTransition(record.snapshot.status, 'failed');
      writer.emit(record.snapshot.id, 'scan.failed', {
        error: { code: 'INTERRUPTED', message: 'The scanner restarted before this scan finished' },
      });
    } catch {
      // A second boot should not fail a scan that already reached a terminal state.
    }
  }
}

function failStale(repository: SqliteScanRepository, queue: InProcessJobQueue, bus: EventBus, staleAfterMs: number): void {
  const writer = new ScanWriter(repository, bus);
  const cutoff = Date.now() - staleAfterMs;
  for (const record of repository.listActive()) {
    if (record.snapshot.status === 'queued') continue;
    if (Date.parse(record.snapshot.updatedAt) > cutoff) continue;
    queue.cancel(record.snapshot.id);
    try {
      writer.emit(record.snapshot.id, 'scan.failed', { error: { code: 'TIMEOUT', message: 'The scan stopped making progress' } });
    } catch {
      // The worker may have finished the scan between the list and the write.
    }
  }
}

export async function main(): Promise<void> {
  const application = await createApplication();
  const close = async () => {
    await application.shutdown();
    process.exit(0);
  };
  process.on('SIGINT', () => void close());
  process.on('SIGTERM', () => void close());
  await application.app.listen({ port: application.config.PORT, host: application.config.HOST });
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname)) {
  main().catch((error: unknown) => {
    const message = error instanceof AppError ? error.message : error instanceof Error ? error.message : 'startup failed';
    process.stderr.write(`${message}\n`);
    process.exit(1);
  });
}
