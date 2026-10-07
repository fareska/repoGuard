import type { ErrorCode } from '@repoguard/shared';
import { isAbortError } from '../../domain/failures.js';

export class UpstreamError extends Error {
  constructor(
    readonly code: ErrorCode,
    message: string,
    readonly status = 0,
    readonly retryAfterMs?: number,
  ) {
    super(message);
    this.name = 'UpstreamError';
  }
}

export class CircuitBreaker {
  private failures = 0;
  private openUntil = 0;

  constructor(
    private readonly threshold: number,
    private readonly openMs: number,
  ) {}

  assertClosed(): void {
    if (Date.now() < this.openUntil) {
      throw new UpstreamError('UPSTREAM_UNAVAILABLE', 'Upstream circuit breaker is open');
    }
  }

  success(): void {
    this.failures = 0;
  }

  failure(): void {
    this.failures += 1;
    if (this.failures >= this.threshold) this.openUntil = Date.now() + this.openMs;
  }
}

export class TtlCache<T> {
  private readonly entries = new Map<string, { value: T; expires: number }>();

  constructor(private readonly maxEntries = 4000) {}

  get(key: string): T | undefined {
    const hit = this.entries.get(key);
    if (!hit) return undefined;
    if (hit.expires <= Date.now()) {
      this.entries.delete(key);
      return undefined;
    }
    this.entries.delete(key);
    this.entries.set(key, hit);
    return hit.value;
  }

  set(key: string, value: T, ttlMs: number): void {
    if (this.entries.size >= this.maxEntries) {
      const oldest = this.entries.keys().next().value;
      if (oldest) this.entries.delete(oldest);
    }
    this.entries.set(key, { value, expires: Date.now() + ttlMs });
  }
}

export class Inflight {
  private readonly pending = new Map<string, Promise<unknown>>();

  run<T>(key: string, load: () => Promise<T>): Promise<T> {
    const existing = this.pending.get(key) as Promise<T> | undefined;
    if (existing) return existing;
    const promise = load().finally(() => this.pending.delete(key));
    this.pending.set(key, promise);
    return promise;
  }
}

export interface FetchOptions {
  breaker: CircuitBreaker;
  signal: AbortSignal;
  retries: number;
  timeoutMs: number;
  headers?: Record<string, string>;
}

export async function fetchUpstream(url: string, options: FetchOptions & { method?: string; body?: string }): Promise<Response> {
  options.breaker.assertClosed();
  let lastError: UpstreamError | undefined;
  for (let attempt = 0; attempt < options.retries; attempt += 1) {
    try {
      const response = await fetch(url, {
        method: options.method ?? 'GET',
        headers: options.headers,
        body: options.body,
        redirect: 'follow',
        signal: AbortSignal.any([options.signal, AbortSignal.timeout(options.timeoutMs)]),
      });
      if (response.status === 429 || response.status >= 500) {
        options.breaker.failure();
        lastError = new UpstreamError(
          response.status === 429 ? 'RATE_LIMITED_UPSTREAM' : 'UPSTREAM_UNAVAILABLE',
          `Upstream responded ${response.status}`,
          response.status,
          retryAfterMs(response.headers.get('retry-after')),
        );
        if (attempt === options.retries - 1) throw lastError;
        await sleep(lastError.retryAfterMs ?? backoff(attempt), options.signal);
        continue;
      }
      options.breaker.success();
      return response;
    } catch (error) {
      if (isAbortError(error) && options.signal.aborted) throw error;
      if (error instanceof UpstreamError && attempt === options.retries - 1) throw error;
      options.breaker.failure();
      lastError = error instanceof UpstreamError ? error : new UpstreamError('UPSTREAM_UNAVAILABLE', 'Upstream request failed');
      if (attempt === options.retries - 1) break;
      await sleep(backoff(attempt), options.signal);
    }
  }
  if (lastError instanceof UpstreamError) throw lastError;
  throw new UpstreamError('UPSTREAM_UNAVAILABLE', 'Upstream request failed');
}

function retryAfterMs(header: string | null): number | undefined {
  if (!header) return undefined;
  const seconds = Number(header);
  if (Number.isFinite(seconds)) return seconds * 1000;
  const date = Date.parse(header);
  if (Number.isNaN(date)) return undefined;
  return Math.max(0, date - Date.now());
}

function backoff(attempt: number): number {
  const base = 250 * 2 ** attempt;
  return base + Math.floor(Math.random() * 200);
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        const error = new Error('Aborted');
        error.name = 'AbortError';
        reject(error);
      },
      { once: true },
    );
  });
}
