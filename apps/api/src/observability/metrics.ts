import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from 'prom-client';

export function createMetrics() {
  const registry = new Registry();
  collectDefaultMetrics({ register: registry });
  const scans = new Counter({
    name: 'repoguard_scans_total',
    help: 'Scans by terminal or submitted status',
    labelNames: ['status'],
    registers: [registry],
  });
  const duration = new Histogram({
    name: 'repoguard_scan_duration_seconds',
    help: 'Scan duration',
    buckets: [1, 5, 15, 30, 60, 120, 300, 600],
    registers: [registry],
  });
  const queueDepth = new Gauge({ name: 'repoguard_queue_depth', help: 'Queued scans', registers: [registry] });
  const running = new Gauge({ name: 'repoguard_running_scans', help: 'Running scans', registers: [registry] });
  const sse = new Gauge({ name: 'repoguard_sse_connections', help: 'Open event streams', registers: [registry] });
  return { registry, scans, duration, queueDepth, running, sse };
}

export type Metrics = ReturnType<typeof createMetrics>;
