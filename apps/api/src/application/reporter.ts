import { countsOf, type Finding, type ScanEvent } from '@repoguard/shared';
import type { Config } from '../config/env.js';
import { finalizeFinding, type RawFinding } from '../domain/findings.js';
import type { SqliteScanRepository } from '../infrastructure/persistence/sqlite.js';
import { OptimisticLockError } from '../infrastructure/persistence/sqlite.js';
import type { EventBus } from '../infrastructure/events/bus.js';
import { redactSecrets } from '../infrastructure/scanners/secrets.js';
import type { ProgressReporter } from '../infrastructure/scanners/types.js';

type Emit = (type: ScanEvent['type'], payload: ScanEvent['payload']) => void;

export function createStageReporter(
  config: Config,
  emit: Emit,
  stageId: string,
  onFinding: (finding: ReturnType<typeof finalizeFinding>) => void,
): { reporter: ProgressReporter; flush: () => Promise<void> } {
  let progress = 0;
  let message: string | undefined;
  let dirty = false;
  let timer: NodeJS.Timeout | undefined;
  let lastFlush = 0;

  const flush = async () => {
    if (timer) clearTimeout(timer);
    timer = undefined;
    if (!dirty) return;
    dirty = false;
    lastFlush = Date.now();
    emit('stage.progress', {
      stageId,
      progress,
      ...(message ? { message } : {}),
    });
  };

  const schedule = () => {
    dirty = true;
    const wait = Math.max(0, config.PROGRESS_FLUSH_MS - (Date.now() - lastFlush));
    if (timer) return;
    timer = setTimeout(() => void flush(), wait);
  };

  const reporter: ProgressReporter = {
    progress(fraction, nextMessage) {
      progress = Math.max(progress, Math.min(0.99, fraction));
      if (nextMessage) message = nextMessage;
      schedule();
    },
    log(level, text) {
      if (level === 'debug' && config.SCAN_LOG_LEVEL !== 'debug') return;
      const rank = { debug: 0, info: 1, warn: 2, error: 3 } as const;
      if (rank[level] < rank[config.SCAN_LOG_LEVEL]) return;
      emit('log', { level, message: redactSecrets(text).slice(0, 500), stageId });
    },
    finding(raw: RawFinding) {
      onFinding(finalizeFinding(raw));
    },
  };

  return { reporter, flush };
}

export class ScanWriter {
  constructor(
    private readonly repository: SqliteScanRepository,
    private readonly bus: EventBus,
  ) {}

  emit(scanId: string, type: ScanEvent['type'], payload: ScanEvent['payload']): void {
    const { event } = this.append(scanId, type, payload);
    this.bus.publish(event);
  }

  counts(scanId: string, findings: Pick<Finding, 'adjustedSeverity'>[]): void {
    this.emit(scanId, 'findings.updated', countsOf(findings));
  }

  private append(scanId: string, type: ScanEvent['type'], payload: ScanEvent['payload']) {
    let last: unknown;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        return this.repository.append(scanId, { type, payload });
      } catch (error) {
        if (!(error instanceof OptimisticLockError)) throw error;
        last = error;
      }
    }
    throw last;
  }
}
