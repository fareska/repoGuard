import {
  buildStages,
  emptyCounts,
  isTerminal,
  parseRepoUrl,
  problem,
  scanLinks,
  type Finding,
  type Page,
  type Report,
  type RequestedMode,
  type ScanMode,
  type ScanSnapshot,
  type ScanStatus,
  type ScanSummary,
} from '@repoguard/shared';
import type { Config } from '../config/env.js';
import { createId } from '../domain/findings.js';
import { AppError } from '../domain/failures.js';
import { assertTransition } from '../domain/stateMachine.js';
import type { EventBus } from '../infrastructure/events/bus.js';
import { decodeCursor, type SqliteScanRepository } from '../infrastructure/persistence/sqlite.js';
import { QueueFullError, type InProcessJobQueue } from '../infrastructure/queue/inProcess.js';
import { scannersForMode, type createScanners } from '../infrastructure/scanners/registry.js';
import type { Scanner } from '../infrastructure/scanners/types.js';
import { buildReport } from './orchestrator.js';
import { ScanWriter } from './reporter.js';
import { ruleTriage } from '../infrastructure/triage/rules.js';

type ScannerList = ReturnType<typeof createScanners>;

export class ScanService {
  private readonly writer: ScanWriter;

  constructor(
    private readonly config: Config,
    private readonly repository: SqliteScanRepository,
    private readonly queue: InProcessJobQueue,
    private readonly scanners: ScannerList,
    bus: EventBus,
  ) {
    this.writer = new ScanWriter(repository, bus);
  }

  create(input: { repoUrl: string; ref?: string; mode?: RequestedMode; scanners?: string[] }, idempotencyKey?: string): { snapshot: ScanSnapshot; created: boolean } {
    const parsed = parseRepoUrl(input.repoUrl);
    if (!parsed) throw new AppError('INVALID_REPO_URL', 400, 'Use a public GitHub URL such as https://github.com/owner/name.');
    const mode = this.resolveMode(input.mode);
    if (idempotencyKey) {
      const existingId = this.repository.getIdempotency(idempotencyKey, Date.now(), this.config.IDEMPOTENCY_TTL_MS);
      const existing = existingId ? this.repository.get(existingId) : null;
      if (existing) return { snapshot: existing.snapshot, created: false };
    }
    const ref = input.ref || parsed.ref || '';
    if (this.config.DEDUPE_INFLIGHT) {
      const inflight = this.repository.findInflight(parsed.owner, parsed.name, ref, mode);
      if (inflight) return { snapshot: inflight.snapshot, created: false };
    }
    const selected = this.selectScanners(mode, input.scanners);
    const id = createId('scn');
    const now = new Date().toISOString();
    const snapshot: ScanSnapshot = {
      id,
      status: 'queued',
      mode,
      repo: { url: parsed.url, owner: parsed.owner, name: parsed.name, ...(ref ? { ref } : {}) },
      progress: { percent: 0, currentStage: null, stages: buildStages(selected) },
      counts: { findings: 0, bySeverity: emptyCounts() },
      error: null,
      createdAt: now,
      startedAt: null,
      updatedAt: now,
      finishedAt: null,
      lastEventSeq: 0,
      links: scanLinks(id),
    };
    this.repository.create({ snapshot, version: 1, cancelRequested: false, riskLevel: null });
    if (idempotencyKey) this.repository.saveIdempotency(idempotencyKey, id, now);
    const position = this.queue.stats().queued + 1;
    try {
      this.writer.emit(id, 'scan.queued', { position });
      this.queue.enqueue({ scanId: id });
    } catch (error) {
      this.repository.delete(id);
      if (error instanceof QueueFullError) throw new AppError('QUEUE_FULL', 503, 'Too many scans are waiting. Try again in a moment.');
      throw error;
    }
    const stored = this.repository.get(id);
    return { snapshot: stored?.snapshot ?? snapshot, created: true };
  }

  get(id: string): ScanSnapshot {
    const record = this.require(id);
    if (record.snapshot.status === 'queued') {
      const position = this.queue.position(id);
      if (position) record.snapshot.progress.queuePosition = position;
    }
    return record.snapshot;
  }

  list(query: { status?: ScanStatus; limit: number; cursor?: string }): Page<ScanSummary> {
    const cursor = query.cursor ? decodeCursor(query.cursor) : null;
    if (query.cursor && !cursor) throw new AppError('INVALID_REPO_URL', 400, 'The cursor is not valid.');
    return this.repository.list({ status: query.status, limit: query.limit, ...(cursor ? { cursor } : {}) });
  }

  result(id: string): Report {
    const record = this.require(id);
    const report = this.repository.getReport(id);
    if (report) return report;
    if (record.snapshot.status === 'failed' || record.snapshot.status === 'cancelled') {
      const findings = this.repository.listFindings(id);
      if (findings.length > 0) {
        return buildReport({
          scanId: id,
          repo: record.snapshot.repo,
          findings,
          output: ruleTriage({ repoName: record.snapshot.repo.name, findings, languages: [], scannersRun: [] }),
          provider: 'rules',
          coverage: {
            partial: true,
            scannersRun: [],
            scannersFailed: [],
            scannersSkipped: [],
            manifestsFound: [],
            filesScanned: 0,
            filesSkipped: { count: 0, reasons: {} },
            durationMs: 0,
            unsupportedEcosystems: [],
          },
        });
      }
    }
    throw new AppError('NOT_READY', 409, `The scan is ${record.snapshot.status}.`);
  }

  findings(id: string, query: { severity?: string; category?: string; scanner?: string; limit: number; cursor?: string }): Page<Finding> {
    this.require(id);
    const all = this.repository
      .listFindings(id)
      .filter((finding) => !query.severity || finding.adjustedSeverity === query.severity)
      .filter((finding) => !query.category || finding.category === query.category)
      .filter((finding) => !query.scanner || finding.scanner === query.scanner)
      .sort((left, right) => right.adjustedSeverity.localeCompare(left.adjustedSeverity) || left.id.localeCompare(right.id));
    const start = query.cursor ? all.findIndex((finding) => finding.id === query.cursor) + 1 : 0;
    if (query.cursor && start <= 0) throw new AppError('NOT_FOUND', 400, 'The findings cursor is not valid.');
    const items = all.slice(start, start + query.limit);
    const next = all[start + query.limit];
    return { items, ...(next ? { nextCursor: next.id } : {}) };
  }

  cancel(id: string): ScanSnapshot {
    const record = this.require(id);
    if (isTerminal(record.snapshot.status)) throw new AppError('ILLEGAL_TRANSITION', 409, 'The scan is already finished.');
    if (record.snapshot.status === 'queued') {
      this.queue.cancel(id);
      assertTransition(record.snapshot.status, 'cancelled');
      this.writer.emit(id, 'scan.cancelled', { by: 'user' });
      return this.require(id).snapshot;
    }
    this.repository.markCancelRequested(id);
    this.queue.cancel(id);
    return this.require(id).snapshot;
  }

  delete(id: string): void {
    if (!this.repository.delete(id)) throw new AppError('NOT_FOUND', 404, 'That scan does not exist.');
  }

  infos() {
    return this.scanners.map((scanner) => ({
      id: scanner.id,
      displayName: scanner.displayName,
      description: scanner.description,
      weight: scanner.weight,
    }));
  }

  private require(id: string) {
    const record = this.repository.get(id);
    if (!record) throw new AppError('NOT_FOUND', 404, 'That scan does not exist.');
    return record;
  }

  private resolveMode(requested?: RequestedMode): ScanMode {
    if (requested === 'mock') {
      if (!this.config.ALLOW_MOCK_MODE) throw new AppError('MOCK_MODE_DISABLED', 400, 'Mock mode is turned off on this server.');
      return 'mock';
    }
    if (requested === 'real') return 'real';
    return this.config.SCAN_MODE;
  }

  private selectScanners(mode: ScanMode, requested?: string[]): Scanner[] {
    try {
      const selected = scannersForMode(this.scanners, mode, requested);
      if (selected.length === 0) throw new Error('none');
      return selected;
    } catch (error) {
      if (error instanceof Error && error.name === 'UnknownScannerError') {
        throw new AppError('UNKNOWN_SCANNER', 400, error.message);
      }
      throw new AppError('UNKNOWN_SCANNER', 400, 'Choose at least one scanner.');
    }
  }
}

export const errorBody = problem;
