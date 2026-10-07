import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import Database from 'better-sqlite3';
import {
  isTerminal,
  scanLinks,
  type Finding,
  type Page,
  type Report,
  type RiskLevel,
  type ScanEvent,
  type ScanEventType,
  type ScanSnapshot,
  type ScanStatus,
  type ScanSummary,
} from '@repoguard/shared';
import { applyScanEvent } from '@repoguard/shared';
import { IllegalTransitionError } from '../../domain/stateMachine.js';

export interface ScanRecord {
  snapshot: ScanSnapshot;
  version: number;
  cancelRequested: boolean;
  riskLevel: RiskLevel | null;
}

interface AppendDraft {
  type: ScanEventType;
  payload: ScanEvent['payload'];
  ts?: string;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL,
  mode TEXT NOT NULL,
  repo_json TEXT NOT NULL,
  progress_json TEXT NOT NULL,
  counts_json TEXT NOT NULL,
  error_json TEXT,
  risk_level TEXT,
  cancel_requested INTEGER NOT NULL DEFAULT 0,
  version INTEGER NOT NULL,
  last_seq INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  started_at TEXT,
  updated_at TEXT NOT NULL,
  finished_at TEXT
);
CREATE TABLE IF NOT EXISTS scan_events (
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  ts TEXT NOT NULL,
  type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  PRIMARY KEY (scan_id, seq)
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  fingerprint TEXT NOT NULL,
  scanner TEXT NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  adjusted_severity TEXT NOT NULL,
  confidence TEXT NOT NULL,
  data_json TEXT NOT NULL,
  UNIQUE (scan_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS reports (
  scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
  generated_at TEXT NOT NULL,
  report_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS idempotency_keys (
  key TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings (scan_id);
`;

export class OptimisticLockError extends Error {
  constructor() {
    super('Scan was updated by someone else');
    this.name = 'OptimisticLockError';
  }
}

interface ScanRow {
  id: string;
  status: string;
  mode: string;
  repo_json: string;
  progress_json: string;
  counts_json: string;
  error_json: string | null;
  risk_level: string | null;
  cancel_requested: number;
  version: number;
  last_seq: number;
  created_at: string;
  started_at: string | null;
  updated_at: string;
  finished_at: string | null;
}

export function openDatabase(databaseUrl: string): Database.Database {
  if (databaseUrl !== ':memory:') mkdirSync(dirname(databaseUrl), { recursive: true });
  const db = new Database(databaseUrl);
  db.pragma('foreign_keys = ON');
  if (databaseUrl !== ':memory:') db.pragma('journal_mode = WAL');
  db.exec(SCHEMA);
  return db;
}

export class SqliteScanRepository {
  private readonly insertScan;
  private readonly insertEvent;
  private readonly updateScan;
  private readonly touchScan;
  private readonly insertFinding;
  private readonly upsertReport;
  private readonly setRisk;

  constructor(private readonly db: Database.Database) {
    this.insertScan = db.prepare(`
      INSERT INTO scans (
        id, status, mode, repo_json, progress_json, counts_json, error_json, risk_level,
        cancel_requested, version, last_seq, created_at, started_at, updated_at, finished_at
      ) VALUES (
        @id, @status, @mode, @repo_json, @progress_json, @counts_json, @error_json, @risk_level,
        @cancel_requested, @version, @last_seq, @created_at, @started_at, @updated_at, @finished_at
      )
    `);
    this.insertEvent = db.prepare(`
      INSERT INTO scan_events (scan_id, seq, ts, type, payload_json)
      VALUES (@scan_id, @seq, @ts, @type, @payload_json)
    `);
    this.updateScan = db.prepare(`
      UPDATE scans SET
        status = @status,
        repo_json = @repo_json,
        progress_json = @progress_json,
        counts_json = @counts_json,
        error_json = @error_json,
        risk_level = @risk_level,
        cancel_requested = @cancel_requested,
        version = @version,
        last_seq = @last_seq,
        started_at = @started_at,
        updated_at = @updated_at,
        finished_at = @finished_at
      WHERE id = @id AND version = @expected_version
    `);
    this.touchScan = db.prepare(`
      UPDATE scans SET updated_at = @updated_at
      WHERE id = @id AND status NOT IN ('completed', 'failed', 'cancelled')
    `);
    this.insertFinding = db.prepare(`
      INSERT INTO findings (
        id, scan_id, fingerprint, scanner, category, severity, adjusted_severity, confidence, data_json
      ) VALUES (
        @id, @scan_id, @fingerprint, @scanner, @category, @severity, @adjusted_severity, @confidence, @data_json
      ) ON CONFLICT (scan_id, fingerprint) DO NOTHING
    `);
    this.upsertReport = db.prepare(`
      INSERT INTO reports (scan_id, generated_at, report_json)
      VALUES (@scan_id, @generated_at, @report_json)
      ON CONFLICT (scan_id) DO UPDATE SET generated_at = excluded.generated_at, report_json = excluded.report_json
    `);
    this.setRisk = db.prepare(`UPDATE scans SET risk_level = @risk_level WHERE id = @id`);
  }

  create(record: ScanRecord): void {
    this.insertScan.run(toParams(record));
  }

  get(id: string): ScanRecord | null {
    const row = this.db.prepare('SELECT * FROM scans WHERE id = ?').get(id) as ScanRow | undefined;
    return row ? fromRow(row) : null;
  }

  append(scanId: string, draft: AppendDraft): { record: ScanRecord; event: ScanEvent } {
    const write = this.db.transaction(() => {
      const current = this.mustGet(scanId);
      if (isTerminal(current.snapshot.status)) {
        throw new IllegalTransitionError(current.snapshot.status, current.snapshot.status);
      }
      const event = {
        scanId,
        seq: current.snapshot.lastEventSeq + 1,
        ts: draft.ts ?? new Date().toISOString(),
        type: draft.type,
        payload: draft.payload,
      } as ScanEvent;
      const snapshot = applyScanEvent(current.snapshot, event);
      const next: ScanRecord = { ...current, snapshot, version: current.version + 1 };
      const result = this.updateScan.run({ ...toParams(next), expected_version: current.version });
      if (result.changes !== 1) throw new OptimisticLockError();
      this.insertEvent.run({
        scan_id: scanId,
        seq: event.seq,
        ts: event.ts,
        type: event.type,
        payload_json: JSON.stringify(event.payload),
      });
      return { record: next, event };
    });
    return write();
  }

  touch(scanId: string, updatedAt: string): void {
    this.touchScan.run({ id: scanId, updated_at: updatedAt });
  }

  markCancelRequested(scanId: string): ScanRecord | null {
    const current = this.get(scanId);
    if (!current || isTerminal(current.snapshot.status)) return current;
    const next = { ...current, cancelRequested: true, version: current.version + 1 };
    const result = this.updateScan.run({ ...toParams(next), expected_version: current.version });
    if (result.changes !== 1) throw new OptimisticLockError();
    return next;
  }

  updateRepo(scanId: string, repo: import('@repoguard/shared').RepoRef): void {
    const current = this.get(scanId);
    if (!current || isTerminal(current.snapshot.status)) return;
    const next: ScanRecord = {
      ...current,
      version: current.version + 1,
      snapshot: { ...current.snapshot, repo: { ...current.snapshot.repo, ...repo } },
    };
    this.updateScan.run({ ...toParams(next), expected_version: current.version });
  }

  listEvents(scanId: string, afterSeq = 0): ScanEvent[] {
    const rows = this.db
      .prepare('SELECT scan_id, seq, ts, type, payload_json FROM scan_events WHERE scan_id = ? AND seq > ? ORDER BY seq')
      .all(scanId, afterSeq) as { scan_id: string; seq: number; ts: string; type: ScanEventType; payload_json: string }[];
    return rows.map((row) => ({
      scanId: row.scan_id,
      seq: row.seq,
      ts: row.ts,
      type: row.type,
      payload: JSON.parse(row.payload_json),
    })) as ScanEvent[];
  }

  saveFindings(scanId: string, findings: Finding[]): void {
    const write = this.db.transaction((items: Finding[]) => {
      for (const finding of items) {
        this.insertFinding.run({
          id: finding.id,
          scan_id: scanId,
          fingerprint: finding.fingerprint,
          scanner: finding.scanner,
          category: finding.category,
          severity: finding.severity,
          adjusted_severity: finding.adjustedSeverity,
          confidence: finding.confidence,
          data_json: JSON.stringify(finding),
        });
      }
    });
    write(findings);
  }

  listFindings(scanId: string): Finding[] {
    const rows = this.db.prepare('SELECT data_json FROM findings WHERE scan_id = ?').all(scanId) as { data_json: string }[];
    return rows.map((row) => JSON.parse(row.data_json) as Finding);
  }

  saveReport(report: Report): void {
    const write = this.db.transaction(() => {
      this.upsertReport.run({
        scan_id: report.scanId,
        generated_at: report.generatedAt,
        report_json: JSON.stringify(report),
      });
      this.setRisk.run({ id: report.scanId, risk_level: report.summary.riskLevel });
    });
    write();
  }

  getReport(scanId: string): Report | null {
    const row = this.db.prepare('SELECT report_json FROM reports WHERE scan_id = ?').get(scanId) as
      | { report_json: string }
      | undefined;
    return row ? (JSON.parse(row.report_json) as Report) : null;
  }

  list(query: { status?: ScanStatus; limit: number; cursor?: { createdAt: string; id: string } }): Page<ScanSummary> {
    const rows = this.db
      .prepare(
        `SELECT * FROM scans
         WHERE (@status IS NULL OR status = @status)
           AND (
             @cursor_created IS NULL
             OR created_at < @cursor_created
             OR (created_at = @cursor_created AND id < @cursor_id)
           )
         ORDER BY created_at DESC, id DESC
         LIMIT @limit`,
      )
      .all({
        status: query.status ?? null,
        cursor_created: query.cursor?.createdAt ?? null,
        cursor_id: query.cursor?.id ?? null,
        limit: query.limit + 1,
      }) as ScanRow[];
    const page = rows.slice(0, query.limit).map(toSummary);
    const extra = rows[query.limit];
    const last = page.at(-1);
    return {
      items: page,
      ...(extra && last ? { nextCursor: encodeCursor(last.createdAt, last.id) } : {}),
    };
  }

  listActive(): ScanRecord[] {
    const rows = this.db
      .prepare(`SELECT * FROM scans WHERE status IN ('queued', 'fetching', 'analyzing', 'triaging')`)
      .all() as ScanRow[];
    return rows.map(fromRow);
  }

  findInflight(owner: string, name: string, ref: string, mode: string): ScanRecord | null {
    return (
      this.listActive().find(
        (record) =>
          record.snapshot.mode === mode &&
          record.snapshot.repo.owner === owner &&
          record.snapshot.repo.name === name &&
          (record.snapshot.repo.ref ?? '') === ref,
      ) ?? null
    );
  }

  getIdempotency(key: string, now: number, ttlMs: number): string | null {
    const row = this.db.prepare('SELECT scan_id, created_at FROM idempotency_keys WHERE key = ?').get(key) as
      | { scan_id: string; created_at: string }
      | undefined;
    if (!row) return null;
    if (now - Date.parse(row.created_at) > ttlMs) {
      this.db.prepare('DELETE FROM idempotency_keys WHERE key = ?').run(key);
      return null;
    }
    return row.scan_id;
  }

  saveIdempotency(key: string, scanId: string, createdAt: string): void {
    this.db
      .prepare('INSERT OR REPLACE INTO idempotency_keys (key, scan_id, created_at) VALUES (?, ?, ?)')
      .run(key, scanId, createdAt);
  }

  delete(scanId: string): boolean {
    const write = this.db.transaction(() => {
      this.db.prepare('DELETE FROM idempotency_keys WHERE scan_id = ?').run(scanId);
      const result = this.db.prepare('DELETE FROM scans WHERE id = ?').run(scanId);
      return result.changes > 0;
    });
    return write();
  }

  prune(now: Date, eventDays: number, reportDays: number): void {
    const eventsBefore = new Date(now.getTime() - eventDays * 86_400_000).toISOString();
    const reportsBefore = new Date(now.getTime() - reportDays * 86_400_000).toISOString();
    this.db
      .prepare(
        `DELETE FROM scan_events WHERE ts < ? AND type IN ('stage.progress', 'log', 'findings.updated')`,
      )
      .run(eventsBefore);
    const old = this.db
      .prepare(`SELECT id FROM scans WHERE finished_at IS NOT NULL AND finished_at < ?`)
      .all(reportsBefore) as { id: string }[];
    for (const row of old) this.delete(row.id);
  }

  private mustGet(id: string): ScanRecord {
    const record = this.get(id);
    if (!record) throw new Error(`Scan ${id} disappeared`);
    return record;
  }
}

function toParams(record: ScanRecord) {
  const snapshot = record.snapshot;
  return {
    id: snapshot.id,
    status: snapshot.status,
    mode: snapshot.mode,
    repo_json: JSON.stringify(snapshot.repo),
    progress_json: JSON.stringify(snapshot.progress),
    counts_json: JSON.stringify(snapshot.counts),
    error_json: snapshot.error ? JSON.stringify(snapshot.error) : null,
    risk_level: record.riskLevel,
    cancel_requested: record.cancelRequested ? 1 : 0,
    version: record.version,
    last_seq: snapshot.lastEventSeq,
    created_at: snapshot.createdAt,
    started_at: snapshot.startedAt,
    updated_at: snapshot.updatedAt,
    finished_at: snapshot.finishedAt,
  };
}

function fromRow(row: ScanRow): ScanRecord {
  const snapshot: ScanSnapshot = {
    id: row.id,
    status: row.status as ScanSnapshot['status'],
    mode: row.mode as ScanSnapshot['mode'],
    repo: JSON.parse(row.repo_json),
    progress: JSON.parse(row.progress_json),
    counts: JSON.parse(row.counts_json),
    error: row.error_json ? JSON.parse(row.error_json) : null,
    createdAt: row.created_at,
    startedAt: row.started_at,
    updatedAt: row.updated_at,
    finishedAt: row.finished_at,
    lastEventSeq: row.last_seq,
    links: scanLinks(row.id),
  };
  return {
    snapshot,
    version: row.version,
    cancelRequested: row.cancel_requested === 1,
    riskLevel: row.risk_level as RiskLevel | null,
  };
}

function toSummary(row: ScanRow): ScanSummary {
  const repo = JSON.parse(row.repo_json) as ScanSnapshot['repo'];
  const progress = JSON.parse(row.progress_json) as ScanSnapshot['progress'];
  const counts = JSON.parse(row.counts_json) as ScanSnapshot['counts'];
  return {
    id: row.id,
    status: row.status as ScanSummary['status'],
    mode: row.mode as ScanSummary['mode'],
    repo: { url: repo.url, owner: repo.owner, name: repo.name },
    percent: progress.percent,
    findings: counts.findings,
    riskLevel: row.risk_level as RiskLevel | null,
    createdAt: row.created_at,
    finishedAt: row.finished_at,
  };
}

export function encodeCursor(createdAt: string, id: string): string {
  return Buffer.from(`${createdAt}|${id}`).toString('base64url');
}

export function decodeCursor(cursor: string): { createdAt: string; id: string } | null {
  try {
    const [createdAt, id] = Buffer.from(cursor, 'base64url').toString('utf8').split('|');
    if (!createdAt || !id) return null;
    return { createdAt, id };
  } catch {
    return null;
  }
}
