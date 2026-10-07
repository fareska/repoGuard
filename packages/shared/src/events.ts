import type { FindingCounts, RiskLevel, ScanErrorRef } from './types.js';

export const SCAN_EVENT_TYPES = [
  'scan.queued',
  'scan.started',
  'stage.started',
  'stage.progress',
  'stage.completed',
  'stage.failed',
  'stage.skipped',
  'findings.updated',
  'log',
  'scan.completed',
  'scan.failed',
  'scan.cancelled',
] as const;

export type ScanEventType = (typeof SCAN_EVENT_TYPES)[number];
export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface ScanEventBase {
  scanId: string;
  seq: number;
  ts: string;
}

export type ScanEvent = ScanEventBase &
  (
    | { type: 'scan.queued'; payload: { position: number } }
    | { type: 'scan.started'; payload: { workerId: string } }
    | { type: 'stage.started'; payload: { stageId: string } }
    | {
        type: 'stage.progress';
        payload: { stageId: string; progress: number; message?: string; stats?: Record<string, number> };
      }
    | { type: 'stage.completed'; payload: { stageId: string; stats?: Record<string, number> } }
    | { type: 'stage.failed'; payload: { stageId: string; error: ScanErrorRef } }
    | { type: 'stage.skipped'; payload: { stageId: string; reason: string } }
    | { type: 'findings.updated'; payload: FindingCounts }
    | { type: 'log'; payload: { level: LogLevel; message: string; stageId?: string } }
    | { type: 'scan.completed'; payload: { reportId: string; summary: { riskLevel: RiskLevel; counts: FindingCounts['bySeverity'] } } }
    | { type: 'scan.failed'; payload: { error: ScanErrorRef } }
    | { type: 'scan.cancelled'; payload: { by: 'user' | 'system'; reason?: string } }
  );
