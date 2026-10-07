import type { ScanEvent } from './events.js';
import { aggregatePercent } from './stages.js';
import { isTerminal, type ScanSnapshot, type Stage } from './types.js';

export function applyScanEvent(snapshot: ScanSnapshot, event: ScanEvent): ScanSnapshot {
  if (isTerminal(snapshot.status)) return snapshot;
  const next = structuredClone(snapshot);
  next.updatedAt = event.ts;
  next.lastEventSeq = Math.max(snapshot.lastEventSeq, event.seq);

  switch (event.type) {
    case 'scan.queued':
      next.status = 'queued';
      next.progress.queuePosition = event.payload.position;
      break;
    case 'scan.started':
      next.status = 'fetching';
      next.startedAt ??= event.ts;
      next.progress.queuePosition = undefined;
      break;
    case 'stage.started':
      next.progress.currentStage = event.payload.stageId;
      next.progress.stages = mapStage(next.progress.stages, event.payload.stageId, (stage) => ({
        ...stage,
        status: 'running',
        startedAt: stage.startedAt ?? event.ts,
      }));
      next.status = statusForStage(event.payload.stageId, next.status);
      break;
    case 'stage.progress':
      next.progress.stages = mapStage(next.progress.stages, event.payload.stageId, (stage) => ({
        ...stage,
        progress: Math.max(stage.progress, clamp(event.payload.progress)),
        ...(event.payload.message !== undefined ? { message: event.payload.message } : {}),
        ...(event.payload.stats ? { stats: { ...stage.stats, ...event.payload.stats } } : {}),
      }));
      break;
    case 'stage.completed':
      next.progress.stages = mapStage(next.progress.stages, event.payload.stageId, (stage) => ({
        ...stage,
        status: 'completed',
        progress: 1,
        finishedAt: event.ts,
        ...(event.payload.stats ? { stats: { ...stage.stats, ...event.payload.stats } } : {}),
      }));
      break;
    case 'stage.failed':
      next.progress.stages = mapStage(next.progress.stages, event.payload.stageId, (stage) => ({
        ...stage,
        status: 'failed',
        progress: 1,
        finishedAt: event.ts,
        error: event.payload.error,
      }));
      break;
    case 'stage.skipped':
      next.progress.stages = mapStage(next.progress.stages, event.payload.stageId, (stage) => ({
        ...stage,
        status: 'skipped',
        progress: 1,
        finishedAt: event.ts,
        message: event.payload.reason,
      }));
      break;
    case 'findings.updated':
      next.counts = event.payload;
      break;
    case 'log':
      break;
    case 'scan.completed':
      next.status = 'completed';
      next.finishedAt = event.ts;
      next.progress.currentStage = null;
      next.progress.queuePosition = undefined;
      break;
    case 'scan.failed':
      next.status = 'failed';
      next.error = event.payload.error;
      next.finishedAt = event.ts;
      next.progress.currentStage = null;
      next.progress.queuePosition = undefined;
      next.progress.stages = settleOpenStages(next.progress.stages, event.ts, event.payload.error);
      break;
    case 'scan.cancelled':
      next.status = 'cancelled';
      next.finishedAt = event.ts;
      next.progress.currentStage = null;
      next.progress.queuePosition = undefined;
      next.progress.stages = settleOpenStages(next.progress.stages, event.ts);
      break;
    default:
      break;
  }

  next.progress.percent = aggregatePercent(next.progress.stages, isTerminal(next.status), snapshot.progress.percent);
  return next;
}

function statusForStage(stageId: string, current: ScanSnapshot['status']): ScanSnapshot['status'] {
  if (stageId === 'fetch') return 'fetching';
  if (stageId === 'triage') return 'triaging';
  if (stageId.startsWith('scan:')) return 'analyzing';
  return current;
}

function mapStage(stages: Stage[], stageId: string, update: (stage: Stage) => Stage): Stage[] {
  return stages.map((stage) => (stage.id === stageId ? update(stage) : stage));
}

function settleOpenStages(stages: Stage[], ts: string, error?: ScanSnapshot['error']): Stage[] {
  return stages.map((stage) => {
    if (stage.status === 'running') {
      return {
        ...stage,
        status: 'failed',
        progress: 1,
        finishedAt: ts,
        ...(error ? { error } : {}),
      };
    }
    if (stage.status === 'pending') {
      return { ...stage, status: 'skipped', progress: 1, finishedAt: ts, message: 'Scan ended before this stage' };
    }
    return stage;
  });
}

function clamp(value: number): number {
  if (Number.isNaN(value)) return 0;
  return Math.min(1, Math.max(0, value));
}
