import { describe, expect, it } from 'vitest';
import { applyScanEvent } from '@repoguard/shared';
import { buildStages } from '@repoguard/shared';
import { emptyCounts, scanLinks, type ScanSnapshot } from '@repoguard/shared';

function snapshot(): ScanSnapshot {
  return {
    id: 'scn_test',
    status: 'queued',
    mode: 'mock',
    repo: { url: 'https://github.com/acme/shop', owner: 'acme', name: 'shop' },
    progress: { percent: 0, currentStage: null, stages: buildStages([{ id: 'mock', displayName: 'Simulated scan', weight: 65 }]) },
    counts: { findings: 0, bySeverity: emptyCounts() },
    error: null,
    createdAt: '2026-01-01T00:00:00.000Z',
    startedAt: null,
    updatedAt: '2026-01-01T00:00:00.000Z',
    finishedAt: null,
    lastEventSeq: 0,
    links: scanLinks('scn_test'),
  };
}

describe('progress reducer', () => {
  it('never decreases and reaches 100 only when terminal', () => {
    let scan = applyScanEvent(snapshot(), { scanId: 'scn_test', seq: 1, ts: '2026-01-01T00:00:01.000Z', type: 'scan.started', payload: { workerId: 'w' } });
    scan = applyScanEvent(scan, { scanId: 'scn_test', seq: 2, ts: '2026-01-01T00:00:02.000Z', type: 'stage.started', payload: { stageId: 'fetch' } });
    scan = applyScanEvent(scan, { scanId: 'scn_test', seq: 3, ts: '2026-01-01T00:00:03.000Z', type: 'stage.progress', payload: { stageId: 'fetch', progress: 0.5 } });
    const mid = scan.progress.percent;
    scan = applyScanEvent(scan, { scanId: 'scn_test', seq: 4, ts: '2026-01-01T00:00:04.000Z', type: 'stage.progress', payload: { stageId: 'fetch', progress: 0.1 } });
    expect(scan.progress.percent).toBeGreaterThanOrEqual(mid);
    expect(scan.progress.percent).toBeLessThan(100);
    scan = applyScanEvent(scan, { scanId: 'scn_test', seq: 5, ts: '2026-01-01T00:00:05.000Z', type: 'scan.completed', payload: { reportId: 'scn_test', summary: { riskLevel: 'clean', counts: emptyCounts() } } });
    expect(scan.status).toBe('completed');
    expect(scan.progress.percent).toBe(100);
    const ignored = applyScanEvent(scan, { scanId: 'scn_test', seq: 6, ts: '2026-01-01T00:00:06.000Z', type: 'stage.progress', payload: { stageId: 'fetch', progress: 0 } });
    expect(ignored).toBe(scan);
  });

  it('caps triage below 100', () => {
    let scan = snapshot();
    scan = applyScanEvent(scan, { scanId: 'scn_test', seq: 1, ts: '2026-01-01T00:00:01.000Z', type: 'stage.started', payload: { stageId: 'triage' } });
    for (const stage of scan.progress.stages) {
      if (stage.id !== 'triage') scan = applyScanEvent(scan, { scanId: 'scn_test', seq: scan.lastEventSeq + 1, ts: '2026-01-01T00:00:02.000Z', type: 'stage.completed', payload: { stageId: stage.id } });
    }
    scan = applyScanEvent(scan, { scanId: 'scn_test', seq: scan.lastEventSeq + 1, ts: '2026-01-01T00:00:03.000Z', type: 'stage.progress', payload: { stageId: 'triage', progress: 1 } });
    expect(scan.status).toBe('triaging');
    expect(scan.progress.percent).toBeLessThan(100);
  });
});
