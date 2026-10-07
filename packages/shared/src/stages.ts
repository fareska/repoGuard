import type { Stage, StageStatus } from './types.js';

export const FETCH_WEIGHT = 15;
export const TRIAGE_WEIGHT = 20;
export const SCAN_WEIGHT = 65;

export function distributeWeights(total: number, parts: number[]): number[] {
  if (parts.length === 0) return [];
  const sum = parts.reduce((totalWeight, part) => totalWeight + part, 0);
  const basis = sum > 0 ? parts : parts.map(() => 1);
  const basisSum = basis.reduce((totalWeight, part) => totalWeight + part, 0);
  const exact = basis.map((part) => (total * part) / basisSum);
  const weights = exact.map((value) => Math.floor(value));
  let remainder = total - weights.reduce((totalWeight, part) => totalWeight + part, 0);
  const order = exact
    .map((value, index) => ({ index, fraction: value - Math.floor(value) }))
    .sort((left, right) => right.fraction - left.fraction || left.index - right.index);
  for (const item of order) {
    if (remainder <= 0) break;
    const current = weights[item.index];
    if (current === undefined) continue;
    weights[item.index] = current + 1;
    remainder -= 1;
  }
  return weights;
}

export function buildStages(scanners: { id: string; displayName: string; weight: number }[]): Stage[] {
  const scanWeights = distributeWeights(
    SCAN_WEIGHT,
    scanners.map((scanner) => scanner.weight),
  );
  return [
    pendingStage('fetch', 'Fetching repository', FETCH_WEIGHT),
    ...scanners.map((scanner, index) =>
      pendingStage(`scan:${scanner.id}`, scanner.displayName, scanWeights[index] ?? 0),
    ),
    pendingStage('triage', 'Prioritizing risks', TRIAGE_WEIGHT),
  ];
}

function pendingStage(id: string, label: string, weight: number): Stage {
  return { id, label, status: 'pending' satisfies StageStatus, weight, progress: 0 };
}

export function aggregatePercent(stages: Stage[], terminal: boolean, previous: number): number {
  if (terminal) return 100;
  const raw = Math.round(
    stages.reduce((sum, stage) => {
      const fraction = stage.status === 'failed' || stage.status === 'skipped' ? 1 : clamp(stage.progress);
      return sum + stage.weight * fraction;
    }, 0),
  );
  return Math.max(previous, Math.min(raw, 99));
}

function clamp(value: number): number {
  if (Number.isNaN(value)) return 0;
  return Math.min(1, Math.max(0, value));
}
