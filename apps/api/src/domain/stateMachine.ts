import type { ScanStatus } from '@repoguard/shared';

const TRANSITIONS: Record<ScanStatus, ScanStatus[]> = {
  queued: ['fetching', 'cancelled', 'failed'],
  fetching: ['analyzing', 'failed', 'cancelled'],
  analyzing: ['triaging', 'failed', 'cancelled'],
  triaging: ['completed', 'failed', 'cancelled'],
  completed: [],
  failed: [],
  cancelled: [],
};

export class IllegalTransitionError extends Error {
  constructor(
    readonly from: ScanStatus,
    readonly to: ScanStatus,
  ) {
    super(`Cannot move a scan from ${from} to ${to}`);
    this.name = 'IllegalTransitionError';
  }
}

export function assertTransition(from: ScanStatus, to: ScanStatus): void {
  if (from === to) return;
  if (!TRANSITIONS[from].includes(to)) throw new IllegalTransitionError(from, to);
}

export function allowedTransitions(): Record<ScanStatus, ScanStatus[]> {
  return TRANSITIONS;
}
