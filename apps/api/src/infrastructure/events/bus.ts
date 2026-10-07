import type { ScanEvent } from '@repoguard/shared';

export class EventBus {
  private readonly listeners = new Map<string, Set<(event: ScanEvent) => void>>();

  publish(event: ScanEvent): void {
    for (const listener of this.listeners.get(event.scanId) ?? []) listener(event);
  }

  subscribe(scanId: string, listener: (event: ScanEvent) => void): () => void {
    const set = this.listeners.get(scanId) ?? new Set<(event: ScanEvent) => void>();
    set.add(listener);
    this.listeners.set(scanId, set);
    return () => {
      set.delete(listener);
      if (set.size === 0) this.listeners.delete(scanId);
    };
  }

  listenerCount(scanId?: string): number {
    if (scanId) return this.listeners.get(scanId)?.size ?? 0;
    let total = 0;
    for (const set of this.listeners.values()) total += set.size;
    return total;
  }
}
