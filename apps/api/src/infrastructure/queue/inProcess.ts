export class QueueFullError extends Error {
  constructor(message = 'The scan queue is full') {
    super(message);
    this.name = 'QueueFullError';
  }
}

export interface ScanJob {
  scanId: string;
}

export class InProcessJobQueue {
  private readonly waiting: ScanJob[] = [];
  private readonly running = new Map<string, AbortController>();
  private handler: ((job: ScanJob, signal: AbortSignal) => Promise<void>) | null = null;
  private paused = false;

  constructor(private readonly limits: { maxConcurrent: number; maxQueueLength: number }) {}

  enqueue(job: ScanJob): void {
    if (this.paused || this.waiting.length >= this.limits.maxQueueLength) throw new QueueFullError();
    this.waiting.push(job);
    this.pump();
  }

  process(handler: (job: ScanJob, signal: AbortSignal) => Promise<void>): void {
    this.handler = handler;
    this.pump();
  }

  cancel(scanId: string): boolean {
    const index = this.waiting.findIndex((job) => job.scanId === scanId);
    if (index >= 0) {
      this.waiting.splice(index, 1);
      return true;
    }
    const controller = this.running.get(scanId);
    if (!controller) return false;
    controller.abort();
    return true;
  }

  position(scanId: string): number | undefined {
    const index = this.waiting.findIndex((job) => job.scanId === scanId);
    return index >= 0 ? index + 1 : undefined;
  }

  stats(): { queued: number; running: number } {
    return { queued: this.waiting.length, running: this.running.size };
  }

  get accepting(): boolean {
    return !this.paused;
  }

  pause(): void {
    this.paused = true;
  }

  async drain(timeoutMs: number): Promise<void> {
    this.paused = true;
    const started = Date.now();
    while (this.running.size > 0 && Date.now() - started < timeoutMs) {
      await delay(50);
    }
    for (const controller of this.running.values()) controller.abort();
  }

  private pump(): void {
    if (!this.handler) return;
    while (this.running.size < this.limits.maxConcurrent && this.waiting.length > 0) {
      const job = this.waiting.shift();
      if (!job) return;
      const controller = new AbortController();
      this.running.set(job.scanId, controller);
      void this.handler(job, controller.signal).finally(() => {
        this.running.delete(job.scanId);
        this.pump();
      });
    }
  }
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
