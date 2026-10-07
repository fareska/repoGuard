import type { RawFinding } from '../../domain/findings.js';
import type { RepoContext } from '../github/repoContext.js';

export interface ProgressReporter {
  progress(fraction: number, message?: string): void;
  log(level: 'debug' | 'info' | 'warn' | 'error', message: string): void;
  finding(finding: RawFinding): void;
}

export interface Scanner {
  readonly id: string;
  readonly displayName: string;
  readonly description: string;
  readonly weight: number;
  supports(context: RepoContext): boolean;
  run(context: RepoContext, reporter: ProgressReporter, signal: AbortSignal): Promise<RawFinding[]>;
}
