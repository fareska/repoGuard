import { hostname } from 'node:os';
import pLimit from 'p-limit';
import {
  countsOf,
  isTerminal,
  type Coverage,
  type Finding,
  type Report,
  type RepoRef,
  type TriageOutput,
} from '@repoguard/shared';
import type { Config } from '../config/env.js';
import { IllegalTransitionError, assertTransition } from '../domain/stateMachine.js';
import { dedupeFindings, finalizeFinding, type RawFinding } from '../domain/findings.js';
import { ScanFailure, isAbortError, errorMessage } from '../domain/failures.js';
import type { EventBus } from '../infrastructure/events/bus.js';
import { fetchRepository } from '../infrastructure/github/extract.js';
import { mapUpstream, type GitHubClient } from '../infrastructure/github/client.js';
import { buildRepoContext, type RepoContext } from '../infrastructure/github/repoContext.js';
import type { SqliteScanRepository } from '../infrastructure/persistence/sqlite.js';
import type { Scanner } from '../infrastructure/scanners/types.js';
import { LlmTriageProvider, PROMPT_VERSION, RuleBasedTriageProvider } from '../infrastructure/triage/llm.js';
import { ruleTriage } from '../infrastructure/triage/rules.js';
import type { AppLogger } from '../observability/logger.js';
import { ScanWriter, createStageReporter } from './reporter.js';

const WORKER_ID = `${hostname()}:${process.pid}`;

export class ScanOrchestrator {
  private shuttingDown = false;
  private readonly rules = new RuleBasedTriageProvider();
  private readonly llm: LlmTriageProvider;

  constructor(
    private readonly config: Config,
    private readonly repository: SqliteScanRepository,
    private readonly bus: EventBus,
    private readonly github: GitHubClient,
    private readonly scanners: Scanner[],
    private readonly logger: AppLogger,
  ) {
    this.llm = new LlmTriageProvider(config, this.rules);
  }

  markShuttingDown(): void {
    this.shuttingDown = true;
  }

  async run(scanId: string, parent: AbortSignal): Promise<void> {
    const signal = AbortSignal.any([parent, AbortSignal.timeout(this.config.SCAN_TIMEOUT_MS)]);
    const writer = new ScanWriter(this.repository, this.bus);
    const started = Date.now();
    let cleanup = async () => {};
    const heartbeat = setInterval(() => this.repository.touch(scanId, new Date().toISOString()), 20_000);
    try {
      const initial = this.repository.get(scanId);
      if (!initial || isTerminal(initial.snapshot.status)) return;
      assertTransition(initial.snapshot.status, 'fetching');
      writer.emit(scanId, 'scan.started', { workerId: WORKER_ID });
      const context = await this.fetchStage(scanId, writer, signal, (next) => {
        cleanup = next;
      });
      const { findings, coverageParts } = await this.analyze(scanId, writer, context, signal);
      await this.triage(scanId, writer, context, findings, coverageParts, started, signal);
    } catch (error) {
      await this.fail(scanId, writer, error, started);
    } finally {
      clearInterval(heartbeat);
      await cleanup();
    }
  }

  private async fetchStage(
    scanId: string,
    writer: ScanWriter,
    signal: AbortSignal,
    setCleanup: (cleanup: () => Promise<void>) => void,
  ): Promise<RepoContext> {
    const scan = this.must(scanId);
    writer.emit(scanId, 'stage.started', { stageId: 'fetch' });
    const stage = createStageReporter(this.config, (type, payload) => writer.emit(scanId, type, payload), 'fetch', () => undefined);
    try {
      if (scan.snapshot.mode === 'mock') {
        stage.reporter.progress(0.4, 'Preparing a simulated repository');
        await wait(this.config.MOCK_DELAY_MS, signal);
        stage.reporter.progress(0.9, 'Simulated repository is ready');
        await stage.flush();
        const context = buildRepoContext('/var/empty', { ...scan.snapshot.repo, defaultBranch: 'main', commitSha: 'mock' }, this.config.MAX_FILE_BYTES);
        writer.emit(scanId, 'stage.completed', { stageId: 'fetch', stats: { files: 0, bytes: 0 } });
        this.repository.updateRepo(scanId, context.repo);
        return context;
      }
      const fetched = await withTimeout(signal, this.config.STAGE_TIMEOUT_FETCH_MS, (stageSignal) =>
        fetchRepository(this.github, scan.snapshot.repo, this.config, stageSignal, (fraction, message) => stage.reporter.progress(fraction, message)),
      );
      setCleanup(fetched.cleanup);
      await stage.flush();
      writer.emit(scanId, 'stage.completed', {
        stageId: 'fetch',
        stats: { files: fetched.context.files.length, bytes: fetched.context.files.reduce((sum, file) => sum + file.size, 0) },
      });
      this.repository.updateRepo(scanId, fetched.context.repo);
      return fetched.context;
    } catch (error) {
      await stage.flush();
      throw error;
    }
  }

  private async analyze(scanId: string, writer: ScanWriter, context: RepoContext, signal: AbortSignal) {
    const current = this.must(scanId);
    assertTransition(current.snapshot.status, 'analyzing');
    const selected = new Set(
      current.snapshot.progress.stages.filter((stage) => stage.id.startsWith('scan:')).map((stage) => stage.id.slice('scan:'.length)),
    );
    const scanners = this.scanners.filter((scanner) => selected.has(scanner.id));
    const limit = pLimit(this.config.SCANNER_CONCURRENCY);
    const done: Finding[] = [];
    const interim: Finding[] = [];
    const scannersRun: string[] = [];
    const scannersFailed: Coverage['scannersFailed'] = [];
    const scannersSkipped: Coverage['scannersSkipped'] = [];
    let fatal: unknown;
    await Promise.all(
      scanners.map((scanner) =>
        limit(async () => {
          const stageId = `scan:${scanner.id}`;
          if (!scanner.supports(context)) {
            writer.emit(scanId, 'stage.skipped', { stageId, reason: 'Nothing in this repository matches the scanner' });
            scannersSkipped.push({ id: scanner.id, reason: 'Nothing in this repository matches the scanner' });
            return;
          }
          writer.emit(scanId, 'stage.started', { stageId });
          const stage = createStageReporter(this.config, (type, payload) => writer.emit(scanId, type, payload), stageId, (finding) => {
            interim.push(finding);
            writer.counts(scanId, dedupeFindings([...done, ...interim]));
          });
          try {
            const raw = await withTimeout(signal, this.config.STAGE_TIMEOUT_SCANNER_MS, (stageSignal) => scanner.run(context, stage.reporter, stageSignal));
            const finalized = dedupeFindings(raw.map((item: RawFinding) => finalizeFinding(item)));
            this.repository.saveFindings(scanId, finalized);
            done.push(...finalized);
            for (let index = interim.length - 1; index >= 0; index -= 1) {
              if (interim[index]?.scanner === scanner.id) interim.splice(index, 1);
            }
            writer.counts(scanId, dedupeFindings([...done, ...interim]));
            await stage.flush();
            writer.emit(scanId, 'stage.completed', { stageId, stats: { findings: finalized.length } });
            scannersRun.push(scanner.id);
          } catch (error) {
            await stage.flush();
            if (isAbortError(error) || (error instanceof Error && error.name === 'TimeoutError')) {
              fatal = error;
              return;
            }
            const failure = toFailure(error);
            writer.emit(scanId, 'stage.failed', { stageId, error: { code: failure.code, message: failure.message } });
            scannersFailed.push({ id: scanner.id, error: { code: failure.code, message: failure.message } });
            this.logger.warn({ scanId, stageId, code: failure.code }, failure.message);
          }
        }),
      ),
    );
    if (fatal) throw fatal;
    return {
      findings: dedupeFindings(done),
      coverageParts: { scannersRun, scannersFailed, scannersSkipped, context },
    };
  }

  private async triage(
    scanId: string,
    writer: ScanWriter,
    context: RepoContext,
    findings: Finding[],
    parts: { scannersRun: string[]; scannersFailed: Coverage['scannersFailed']; scannersSkipped: Coverage['scannersSkipped']; context: RepoContext },
    started: number,
    signal: AbortSignal,
  ): Promise<void> {
    const current = this.must(scanId);
    assertTransition(current.snapshot.status, 'triaging');
    writer.emit(scanId, 'stage.started', { stageId: 'triage' });
    const stage = createStageReporter(this.config, (type, payload) => writer.emit(scanId, type, payload), 'triage', () => undefined);
    stage.reporter.progress(0.2, 'Ranking findings');
    const input = {
      repoName: context.repo.name,
      findings,
      languages: context.languages,
      scannersRun: parts.scannersRun,
    };
    const provider = this.config.TRIAGE_PROVIDER === 'llm' ? this.llm : this.rules;
    let providerName = provider.id;
    const baseline = ruleTriage(input);
    const output = await withTimeout(signal, this.config.STAGE_TIMEOUT_TRIAGE_MS, async () => {
      const produced = await provider.triage(input);
      if (provider.id === 'llm' && produced.summary.text === baseline.summary.text && produced.summary.headline === baseline.summary.headline) {
        providerName = 'rules (llm fallback)';
      }
      return produced;
    });
    stage.reporter.progress(0.8, 'Writing the summary');
    await stage.flush();
    const report = buildReport({
      scanId,
      repo: context.repo,
      findings,
      output,
      provider: providerName,
      promptVersion: provider instanceof LlmTriageProvider ? PROMPT_VERSION : undefined,
      coverage: coverageFrom(parts, context, started, false),
    });
    this.repository.saveReport(report);
    writer.emit(scanId, 'stage.completed', { stageId: 'triage', stats: { findings: findings.length } });
    const latest = this.must(scanId);
    assertTransition(latest.snapshot.status, 'completed');
    writer.emit(scanId, 'scan.completed', { reportId: scanId, summary: { riskLevel: report.summary.riskLevel, counts: report.summary.counts } });
  }

  private async fail(scanId: string, writer: ScanWriter, error: unknown, started: number): Promise<void> {
    const current = this.repository.get(scanId);
    if (!current || isTerminal(current.snapshot.status)) return;
    if (error instanceof IllegalTransitionError) return;
    const failure = classify(error, current.cancelRequested, this.shuttingDown);
    if (failure.code === 'CANCELLED') {
      try {
        assertTransition(current.snapshot.status, 'cancelled');
        writer.emit(scanId, 'scan.cancelled', { by: 'user' });
      } catch (transitionError) {
        if (!(transitionError instanceof IllegalTransitionError)) this.logger.error({ err: transitionError, scanId }, 'cancel failed');
      }
      return;
    }
    try {
      assertTransition(current.snapshot.status, 'failed');
      const findings = this.repository.listFindings(scanId);
      if (findings.length > 0 && !this.repository.getReport(scanId)) {
        const output = await this.rules.triage({ repoName: current.snapshot.repo.name, findings, languages: [], scannersRun: [] });
        this.repository.saveReport(
          buildReport({
            scanId,
            repo: current.snapshot.repo,
            findings,
            output,
            provider: 'rules',
            coverage: {
              partial: true,
              scannersRun: [],
              scannersFailed: [],
              scannersSkipped: [],
              manifestsFound: [],
              filesScanned: 0,
              filesSkipped: { count: 0, reasons: {} },
              durationMs: Date.now() - started,
              unsupportedEcosystems: [],
            },
          }),
        );
      }
      writer.emit(scanId, 'scan.failed', { error: { code: failure.code, message: failure.message } });
      this.logger.warn({ scanId, code: failure.code }, failure.message);
    } catch (transitionError) {
      if (!(transitionError instanceof IllegalTransitionError)) this.logger.error({ err: transitionError, scanId }, 'fail path failed');
    }
  }

  private must(scanId: string) {
    const record = this.repository.get(scanId);
    if (!record) throw new ScanFailure('NOT_FOUND', 'Scan disappeared');
    return record;
  }
}

function coverageFrom(
  parts: { scannersRun: string[]; scannersFailed: Coverage['scannersFailed']; scannersSkipped: Coverage['scannersSkipped'] },
  context: RepoContext,
  started: number,
  partial: boolean,
): Coverage {
  const reasons: Record<string, number> = {};
  for (const file of context.files) {
    if (!file.skipReason) continue;
    reasons[file.skipReason] = (reasons[file.skipReason] ?? 0) + 1;
  }
  const skipped = context.files.filter((file) => file.skipReason).length;
  return {
    partial,
    scannersRun: parts.scannersRun,
    scannersFailed: parts.scannersFailed,
    scannersSkipped: parts.scannersSkipped,
    manifestsFound: [],
    filesScanned: context.files.length - skipped,
    filesSkipped: { count: skipped, reasons },
    durationMs: Date.now() - started,
    unsupportedEcosystems: [],
  };
}

export function buildReport(input: {
  scanId: string;
  repo: RepoRef;
  findings: Finding[];
  output: TriageOutput;
  provider: string;
  promptVersion?: string;
  coverage: Coverage;
}): Report {
  const byId = new Map(input.findings.map((finding) => [finding.id, finding]));
  const counts = countsOf(input.findings).bySeverity;
  return {
    scanId: input.scanId,
    repo: {
      ...input.repo,
      commitSha: input.repo.commitSha ?? '',
      defaultBranch: input.repo.defaultBranch ?? input.repo.ref ?? 'main',
    },
    generatedAt: new Date().toISOString(),
    coverage: input.coverage,
    summary: { ...input.output.summary, counts },
    topRisks: input.output.topRisks.flatMap((risk) => {
      const finding = byId.get(risk.findingId);
      return finding ? [{ ...risk, finding }] : [];
    }),
    nextActions: input.output.nextActions,
    groups: input.output.groups,
    findings: [...input.findings].sort((left, right) => severityOrder(right) - severityOrder(left)),
    triage: { provider: input.provider, ...(input.promptVersion ? { promptVersion: input.promptVersion } : {}) },
  };
}

function severityOrder(finding: Finding): number {
  return ['info', 'low', 'medium', 'high', 'critical'].indexOf(finding.adjustedSeverity);
}

function classify(error: unknown, cancelRequested: boolean, shuttingDown: boolean): { code: ScanFailure['code'] | 'CANCELLED'; message: string } {
  if (isAbortError(error) || (error instanceof Error && error.name === 'TimeoutError')) {
    if (cancelRequested) return { code: 'CANCELLED', message: 'Cancelled' };
    if (shuttingDown) return { code: 'INTERRUPTED', message: 'The scanner shut down before this scan finished' };
    return { code: 'TIMEOUT', message: 'The scan exceeded its time limit' };
  }
  const upstream = mapUpstream(error);
  if (upstream) return { code: upstream.code, message: upstream.message };
  if (error instanceof ScanFailure) return { code: error.code, message: error.message };
  return { code: 'INTERNAL', message: 'The scan failed unexpectedly' };
}

function toFailure(error: unknown): ScanFailure {
  if (error instanceof ScanFailure) return error;
  const upstream = mapUpstream(error);
  if (upstream) return upstream;
  return new ScanFailure('INTERNAL', errorMessage(error));
}

async function withTimeout<T>(parent: AbortSignal, ms: number, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(timeoutError()), ms);
  const onParent = () => controller.abort(parent.reason);
  if (parent.aborted) controller.abort(parent.reason);
  else parent.addEventListener('abort', onParent, { once: true });
  try {
    return await run(controller.signal);
  } finally {
    clearTimeout(timer);
    parent.removeEventListener('abort', onParent);
  }
}

function timeoutError(): Error {
  const error = new Error('Stage timed out');
  error.name = 'TimeoutError';
  return error;
}

function wait(ms: number, signal: AbortSignal): Promise<void> {
  if (ms === 0) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener('abort', () => {
      clearTimeout(timer);
      reject(Object.assign(new Error('Aborted'), { name: 'AbortError' }));
    }, { once: true });
  });
}
