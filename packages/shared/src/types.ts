export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SCAN_STATUSES = [
  'queued',
  'fetching',
  'analyzing',
  'triaging',
  'completed',
  'failed',
  'cancelled',
] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

export const TERMINAL_STATUSES = ['completed', 'failed', 'cancelled'] as const;
export type TerminalStatus = (typeof TERMINAL_STATUSES)[number];

export function isTerminal(status: ScanStatus): boolean {
  return status === 'completed' || status === 'failed' || status === 'cancelled';
}

export type ScanMode = 'real' | 'mock' | 'hybrid';
export type RequestedMode = 'real' | 'mock';
export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'clean';
export type Confidence = 'high' | 'medium' | 'low';
export type Effort = 'S' | 'M' | 'L';
export type Impact = 'high' | 'medium' | 'low';
export type Precision = 'lockfile' | 'manifest-pinned' | 'manifest-range';
export type Ecosystem =
  | 'npm'
  | 'PyPI'
  | 'Go'
  | 'crates.io'
  | 'RubyGems'
  | 'Packagist'
  | 'NuGet'
  | 'Maven';

export type FindingCategory = 'dependency' | 'secret' | 'code' | 'config' | 'hygiene';
export type RemediationType =
  | 'upgrade'
  | 'override'
  | 'replace'
  | 'remove'
  | 'rotate_secret'
  | 'code_change'
  | 'config_change'
  | 'process';

export type StageStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped';

export interface ScanErrorRef {
  code: string;
  message: string;
}

export interface Stage {
  id: string;
  label: string;
  status: StageStatus;
  weight: number;
  progress: number;
  message?: string;
  startedAt?: string;
  finishedAt?: string;
  error?: ScanErrorRef;
  stats?: Record<string, number>;
}

export interface RepoRef {
  url: string;
  owner: string;
  name: string;
  ref?: string;
  defaultBranch?: string;
  commitSha?: string;
}

export interface FindingCounts {
  findings: number;
  bySeverity: Record<Severity, number>;
}

export interface Progress {
  percent: number;
  currentStage: string | null;
  queuePosition?: number;
  stages: Stage[];
}

export interface ScanLinks {
  self: string;
  events: string;
  result: string;
}

export interface ScanSnapshot {
  id: string;
  status: ScanStatus;
  mode: ScanMode;
  repo: RepoRef;
  progress: Progress;
  counts: FindingCounts;
  error: ScanErrorRef | null;
  createdAt: string;
  startedAt: string | null;
  updatedAt: string;
  finishedAt: string | null;
  lastEventSeq: number;
  links: ScanLinks;
}

export interface ScanSummary {
  id: string;
  status: ScanStatus;
  mode: ScanMode;
  repo: Pick<RepoRef, 'url' | 'owner' | 'name'>;
  percent: number;
  findings: number;
  riskLevel: RiskLevel | null;
  createdAt: string;
  finishedAt: string | null;
}

export interface ReferenceLink {
  title: string;
  url: string;
}

export interface Remediation {
  summary: string;
  steps: string[];
  fixVersion?: string;
  effort: Effort;
  type: RemediationType;
  alternative?: { name: string; source: 'registry_deprecation' | 'curated' | 'llm_unverified' };
}

export interface FindingContext {
  isDevDependency?: boolean;
  isDirectDependency?: boolean;
  parents?: string[];
  precision?: Precision;
  epss?: number;
  kev?: boolean;
  fixAvailable?: boolean;
}

export interface FindingLocation {
  path: string;
  startLine?: number;
  endLine?: number;
  snippet?: string;
}

export interface Finding {
  id: string;
  fingerprint: string;
  scanner: string;
  category: FindingCategory;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  adjustedSeverity: Severity;
  severityRationale: string[];
  confidence: Confidence;
  location?: FindingLocation;
  evidence: Record<string, unknown>;
  cwe: string[];
  owasp?: string[];
  references: ReferenceLink[];
  remediation: Remediation;
  context: FindingContext;
}

export interface Coverage {
  partial: boolean;
  scannersRun: string[];
  scannersFailed: { id: string; error: ScanErrorRef }[];
  scannersSkipped: { id: string; reason: string }[];
  manifestsFound: string[];
  filesScanned: number;
  filesSkipped: { count: number; reasons: Record<string, number> };
  durationMs: number;
  unsupportedEcosystems: { ecosystem: string; paths: string[] }[];
}

export interface TriageSummary {
  headline: string;
  riskLevel: RiskLevel;
  text: string;
}

export interface TopRisk {
  findingId: string;
  whyItMatters: string;
}

export interface NextAction {
  id: string;
  title: string;
  description: string;
  type: RemediationType;
  effort: Effort;
  impact: Impact;
  findingIds: string[];
}

export interface FindingGroup {
  label: string;
  findingIds: string[];
}

export interface TriageOutput {
  summary: TriageSummary;
  topRisks: TopRisk[];
  nextActions: NextAction[];
  groups: FindingGroup[];
}

export interface Report {
  scanId: string;
  repo: RepoRef & { commitSha: string; defaultBranch: string };
  generatedAt: string;
  coverage: Coverage;
  summary: TriageSummary & { counts: Record<Severity, number> };
  topRisks: (TopRisk & { finding: Finding })[];
  nextActions: NextAction[];
  groups: FindingGroup[];
  findings: Finding[];
  triage: { provider: string; promptVersion?: string };
}

export interface ScannerInfo {
  id: string;
  displayName: string;
  description: string;
  weight: number;
}

export interface EcosystemInfo {
  id: Ecosystem;
  lockfiles: string[];
  manifests: string[];
}

export interface ScannersResponse {
  scanners: ScannerInfo[];
  ecosystems: EcosystemInfo[];
  allowMockMode: boolean;
  defaultMode: ScanMode;
}

export interface Page<T> {
  items: T[];
  nextCursor?: string;
}

export function emptyCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
}

export function scanLinks(id: string): ScanLinks {
  return {
    self: `/api/v1/scans/${id}`,
    events: `/api/v1/scans/${id}/events`,
    result: `/api/v1/scans/${id}/result`,
  };
}

export function severityRank(severity: Severity): number {
  return SEVERITIES.length - 1 - SEVERITIES.indexOf(severity);
}

export function countsOf(findings: { adjustedSeverity: Severity }[]): FindingCounts {
  const bySeverity = emptyCounts();
  for (const finding of findings) bySeverity[finding.adjustedSeverity] += 1;
  return { findings: findings.length, bySeverity };
}
