import { createHash, randomBytes } from 'node:crypto';
import {
  severityRank,
  type Confidence,
  type Finding,
  type FindingCategory,
  type FindingContext,
  type FindingLocation,
  type Precision,
  type Remediation,
  type Severity,
} from '@repoguard/shared';
import { EPSS_HIGH, EPSS_LOW } from '../config/severity.js';

const TEST_PATH = /(^|\/)(test|tests|__tests__|fixtures|examples|testdata|spec)\//i;

export function createId(prefix: string): string {
  return `${prefix}_${randomBytes(16).toString('hex')}`;
}

export function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export interface RawFinding {
  scanner: string;
  category: FindingCategory;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: Confidence;
  location?: FindingLocation;
  evidence: Record<string, unknown>;
  cwe: string[];
  owasp?: string[];
  references: Finding['references'];
  remediation: Remediation;
  context: FindingContext;
  fingerprintMaterial: string;
}

export function finalizeFinding(raw: RawFinding): Finding {
  const adjusted = adjustSeverity(raw);
  const { fingerprintMaterial: _material, ...rest } = raw;
  return {
    ...rest,
    id: createId('fnd'),
    fingerprint: sha256(`${raw.scanner}|${raw.ruleId}|${raw.fingerprintMaterial}`),
    adjustedSeverity: adjusted.severity,
    severityRationale: adjusted.rationale,
  };
}

export function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const unique: Finding[] = [];
  for (const finding of findings) {
    if (seen.has(finding.fingerprint)) continue;
    seen.add(finding.fingerprint);
    unique.push(finding);
  }
  return unique;
}

export function adjustSeverity(raw: RawFinding): { severity: Severity; rationale: string[] } {
  let rank = severityRank(raw.severity);
  const notes: string[] = [];
  const malicious = raw.evidence.malicious === true || raw.ruleId.startsWith('MAL-');
  const inTest = raw.location?.path ? TEST_PATH.test(raw.location.path) : false;

  if (raw.category === 'dependency') {
    const epss = raw.context.epss;
    if (epss != null && epss >= EPSS_HIGH) {
      rank = shiftUp(rank);
      notes.push(`High probability of exploitation in the next 30 days (EPSS ${epss.toFixed(2)})`);
    } else if (epss != null && epss < EPSS_LOW && !raw.context.kev) {
      rank = shiftDown(rank);
      notes.push(`Low exploitation likelihood (EPSS ${epss.toFixed(3)})`);
    }
    if (raw.context.isDevDependency) {
      rank = shiftDown(rank);
      notes.push('Only used in development tooling, not shipped to production');
    }
    if (raw.context.precision === 'manifest-range') {
      rank = shiftDown(rank);
      notes.push('Evaluated at the declared lower bound; commit a lockfile for an exact answer');
    }
    if (raw.context.isDirectDependency === undefined) {
      notes.push('Direct vs transitive is unknown; treated as a direct production dependency');
    }
    if (raw.context.fixAvailable) notes.push('A fixed version exists; upgrade is low effort');
    else if (raw.remediation.type === 'replace' || raw.remediation.type === 'remove') {
      notes.push('No fix available from the maintainers');
    }
    if (raw.context.kev) {
      rank = severityRank('critical');
      notes.push('Actively exploited in the wild (CISA KEV)');
    }
    if (malicious) {
      rank = severityRank('critical');
      notes.push('Flagged as malicious by OSV; remove it and rotate credentials');
    }
  }

  if (raw.category === 'secret') {
    if (inTest) {
      rank = shiftDown(rank);
      notes.push('Located in test data; verify it is not a real credential');
    }
    if (raw.confidence === 'high') notes.push('Live-looking credential for a third-party service');
  }

  if (notes.length === 0) notes.push('Severity matches the scanner rule');
  return { severity: fromRank(rank), rationale: notes };
}

function shiftUp(rank: number): number {
  return Math.min(severityRank('critical'), rank + 1);
}

function shiftDown(rank: number): number {
  if (rank <= severityRank('low')) return rank;
  return rank - 1;
}

function fromRank(rank: number): Severity {
  if (rank >= severityRank('critical')) return 'critical';
  if (rank >= severityRank('high')) return 'high';
  if (rank >= severityRank('medium')) return 'medium';
  if (rank >= severityRank('low')) return 'low';
  return 'info';
}

export function compareVersions(left: string, right: string): number {
  const a = parts(left);
  const b = parts(right);
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const av = a[index] ?? 0;
    const bv = b[index] ?? 0;
    if (av !== bv) return av - bv;
  }
  return 0;
}

function parts(version: string): number[] {
  return version
    .replace(/^v/i, '')
    .split(/[.+_-]/)
    .map((part) => {
      const match = /^(\d+)/.exec(part);
      return match?.[1] ? Number(match[1]) : 0;
    });
}

export function sameMajor(current: string, next: string): boolean {
  return (parts(current)[0] ?? 0) === (parts(next)[0] ?? 0);
}

export type { Precision };
