import { createHash } from 'node:crypto';
import type { Severity } from '@repoguard/shared';
import type { RawFinding } from '../../domain/findings.js';
import { countPhrase } from '../../domain/text.js';
import type { RepoContext } from '../github/repoContext.js';
import type { ProgressReporter, Scanner } from './types.js';

const LINE_CAP = 1000;
const HIGH_ENTROPY = 3.5;
const LOW_ENTROPY = 3;

interface SecretRule {
  id: string;
  description: string;
  source: string;
  severity: Severity;
  confidence: RawFinding['confidence'];
  provider: boolean;
  group?: number;
}

const RULES: SecretRule[] = [
  { id: 'SECRET_AWS_ACCESS_KEY', description: 'AWS access key ID', source: String.raw`\b(AKIA[0-9A-Z]{16})\b`, severity: 'critical', confidence: 'high', provider: true, group: 1 },
  { id: 'SECRET_GITHUB_TOKEN', description: 'GitHub personal access token', source: String.raw`\b(ghp_[A-Za-z0-9]{36})\b`, severity: 'critical', confidence: 'high', provider: true, group: 1 },
  { id: 'SECRET_GITHUB_OAUTH', description: 'GitHub OAuth token', source: String.raw`\b(gho_[A-Za-z0-9]{36})\b`, severity: 'critical', confidence: 'high', provider: true, group: 1 },
  { id: 'SECRET_GITHUB_FINE_GRAINED', description: 'GitHub fine-grained personal access token', source: String.raw`\b(github_pat_[A-Za-z0-9_]{22,80})\b`, severity: 'critical', confidence: 'high', provider: true, group: 1 },
  { id: 'SECRET_SLACK', description: 'Slack token', source: String.raw`\b(xox[baprs]-[A-Za-z0-9-]{10,48})\b`, severity: 'critical', confidence: 'high', provider: true, group: 1 },
  { id: 'SECRET_STRIPE', description: 'Stripe live secret key', source: String.raw`\b(sk_live_[A-Za-z0-9]{16,})\b`, severity: 'critical', confidence: 'high', provider: true, group: 1 },
  { id: 'SECRET_GOOGLE_API', description: 'Google API key', source: String.raw`\b(AIza[0-9A-Za-z_-]{35})\b`, severity: 'critical', confidence: 'high', provider: true, group: 1 },
  { id: 'SECRET_PRIVATE_KEY', description: 'Private key', source: String.raw`(-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----)`, severity: 'critical', confidence: 'high', provider: true, group: 1 },
  { id: 'SECRET_GENERIC_ASSIGNMENT', description: 'High-entropy secret assignment', source: String.raw`\b(?:password|passwd|api_key|apikey|api_secret|secret|access_key)\b\s*[=:]\s*['"]?([A-Za-z0-9/+_.=-]{12,80})`, severity: 'high', confidence: 'medium', provider: false, group: 1 },
];

const SKIP_FILE = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|Cargo\.lock|poetry\.lock|Pipfile\.lock|composer\.lock|Gemfile\.lock|go\.sum|packages\.lock\.json)$/i;
const PLACEHOLDER = /^(changeme|password|secret|token|example|placeholder|redacted|xxx+|your[-_]?api[-_]?key|insert[-_]?key|none|null|undefined|test|testing|<.*>)$/i;

export function maskSecret(value: string): string {
  if (value.length <= 8) return '*'.repeat(value.length);
  return `${value.slice(0, 4)}${'*'.repeat(Math.min(16, value.length - 8))}${value.slice(-4)}`;
}

export function redactSecrets(text: string): string {
  let redacted = text;
  for (const rule of RULES) {
    redacted = redacted.replace(new RegExp(rule.source, 'g'), (match, group: string | undefined) => {
      const secret = group || match;
      return match.replace(secret, maskSecret(secret));
    });
  }
  return redacted;
}

export function shannonEntropy(value: string): number {
  if (!value) return 0;
  const freq = new Map<string, number>();
  for (const char of value) freq.set(char, (freq.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export function scanContent(path: string, content: string): RawFinding[] {
  const findings: RawFinding[] = [];
  const lines = content.split(/\r?\n/);
  for (let index = 0; index < lines.length; index += 1) {
    const line = (lines[index] ?? '').slice(0, LINE_CAP);
    for (const rule of RULES) {
      const match = new RegExp(rule.source).exec(line);
      const secret = match?.[rule.group ?? 0];
      if (!match || !secret) continue;
      if (!rule.provider) {
        if (PLACEHOLDER.test(secret) || secret.includes('${') || secret.includes('{{')) continue;
        const entropy = shannonEntropy(secret);
        if (entropy < LOW_ENTROPY) continue;
      }
      const material = rule.id === 'SECRET_PRIVATE_KEY' ? lines.slice(index, index + 3).join('\n') : secret;
      findings.push(secretFinding(rule, path, index + 1, line, secret, material));
    }
  }
  return findings;
}

export class SecretScanner implements Scanner {
  readonly id = 'secrets';
  readonly displayName = 'Leaked secrets';
  readonly description = 'Provider credentials and high-entropy secrets in tracked files.';
  readonly weight = 20;

  supports(): boolean {
    return true;
  }

  async run(context: RepoContext, reporter: ProgressReporter, signal: AbortSignal): Promise<RawFinding[]> {
    const files = context.files.filter((file) => !file.skipReason && !SKIP_FILE.test(file.path));
    const findings: RawFinding[] = [];
    for (let index = 0; index < files.length; index += 1) {
      if (index % 25 === 0) signal.throwIfAborted();
      const file = files[index];
      if (!file) continue;
      const content = context.readText(file.path, file.size);
      if (content) findings.push(...scanContent(file.path, content).map((finding) => {
        reporter.finding(finding);
        return finding;
      }));
      if (index % 20 === 0 || index === files.length - 1) {
        reporter.progress(files.length === 0 ? 1 : (index + 1) / files.length, `Scanned ${index + 1}/${files.length} files`);
      }
    }
    reporter.log('info', `Secret scan produced ${countPhrase(findings.length, 'finding')}`);
    return findings;
  }
}

function secretFinding(rule: SecretRule, path: string, line: number, text: string, secret: string, material: string): RawFinding {
  const masked = maskSecret(secret);
  const generic = !rule.provider;
  const entropy = shannonEntropy(secret);
  const severity: Severity = generic && entropy < HIGH_ENTROPY ? 'medium' : rule.severity;
  const confidence = generic && entropy < HIGH_ENTROPY ? 'low' : rule.confidence;
  return {
    scanner: 'secrets',
    category: 'secret',
    ruleId: rule.id,
    title: `${rule.description} in ${path}`,
    description: `A ${rule.description.toLowerCase()} is committed in ${path}. The raw value is not stored.`,
    severity,
    confidence,
    location: { path, startLine: line, endLine: line, snippet: text.replace(secret, masked).slice(0, 400) },
    evidence: { masked, rule: rule.id },
    cwe: ['CWE-798', 'CWE-312'],
    owasp: ['A02:2021'],
    references: [],
    remediation: {
      type: 'rotate_secret',
      effort: 'S',
      summary: `Revoke the exposed credential and remove it from ${path}`,
      steps: ['Revoke or rotate the credential at the provider.', `Remove the secret from ${path} and purge it from git history if it was pushed.`, 'Store the replacement in a secret manager, not in the repository.'],
    },
    context: {},
    fingerprintMaterial: `${path}|${createHash('sha256').update(material).digest('hex')}`,
  };
}
