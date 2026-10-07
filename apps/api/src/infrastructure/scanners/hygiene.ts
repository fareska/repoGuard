import type { RawFinding } from '../../domain/findings.js';
import { countPhrase } from '../../domain/text.js';
import type { RepoContext } from '../github/repoContext.js';
import type { ProgressReporter, Scanner } from './types.js';

const LARGE_FILE_BYTES = 5 * 1024 * 1024;

export class HygieneScanner implements Scanner {
  readonly id = 'hygiene';
  readonly displayName = 'Repository hygiene';
  readonly description = 'Security policy, license, dependency updates, and large binaries.';
  readonly weight = 5;

  supports(): boolean {
    return true;
  }

  async run(context: RepoContext, reporter: ProgressReporter, _signal: AbortSignal): Promise<RawFinding[]> {
    const paths = new Set(context.files.map((file) => file.path.toLowerCase()));
    const findings: RawFinding[] = [];
    if (![...paths].some((path) => path === 'security.md' || path.endsWith('/security.md'))) {
      findings.push(note('MISSING_SECURITY_MD', 'low', 'No SECURITY.md', 'People who find a vulnerability have no documented way to report it.', 'Add a SECURITY.md with a contact and the disclosure process you want.'));
    }
    if (![...paths].some((path) => path.endsWith('license') || path.endsWith('license.md') || path.endsWith('license.txt') || path.endsWith('copying'))) {
      findings.push(note('MISSING_LICENSE', 'low', 'No LICENSE file', 'A missing license makes reuse legally unclear.', 'Add a license file that matches how you want the code used.'));
    }
    const hasUpdates = [...paths].some((path) => path.includes('dependabot.yml') || path.endsWith('renovate.json') || path.endsWith('.renovaterc'));
    if (!hasUpdates) {
      findings.push(note('MISSING_UPDATE_BOT', 'low', 'No Dependabot or Renovate config', 'Dependency updates are not opening automatically.', 'Add Dependabot or Renovate so vulnerable packages are proposed as pull requests.'));
    }
    for (const file of context.files) {
      if (file.size >= LARGE_FILE_BYTES) {
        findings.push({
          ...note('LARGE_BINARY', 'info', `Large file ${file.path}`, `${file.path} is ${file.size.toLocaleString()} bytes. Large binaries are hard to review and bloat clones.`, 'Store the file outside git, or confirm it needs to be versioned.'),
          fingerprintMaterial: `LARGE_BINARY|${file.path}`,
          location: { path: file.path },
        });
      }
    }
    for (const finding of findings) reporter.finding(finding);
    reporter.progress(0.99, countPhrase(findings.length, 'hygiene note'));
    return findings;
  }
}

function note(ruleId: string, severity: RawFinding['severity'], title: string, description: string, step: string): RawFinding {
  return {
    scanner: 'hygiene',
    category: 'hygiene',
    ruleId,
    title,
    description,
    severity,
    confidence: 'high',
    evidence: { ruleId },
    cwe: [],
    references: [],
    remediation: { type: 'process', effort: 'S', summary: title, steps: [step] },
    context: {},
    fingerprintMaterial: ruleId,
  };
}
