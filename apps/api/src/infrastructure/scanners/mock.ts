import { createHash } from 'node:crypto';
import type { RawFinding } from '../../domain/findings.js';
import type { RepoContext } from '../github/repoContext.js';
import type { ProgressReporter, Scanner } from './types.js';

export class MockScanner implements Scanner {
  readonly id = 'mock';
  readonly displayName = 'Simulated scan';
  readonly description = 'Deterministic sample findings for demos and tests.';
  readonly weight = 65;

  constructor(private readonly delayMs: number) {}

  supports(): boolean {
    return true;
  }

  async run(context: RepoContext, reporter: ProgressReporter, signal: AbortSignal): Promise<RawFinding[]> {
    const findings = mockFindings(context.repo.url, context.repo.name);
    const steps = 5;
    for (let step = 1; step <= steps; step += 1) {
      signal.throwIfAborted();
      const ready = findings.slice(0, Math.round((findings.length * step) / steps));
      if (ready.length > (step === 1 ? 0 : Math.round((findings.length * (step - 1)) / steps))) {
        const finding = ready[ready.length - 1];
        if (finding) reporter.finding(finding);
      }
      reporter.progress(step / steps, `Simulated check ${step}/${steps}`);
      reporter.log('info', `Mock scanner step ${step} for ${context.repo.name}`);
      if (this.delayMs > 0) await delay(this.delayMs, signal);
    }
    return findings;
  }
}

function mockFindings(url: string, name: string): RawFinding[] {
  const variant = createHash('sha256').update(url).digest()[0] ?? 0;
  const qsFixed = variant % 2 === 0;
  return [
    {
      scanner: 'mock',
      category: 'dependency',
      ruleId: 'GHSA-hrpp-h998-j3pp',
      title: `qs in ${name} is vulnerable to prototype pollution`,
      description: 'A demo advisory. The mock scanner does not query OSV; this finding is synthetic and stable for the repository URL.',
      severity: 'high',
      confidence: 'high',
      location: { path: 'package-lock.json' },
      evidence: { package: 'qs', ecosystem: 'npm', version: '6.5.2', vulnIds: ['GHSA-hrpp-h998-j3pp'], fixedVersion: qsFixed ? '6.5.3' : undefined, malicious: false },
      cwe: ['CWE-1321'],
      owasp: ['A06:2021'],
      references: [{ title: 'OSV example', url: 'https://osv.dev' }],
      remediation: qsFixed
        ? { type: 'upgrade', effort: 'S', summary: 'Upgrade qs 6.5.2 → 6.5.3', fixVersion: '6.5.3', steps: ['npm install qs@6.5.3'] }
        : { type: 'replace', effort: 'M', summary: 'Replace qs: no fix in this demo variant', steps: ['Choose a maintained parser.'] },
      context: { isDirectDependency: false, isDevDependency: false, parents: ['express'], precision: 'lockfile', epss: 0.62, fixAvailable: qsFixed },
      fingerprintMaterial: `qs|${url}`,
    },
    {
      scanner: 'mock',
      category: 'secret',
      ruleId: 'SECRET_AWS_ACCESS_KEY',
      title: 'AWS access key ID in config/settings.py',
      description: 'A demo credential. The value shown here is masked and was never a real key.',
      severity: 'critical',
      confidence: 'high',
      location: { path: 'config/settings.py', startLine: 12, endLine: 12, snippet: 'aws_key = "AKIA****************MPLE"' },
      evidence: { masked: 'AKIA****************MPLE' },
      cwe: ['CWE-798'],
      owasp: ['A02:2021'],
      references: [],
      remediation: { type: 'rotate_secret', effort: 'S', summary: 'Revoke the demo AWS key and delete it from the repo', steps: ['Revoke the key.', 'Remove the assignment.'] },
      context: {},
      fingerprintMaterial: `aws|${url}`,
    },
    {
      scanner: 'mock',
      category: 'config',
      ruleId: 'DOCKER_ROOT',
      title: 'Container runs as root',
      description: 'The demo Dockerfile never sets USER.',
      severity: 'medium',
      confidence: 'high',
      location: { path: 'Dockerfile' },
      evidence: { path: 'Dockerfile' },
      cwe: ['CWE-250'],
      owasp: ['A05:2021'],
      references: [],
      remediation: { type: 'config_change', effort: 'S', summary: 'Run the container as a non-root user', steps: ['Add USER app after the packages are installed.'] },
      context: {},
      fingerprintMaterial: `docker|${url}`,
    },
    {
      scanner: 'mock',
      category: 'hygiene',
      ruleId: 'MISSING_SECURITY_MD',
      title: 'No SECURITY.md',
      description: 'The demo repository has no security policy.',
      severity: 'low',
      confidence: 'high',
      evidence: {},
      cwe: [],
      references: [],
      remediation: { type: 'process', effort: 'S', summary: 'Add a SECURITY.md', steps: ['Document how to report a vulnerability.'] },
      context: {},
      fingerprintMaterial: `security|${url}`,
    },
  ];
}

function delay(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        const error = new Error('Aborted');
        error.name = 'AbortError';
        reject(error);
      },
      { once: true },
    );
  });
}
