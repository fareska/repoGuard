import type { RawFinding } from '../../domain/findings.js';
import { countPhrase } from '../../domain/text.js';
import type { RepoContext } from '../github/repoContext.js';
import { loadPackages } from '../manifests/resolve.js';
import type { ManifestParser } from '../manifests/types.js';
import type { ProgressReporter, Scanner } from './types.js';

const REMOTE_INSTALL = /\b(curl|wget)\b[^|\n]{0,200}\|\s*(sh|bash)\b|\bpip3?\s+install\s+https?:\/\//i;

export class DependencyHygieneScanner implements Scanner {
  readonly id = 'deps-hygiene';
  readonly displayName = 'Dependency hygiene';
  readonly description = 'Missing lockfiles, lockfiles out of sync with manifests, and remote install hooks.';
  readonly weight = 8;

  constructor(
    private readonly parsers: ManifestParser[],
    private readonly maxManifestBytes: number,
  ) {}

  supports(): boolean {
    return true;
  }

  async run(context: RepoContext, reporter: ProgressReporter, signal: AbortSignal): Promise<RawFinding[]> {
    signal.throwIfAborted();
    const resolved = loadPackages(context, this.parsers, this.maxManifestBytes);
    const findings: RawFinding[] = [];
    for (const missing of resolved.missingLockfiles) {
      findings.push(hygiene('MISSING_LOCKFILE', 'medium', `Commit a lockfile for ${missing.ecosystem}`, `${missing.manifestPath} declares dependencies without a lockfile, so installs are not reproducible.`, missing.manifestPath, ['Add the ecosystem lockfile and commit it.', 'Re-run the scan for exact versions.']));
    }
    for (const drift of resolved.outOfSync) {
      findings.push(hygiene('LOCKFILE_OUT_OF_SYNC', 'medium', `Lockfile is missing ${drift.dependency}`, `${drift.manifestPath} depends on ${drift.dependency}, but the lockfile has no entry for it.`, drift.manifestPath, ['Regenerate the lockfile from the manifest.', 'Commit both files together.']));
    }
    for (const unsupported of resolved.unsupported) {
      findings.push(hygiene('ECOSYSTEM_UNSUPPORTED', 'info', `Dependencies were not analyzed for ${unsupported.ecosystem}`, `${unsupported.paths[0]} is not parsed in this version. The report does not mean those dependencies are safe.`, unsupported.paths[0] ?? 'pom.xml', ['Track Maven and Gradle resolution on the roadmap.', 'Export a CycloneDX SBOM if you need those packages included now.']));
    }
    const packageJson = context.files.find((file) => file.path.endsWith('package.json') && !file.skipReason);
    if (packageJson) {
      const content = context.readText(packageJson.path, this.maxManifestBytes);
      if (content && REMOTE_INSTALL.test(content)) {
        findings.push(hygiene('REMOTE_INSTALL_HOOK', 'high', 'Install script fetches remote code', 'A package script pipes a remote script into a shell or installs from a URL. That executes attacker-controlled code at install time.', packageJson.path, ['Replace the remote install with a pinned package.', 'Review git history for the script before running install.']));
      }
    }
    for (const finding of findings) reporter.finding(finding);
    reporter.progress(1, `${findings.length} hygiene notes`);
    reporter.log('info', `Dependency hygiene produced ${countPhrase(findings.length, 'finding')}`);
    return findings;
  }
}

function hygiene(ruleId: string, severity: RawFinding['severity'], title: string, description: string, path: string, steps: string[]): RawFinding {
  return {
    scanner: 'deps-hygiene',
    category: 'dependency',
    ruleId,
    title,
    description,
    severity,
    confidence: 'high',
    location: { path },
    evidence: { path },
    cwe: ['CWE-829'],
    references: [],
    remediation: { type: 'process', effort: 'S', summary: title, steps },
    context: {},
    fingerprintMaterial: `${ruleId}|${path}|${title}`,
  };
}
