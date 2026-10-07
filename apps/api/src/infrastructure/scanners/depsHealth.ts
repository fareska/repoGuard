import { UNMAINTAINED_MONTHS } from '../../config/severity.js';
import type { RawFinding } from '../../domain/findings.js';
import { countPhrase } from '../../domain/text.js';
import type { RepoContext } from '../github/repoContext.js';
import type { EnrichmentClient } from '../enrichment/client.js';
import { loadPackages } from '../manifests/resolve.js';
import type { ManifestParser, ResolvedPackage } from '../manifests/types.js';
import { curatedAlternative } from './remediation.js';
import type { ProgressReporter, Scanner } from './types.js';

export class DependencyHealthScanner implements Scanner {
  readonly id = 'deps-health';
  readonly displayName = 'Dependency health';
  readonly description = 'Deprecated, yanked, malicious, or unmaintained packages that should be replaced.';
  readonly weight = 15;

  constructor(
    private readonly parsers: ManifestParser[],
    private readonly enrichment: EnrichmentClient,
    private readonly maxManifestBytes: number,
    private readonly archived: (projectId: string, signal: AbortSignal) => Promise<boolean | null>,
  ) {}

  supports(): boolean {
    return true;
  }

  async run(context: RepoContext, reporter: ProgressReporter, signal: AbortSignal): Promise<RawFinding[]> {
    const resolved = loadPackages(context, this.parsers, this.maxManifestBytes);
    const targets = uniqueDirect(resolved.packages);
    const findings: RawFinding[] = [];
    const push = (finding: RawFinding) => {
      findings.push(finding);
      reporter.finding(finding);
    };
    for (let index = 0; index < targets.length; index += 1) {
      signal.throwIfAborted();
      const pkg = targets[index];
      if (!pkg) continue;
      const [matches, meta] = await Promise.all([
        this.enrichment.vulnerabilities([pkg], signal),
        this.enrichment.packageMeta(pkg, signal),
      ]);
      const vulns = matches[0]?.vulns ?? [];
      const malicious = vulns.find((vuln) => vuln.id.startsWith('MAL-') || /malicious/i.test(vuln.summary ?? ''));
      if (malicious) push(healthFinding(pkg, 'remove', 'critical', 'high', `Remove ${pkg.name}: flagged malicious`, malicious.summary || `${pkg.name} is flagged as malicious.`, true));
      if (meta?.deprecated) {
        const alternative = curatedAlternative(pkg.ecosystem, pkg.name, meta.deprecationMessage);
        push({
          ...healthFinding(pkg, 'replace', 'medium', 'high', `${pkg.name} is deprecated`, meta.deprecationMessage || `${pkg.name} ${pkg.version} is marked deprecated by its registry.`, vulns.length > 0),
          remediation: {
            type: 'replace',
            effort: 'M',
            summary: `Replace ${pkg.name}${alternative ? ` with ${alternative.name}` : ''}`,
            steps: [meta.deprecationMessage || `Stop depending on ${pkg.name}.`, 'Move callers to a maintained package and regenerate the lockfile.'],
            ...(alternative ? { alternative } : {}),
          },
        });
      }
      if (meta?.yanked) push(healthFinding(pkg, 'replace', 'high', 'high', `${pkg.name}@${pkg.version} was yanked`, 'The resolved version is no longer listed by the registry.', true));
      const stale = isStale(meta?.latestPublishedAt);
      const unmaintainedAdvisory = vulns.find((vuln) => /unmaintained/i.test(`${vuln.summary ?? ''} ${vuln.details ?? ''}`));
      if (unmaintainedAdvisory || (stale && vulns.length > 0)) {
        push(healthFinding(pkg, 'replace', vulns.length > 0 ? 'high' : 'medium', 'medium', `${pkg.name} looks unmaintained`, unmaintainedAdvisory?.summary || `No release in more than ${UNMAINTAINED_MONTHS} months while advisories are still open.`, true));
      }
      if (meta?.sourceRepo) {
        const archived = await this.archived(meta.sourceRepo, signal);
        if (archived) push(healthFinding(pkg, 'replace', 'medium', 'high', `${pkg.name} upstream is archived`, `${meta.sourceRepo} is archived, so fixes are unlikely.`, vulns.length > 0));
      }
      reporter.progress((index + 1) / Math.max(targets.length, 1), `Checked ${index + 1}/${targets.length} direct packages`);
    }
    reporter.log('info', `Dependency health produced ${countPhrase(findings.length, 'finding')}`);
    return findings;
  }
}

function uniqueDirect(packages: ResolvedPackage[]): ResolvedPackage[] {
  const seen = new Set<string>();
  const direct: ResolvedPackage[] = [];
  for (const pkg of packages) {
    if (pkg.direct === false) continue;
    const key = `${pkg.ecosystem}\0${pkg.name}\0${pkg.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    direct.push(pkg);
  }
  return direct;
}

function isStale(publishedAt?: string): boolean {
  if (!publishedAt) return false;
  const published = Date.parse(publishedAt);
  if (Number.isNaN(published)) return false;
  const months = (Date.now() - published) / (30 * 24 * 60 * 60 * 1000);
  return months > UNMAINTAINED_MONTHS;
}

function healthFinding(
  pkg: ResolvedPackage,
  type: 'replace' | 'remove',
  severity: RawFinding['severity'],
  confidence: RawFinding['confidence'],
  title: string,
  description: string,
  openVuln: boolean,
): RawFinding {
  const raised = openVuln && severity !== 'critical' ? bump(severity) : severity;
  return {
    scanner: 'deps-health',
    category: 'dependency',
    ruleId: type === 'remove' ? 'MALICIOUS_PACKAGE' : 'DEPENDENCY_HEALTH',
    title,
    description,
    severity: raised,
    confidence,
    location: { path: pkg.source.path },
    evidence: { package: pkg.name, ecosystem: pkg.ecosystem, version: pkg.version, malicious: type === 'remove' },
    cwe: ['CWE-1104'],
    owasp: ['A06:2021'],
    references: [],
    remediation: {
      type,
      effort: type === 'remove' ? 'S' : 'M',
      summary: type === 'remove' ? `Remove ${pkg.name} immediately` : `Replace ${pkg.name}`,
      steps: [type === 'remove' ? `Delete ${pkg.name} and rotate exposed credentials.` : `Replace ${pkg.name} with a maintained alternative.`],
    },
    context: {
      isDevDependency: pkg.dev,
      isDirectDependency: pkg.direct ?? true,
      precision: pkg.precision,
      fixAvailable: false,
    },
    fingerprintMaterial: `${pkg.ecosystem}|${pkg.name}|${pkg.version}|${title}`,
  };
}

function bump(severity: RawFinding['severity']): RawFinding['severity'] {
  if (severity === 'info') return 'low';
  if (severity === 'low') return 'medium';
  if (severity === 'medium') return 'high';
  if (severity === 'high') return 'critical';
  return 'critical';
}
