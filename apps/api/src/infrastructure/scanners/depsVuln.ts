import type { Severity } from '@repoguard/shared';
import { compareVersions, type RawFinding } from '../../domain/findings.js';
import type { RepoContext } from '../github/repoContext.js';
import { fixedVersions, scoreToSeverity, advisoryScore, cweIds, type EnrichmentClient, type OsvVuln } from '../enrichment/client.js';
import { loadPackages } from '../manifests/resolve.js';
import type { ManifestParser, ResolvedPackage } from '../manifests/types.js';
import { curatedAlternative, overrideSteps, upgradeCommand, upgradeEffort } from './remediation.js';
import type { ProgressReporter, Scanner } from './types.js';

export class DependencyVulnScanner implements Scanner {
  readonly id = 'deps-vuln';
  readonly displayName = 'Dependency vulnerabilities';
  readonly description = 'Known vulnerabilities in resolved packages, direct and transitive.';
  readonly weight = 25;

  constructor(
    private readonly parsers: ManifestParser[],
    private readonly enrichment: EnrichmentClient,
    private readonly maxManifestBytes: number,
  ) {}

  supports(): boolean {
    return true;
  }

  async run(context: RepoContext, reporter: ProgressReporter, signal: AbortSignal): Promise<RawFinding[]> {
    const resolved = loadPackages(context, this.parsers, this.maxManifestBytes);
    const packages = resolved.packages.filter((pkg) => pkg.ecosystem !== 'Maven');
    reporter.log('info', `Querying ${packages.length} packages`);
    const findings: RawFinding[] = [];
    const batchSize = 200;
    for (let index = 0; index < packages.length; index += batchSize) {
      signal.throwIfAborted();
      const batch = packages.slice(index, index + batchSize);
      const matches = await this.enrichment.vulnerabilities(batch, signal);
      const ids = matches.flatMap((match) => match.vulns.flatMap((vuln) => [vuln.id, ...(vuln.aliases ?? [])]));
      const signals = await this.enrichment.exploitSignals(ids, signal);
      for (const match of matches) {
        for (const vuln of match.vulns) {
          if (vuln.id.startsWith('MAL-')) continue;
          const finding = toFinding(match.pkg, vuln, signals);
          findings.push(finding);
          reporter.finding(finding);
        }
      }
      reporter.progress(Math.min(0.99, (index + batch.length) / Math.max(packages.length, 1)), `Queried ${Math.min(index + batch.length, packages.length)}/${packages.length} packages`);
    }
    reporter.log('info', `Found ${findings.length} vulnerable package advisories`);
    return findings;
  }
}

function toFinding(
  pkg: ResolvedPackage,
  vuln: OsvVuln,
  signals: Record<string, { epss?: number; kev?: boolean }>,
): RawFinding {
  const aliases = vuln.aliases ?? [];
  const cve = [vuln.id, ...aliases].find((id) => id.startsWith('CVE-'));
  const signal = cve ? signals[cve] : undefined;
  const fixed = chooseFixed(pkg.version, fixedVersions(vuln));
  const malicious = vuln.id.startsWith('MAL-');
  const remediation = remediationFor(pkg, fixed, malicious, vuln.summary);
  const score = advisoryScore(vuln);
  return {
    scanner: 'deps-vuln',
    category: 'dependency',
    ruleId: vuln.id,
    title: `${pkg.name}@${pkg.version} is affected by ${vuln.id}`,
    description: vuln.summary || vuln.details?.split('\n')[0] || `${pkg.name} ${pkg.version} matches advisory ${vuln.id}.`,
    severity: malicious ? 'critical' : scoreToSeverity(score),
    confidence: pkg.precision === 'manifest-range' ? 'medium' : 'high',
    location: { path: pkg.source.path, ...(pkg.source.line ? { startLine: pkg.source.line } : {}) },
    evidence: {
      package: pkg.name,
      ecosystem: pkg.ecosystem,
      version: pkg.version,
      vulnIds: [vuln.id],
      aliases,
      ...(score !== undefined ? { cvssScore: score } : {}),
      ...(fixed ? { fixedVersion: fixed } : {}),
      malicious,
    },
    cwe: cweIds(vuln).length > 0 ? cweIds(vuln) : ['CWE-1395'],
    owasp: ['A06:2021'],
    references: referencesFor(vuln),
    remediation,
    context: {
      isDevDependency: pkg.dev,
      isDirectDependency: pkg.direct,
      ...(pkg.parents ? { parents: pkg.parents } : {}),
      precision: pkg.precision,
      ...(signal?.epss !== undefined ? { epss: signal.epss } : {}),
      ...(signal?.kev ? { kev: true } : {}),
      fixAvailable: Boolean(fixed),
    },
    fingerprintMaterial: `${pkg.ecosystem}|${pkg.name}|${pkg.version}|${vuln.id}`,
  };
}

function remediationFor(pkg: ResolvedPackage, fixed: string | undefined, malicious: boolean, summary?: string): RawFinding['remediation'] {
  if (malicious) {
    return {
      type: 'remove',
      effort: 'S',
      summary: `Remove ${pkg.name} immediately and rotate any credential the build could have exposed`,
      steps: [`Remove ${pkg.name} from the manifest and lockfile.`, 'Rotate credentials that this package could have read during install or runtime.'],
    };
  }
  if (!fixed) {
    const alternative = curatedAlternative(pkg.ecosystem, pkg.name, summary);
    return {
      type: 'replace',
      effort: 'M',
      summary: `Replace ${pkg.name}: no fixed version is available`,
      steps: [`Stop depending on ${pkg.name}.`, alternative ? `A known alternative is ${alternative.name}.` : 'Choose a maintained alternative and retest.'],
      ...(alternative ? { alternative } : {}),
    };
  }
  const effort = upgradeEffort(pkg.version, fixed);
  const breaking = effort === 'M' ? ' This crosses a major version; check the changelog before upgrading.' : '';
  if (pkg.direct === false) {
    const parent = pkg.parents?.[0];
    return {
      type: parent ? 'upgrade' : 'override',
      effort: parent ? effort : 'M',
      fixVersion: fixed,
      summary: parent ? `Update ${parent}, which pulls in ${pkg.name}` : `Pin ${pkg.name} to ${fixed}`,
      steps: overrideSteps(pkg.ecosystem, pkg.name, fixed, parent),
    };
  }
  return {
    type: 'upgrade',
    effort,
    fixVersion: fixed,
    summary: `Upgrade ${pkg.name} ${pkg.version} → ${fixed}${breaking}`,
    steps: [upgradeCommand(pkg.ecosystem, pkg.name, fixed), 'Regenerate the lockfile and run the test suite.'],
  };
}

function chooseFixed(current: string, versions: string[]): string | undefined {
  const newer = versions.filter((version) => compareVersions(version, current) > 0).sort(compareVersions);
  return newer[0] ?? versions.sort(compareVersions).at(-1);
}

function referencesFor(vuln: OsvVuln): RawFinding['references'] {
  const links = (vuln.references ?? []).flatMap((reference) =>
    reference.url ? [{ title: reference.type || vuln.id, url: reference.url }] : [],
  );
  return [{ title: vuln.id, url: `https://osv.dev/vulnerability/${vuln.id}` }, ...links].slice(0, 6);
}

export type { Severity };
