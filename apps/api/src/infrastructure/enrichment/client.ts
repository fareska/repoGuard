import type { Ecosystem } from '@repoguard/shared';
import { CVSS_CRITICAL, CVSS_HIGH, CVSS_MEDIUM, SEVERITY_WORD_SCORE } from '../../config/severity.js';
import type { Severity } from '@repoguard/shared';
import type { ResolvedPackage } from '../manifests/types.js';
import { CircuitBreaker, fetchUpstream, Inflight, TtlCache, type FetchOptions } from './http.js';

export interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: { type: string; score: string }[];
  references?: { type?: string; url?: string }[];
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: {
    database_specific?: { severity?: string; cwe_ids?: string[] };
    ranges?: { events?: { fixed?: string; introduced?: string }[] }[];
  }[];
}

export interface VulnMatch {
  pkg: ResolvedPackage;
  vulns: OsvVuln[];
}

const DEPS_SYSTEM: Partial<Record<Ecosystem, string>> = {
  npm: 'npm',
  PyPI: 'pypi',
  Go: 'go',
  'crates.io': 'cargo',
  RubyGems: 'rubygems',
  NuGet: 'nuget',
  Maven: 'maven',
};

export interface PackageMeta {
  deprecated: boolean;
  deprecationMessage?: string;
  yanked: boolean;
  latestPublishedAt?: string;
  sourceRepo?: string;
  scorecard?: number;
}

export class EnrichmentClient {
  private readonly osvCache: TtlCache<OsvVuln[]>;
  private readonly vulnCache: TtlCache<OsvVuln>;
  private readonly metaCache: TtlCache<PackageMeta | null>;
  private readonly epssCache = new TtlCache<number>();
  private kevIds = new Set<string>();
  private kevExpires = 0;
  private readonly inflight = new Inflight();

  constructor(
    private readonly options: {
      osvBaseUrl: string;
      depsDevBaseUrl: string;
      epssUrl: string;
      kevUrl: string;
      osvTtlMs: number;
      depsTtlMs: number;
      exploitTtlMs: number;
      batchSize: number;
      fetch: Omit<FetchOptions, 'signal' | 'breaker'>;
      breakers: { osv: CircuitBreaker; deps: CircuitBreaker; epss: CircuitBreaker; kev: CircuitBreaker };
    },
  ) {
    this.osvCache = new TtlCache();
    this.vulnCache = new TtlCache();
    this.metaCache = new TtlCache();
  }

  async vulnerabilities(packages: ResolvedPackage[], signal: AbortSignal): Promise<VulnMatch[]> {
    const matches: VulnMatch[] = [];
    for (let index = 0; index < packages.length; index += this.options.batchSize) {
      const batch = packages.slice(index, index + this.options.batchSize);
      const pending: { pkg: ResolvedPackage; key: string }[] = [];
      for (const pkg of batch) {
        const key = `${pkg.ecosystem}\0${pkg.name}\0${pkg.version}`;
        const cached = this.osvCache.get(key);
        if (cached) matches.push({ pkg, vulns: cached });
        else pending.push({ pkg, key });
      }
      if (pending.length === 0) continue;
      const response = await fetchUpstream(`${this.options.osvBaseUrl}/v1/querybatch`, {
        ...this.request('osv', signal),
        method: 'POST',
        body: JSON.stringify({
          queries: pending.map((item) => ({
            version: item.pkg.version,
            package: { ecosystem: item.pkg.ecosystem, name: item.pkg.name },
          })),
        }),
        headers: { 'content-type': 'application/json' },
      });
      if (!response.ok) continue;
      const body = (await response.json()) as { results?: { vulns?: { id: string }[] }[] };
      for (let resultIndex = 0; resultIndex < pending.length; resultIndex += 1) {
        const item = pending[resultIndex];
        if (!item) continue;
        const ids = (body.results?.[resultIndex]?.vulns ?? []).map((vuln) => vuln.id).filter(Boolean);
        const vulns = await this.hydrate(ids, signal);
        this.osvCache.set(item.key, vulns, this.options.osvTtlMs);
        matches.push({ pkg: item.pkg, vulns });
      }
    }
    return matches;
  }

  async packageMeta(pkg: ResolvedPackage, signal: AbortSignal): Promise<PackageMeta | null> {
    const system = DEPS_SYSTEM[pkg.ecosystem];
    if (!system) return null;
    const key = `${system}\0${pkg.name}\0${pkg.version}`;
    const cached = this.metaCache.get(key);
    if (cached !== undefined) return cached;
    return this.inflight.run(key, async () => {
      const meta = await this.loadMeta(system, pkg, signal);
      this.metaCache.set(key, meta, this.options.depsTtlMs);
      return meta;
    });
  }

  async exploitSignals(ids: string[], signal: AbortSignal): Promise<Record<string, { epss?: number; kev?: boolean }>> {
    const cves = [...new Set(ids.filter((id) => id.startsWith('CVE-')))];
    await this.ensureKev(signal);
    const missing = cves.filter((id) => this.epssCache.get(id) === undefined);
    for (let index = 0; index < missing.length; index += 100) {
      const chunk = missing.slice(index, index + 100);
      if (chunk.length === 0) continue;
      try {
        const response = await fetchUpstream(`${this.options.epssUrl}?cve=${chunk.join(',')}`, this.request('epss', signal));
        if (!response.ok) continue;
        const body = (await response.json()) as { data?: { cve?: string; epss?: string }[] };
        const seen = new Set<string>();
        for (const row of body.data ?? []) {
          if (!row.cve) continue;
          seen.add(row.cve);
          this.epssCache.set(row.cve, Number(row.epss ?? 0), this.options.exploitTtlMs);
        }
        for (const id of chunk) {
          if (!seen.has(id)) this.epssCache.set(id, 0, this.options.exploitTtlMs);
        }
      } catch {
        // Exploit signals are optional. A missing source degrades rationale only.
      }
    }
    const signals: Record<string, { epss?: number; kev?: boolean }> = {};
    for (const id of cves) {
      signals[id] = { epss: this.epssCache.get(id), kev: this.kevIds.has(id) };
    }
    return signals;
  }

  private async hydrate(ids: string[], signal: AbortSignal): Promise<OsvVuln[]> {
    const vulns: OsvVuln[] = [];
    await mapPool(ids, 8, async (id) => {
      const cached = this.vulnCache.get(id);
      if (cached) {
        vulns.push(cached);
        return;
      }
      const vuln = await this.inflight.run(`vuln:${id}`, async () => {
        const response = await fetchUpstream(`${this.options.osvBaseUrl}/v1/vulns/${encodeURIComponent(id)}`, this.request('osv', signal));
        if (!response.ok) return null;
        return (await response.json()) as OsvVuln;
      });
      if (!vuln) return;
      this.vulnCache.set(id, vuln, this.options.osvTtlMs);
      vulns.push(vuln);
    });
    return dedupeAliases(vulns);
  }

  private async loadMeta(system: string, pkg: ResolvedPackage, signal: AbortSignal): Promise<PackageMeta | null> {
    const name = encodeURIComponent(pkg.name);
    const version = encodeURIComponent(pkg.version);
    const base = `${this.options.depsDevBaseUrl}/v3/systems/${system}/packages/${name}`;
    try {
      const [packageResponse, versionResponse] = await Promise.all([
        fetchUpstream(base, this.request('deps', signal)),
        fetchUpstream(`${base}/versions/${version}`, this.request('deps', signal)),
      ]);
      if (!packageResponse.ok && !versionResponse.ok) return null;
      const packageBody = packageResponse.ok ? ((await packageResponse.json()) as DepsPackage) : undefined;
      const versionBody = versionResponse.ok ? ((await versionResponse.json()) as DepsVersion) : undefined;
      const versions = packageBody?.versions ?? [];
      const listed = versions.some((item) => item.versionKey?.version === pkg.version);
      const versionRow = versions.find((item) => item.versionKey?.version === pkg.version);
      const latest = versions.reduce<string | undefined>((max, item) => {
        if (!item.publishedAt) return max;
        if (!max || item.publishedAt > max) return item.publishedAt;
        return max;
      }, undefined);
      const source = versionBody?.relatedProjects?.find((project) => project.relationType === 'SOURCE_REPO')?.projectKey?.id;
      let scorecard: number | undefined;
      if (source) {
        try {
          const project = await fetchUpstream(
            `${this.options.depsDevBaseUrl}/v3/projects/${encodeURIComponent(source)}`,
            this.request('deps', signal),
          );
          if (project.ok) {
            const body = (await project.json()) as { scorecard?: { overallScore?: number } };
            scorecard = body.scorecard?.overallScore;
          }
        } catch {
          scorecard = undefined;
        }
      }
      return {
        deprecated: Boolean(versionRow?.isDeprecated || versionBody?.isDeprecated),
        ...(versionRow?.deprecatedReason || versionBody?.deprecatedReason
          ? { deprecationMessage: versionRow?.deprecatedReason || versionBody?.deprecatedReason }
          : {}),
        yanked: versions.length > 0 && !listed,
        ...(latest ? { latestPublishedAt: latest } : {}),
        ...(source ? { sourceRepo: source } : {}),
        ...(scorecard !== undefined ? { scorecard } : {}),
      };
    } catch {
      return null;
    }
  }

  private async ensureKev(signal: AbortSignal): Promise<void> {
    if (Date.now() < this.kevExpires && this.kevIds.size > 0) return;
    await this.inflight.run('kev', async () => {
      if (Date.now() < this.kevExpires && this.kevIds.size > 0) return;
      try {
        const response = await fetchUpstream(this.options.kevUrl, this.request('kev', signal));
        if (!response.ok) return;
        const body = (await response.json()) as { vulnerabilities?: { cveID?: string }[] };
        this.kevIds = new Set((body.vulnerabilities ?? []).map((item) => item.cveID).filter((id): id is string => Boolean(id)));
        this.kevExpires = Date.now() + this.options.exploitTtlMs;
      } catch {
        this.kevExpires = Date.now() + 60_000;
      }
    });
  }

  private request(kind: 'osv' | 'deps' | 'epss' | 'kev', signal: AbortSignal): FetchOptions {
    return { ...this.options.fetch, breaker: this.options.breakers[kind], signal };
  }
}

interface DepsPackage {
  versions?: { versionKey?: { version?: string }; publishedAt?: string; isDeprecated?: boolean; deprecatedReason?: string }[];
}

interface DepsVersion {
  isDeprecated?: boolean;
  deprecatedReason?: string;
  relatedProjects?: { relationType?: string; projectKey?: { id?: string } }[];
}

export function advisoryScore(vuln: OsvVuln): number | undefined {
  for (const item of vuln.severity ?? []) {
    if (!item.type.toUpperCase().includes('CVSS')) continue;
    const numeric = Number(item.score);
    if (!Number.isNaN(numeric) && !item.score.includes('/')) return numeric;
    const parsed = cvssBaseScore(item.score);
    if (parsed !== undefined) return parsed;
  }
  const word = vuln.database_specific?.severity ?? vuln.affected?.find((item) => item.database_specific?.severity)?.database_specific?.severity;
  if (!word) return undefined;
  return SEVERITY_WORD_SCORE[word.toUpperCase()];
}

export function scoreToSeverity(score: number | undefined): Severity {
  if (score == null) return 'medium';
  if (score >= CVSS_CRITICAL) return 'critical';
  if (score >= CVSS_HIGH) return 'high';
  if (score >= CVSS_MEDIUM) return 'medium';
  if (score > 0) return 'low';
  return 'info';
}

export function fixedVersions(vuln: OsvVuln): string[] {
  const versions: string[] = [];
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event.fixed) versions.push(event.fixed);
      }
    }
  }
  return versions;
}

export function cweIds(vuln: OsvVuln): string[] {
  const ids = new Set<string>(vuln.database_specific?.cwe_ids ?? []);
  for (const affected of vuln.affected ?? []) {
    for (const id of affected.database_specific?.cwe_ids ?? []) ids.add(id);
  }
  return [...ids];
}

function dedupeAliases(vulns: OsvVuln[]): OsvVuln[] {
  const byId = new Map(vulns.map((vuln) => [vuln.id, vuln]));
  const dropped = new Set<string>();
  for (const vuln of vulns) {
    for (const alias of vuln.aliases ?? []) {
      const other = byId.get(alias);
      if (!other || dropped.has(vuln.id) || dropped.has(alias)) continue;
      dropped.add(preferVuln(vuln, other) === vuln ? other.id : vuln.id);
    }
  }
  return vulns.filter((vuln) => !dropped.has(vuln.id));
}

function preferVuln(left: OsvVuln, right: OsvVuln): OsvVuln {
  const leftScore = advisoryScore(left) != null ? 2 : 0;
  const rightScore = advisoryScore(right) != null ? 2 : 0;
  const leftId = left.id.startsWith('GHSA-') ? 1 : 0;
  const rightId = right.id.startsWith('GHSA-') ? 1 : 0;
  return leftScore + leftId >= rightScore + rightId ? left : right;
}

export function cvssBaseScore(vector: string): number | undefined {
  if (!vector.startsWith('CVSS:3')) return undefined;
  const metrics = new Map(vector.split('/').slice(1).map((part) => {
    const [key, value] = part.split(':');
    return [key ?? '', value ?? ''] as const;
  }));
  const av = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[metrics.get('AV') ?? ''];
  const ac = { L: 0.77, H: 0.44 }[metrics.get('AC') ?? ''];
  const ui = { N: 0.85, R: 0.62 }[metrics.get('UI') ?? ''];
  const scopeChanged = metrics.get('S') === 'C';
  const prTable = scopeChanged ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 };
  const pr = prTable[metrics.get('PR') as 'N' | 'L' | 'H'];
  const cia = { H: 0.56, L: 0.22, N: 0 };
  const c = cia[metrics.get('C') as 'H' | 'L' | 'N'];
  const i = cia[metrics.get('I') as 'H' | 'L' | 'N'];
  const a = cia[metrics.get('A') as 'H' | 'L' | 'N'];
  if (av == null || ac == null || ui == null || pr == null || c == null || i == null || a == null) return undefined;
  const impact = 1 - (1 - c) * (1 - i) * (1 - a);
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const base = scopeChanged
    ? 7.52 * (impact - 0.029) - 3.25 * (impact - 0.02) ** 15
    : 6.42 * impact;
  const raw = scopeChanged ? 1.08 * (base + exploitability) : base + exploitability;
  return Math.min(10, Math.ceil((raw - 1e-9) * 10) / 10);
}

async function mapPool<T>(items: T[], limit: number, worker: (item: T) => Promise<void>): Promise<void> {
  let cursor = 0;
  async function run(): Promise<void> {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      const item = items[index];
      if (item !== undefined) await worker(item);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => run()));
}
