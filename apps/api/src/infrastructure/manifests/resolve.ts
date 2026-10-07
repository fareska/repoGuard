import type { RepoContext } from '../github/repoContext.js';
import type { ManifestParser, ResolvedPackage } from './types.js';
import { dedupePackages } from './types.js';

export interface ResolveResult {
  packages: ResolvedPackage[];
  manifestsFound: string[];
  missingLockfiles: { ecosystem: string; manifestPath: string }[];
  outOfSync: { ecosystem: string; manifestPath: string; dependency: string }[];
  unsupported: { ecosystem: string; paths: string[] }[];
  parseFailures: string[];
}

const UNSUPPORTED = [
  { ecosystem: 'Maven', pattern: /(^|\/)pom\.xml$/ },
  { ecosystem: 'Gradle', pattern: /(^|\/)build\.gradle(\.kts)?$/ },
];

const cache = new WeakMap<RepoContext, ResolveResult>();

export function loadPackages(context: RepoContext, parsers: ManifestParser[], maxBytes: number): ResolveResult {
  const hit = cache.get(context);
  if (hit) return hit;
  const resolved = resolvePackages(context, parsers, maxBytes);
  cache.set(context, resolved);
  return resolved;
}

export function resolvePackages(context: RepoContext, parsers: ManifestParser[], maxBytes: number): ResolveResult {
  const parsed: { parser: ManifestParser; path: string; packages: ResolvedPackage[] }[] = [];
  const parseFailures: string[] = [];
  for (const file of context.files) {
    const parser = parsers.find((candidate) => candidate.matches(file.path));
    if (!parser || file.size > maxBytes) continue;
    const content = context.readText(file.path, maxBytes);
    if (content == null) continue;
    try {
      parsed.push({ parser, path: file.path, packages: parser.parse(content, file.path) });
    } catch {
      parseFailures.push(file.path);
    }
  }

  const byEcosystem = new Map<string, typeof parsed>();
  for (const item of parsed) {
    const list = byEcosystem.get(item.parser.ecosystem) ?? [];
    list.push(item);
    byEcosystem.set(item.parser.ecosystem, list);
  }

  const packages: ResolvedPackage[] = [];
  const missingLockfiles: ResolveResult['missingLockfiles'] = [];
  const outOfSync: ResolveResult['outOfSync'] = [];

  for (const [ecosystem, items] of byEcosystem) {
    const lockfiles = items.filter((item) => item.parser.precision === 'lockfile');
    const manifests = items.filter((item) => item.parser.precision !== 'lockfile');
    const manifestPackages = manifests.flatMap((item) => item.packages);
    if (lockfiles.length === 0) {
      if (manifests.length > 0) {
        for (const manifest of manifests) missingLockfiles.push({ ecosystem, manifestPath: manifest.path });
        packages.push(...manifestPackages);
      }
      continue;
    }
    const locked = dedupePackages(lockfiles.flatMap((item) => item.packages));
    const names = new Set(locked.map((pkg) => pkg.name));
    for (const manifest of manifestPackages) {
      if (manifest.direct && !names.has(manifest.name)) {
        outOfSync.push({ ecosystem, manifestPath: manifest.source.path, dependency: manifest.name });
      }
    }
    packages.push(...overlay(locked, manifestPackages));
  }

  const unsupported = UNSUPPORTED.map((rule) => ({
    ecosystem: rule.ecosystem,
    paths: context.files.filter((file) => rule.pattern.test(file.path)).map((file) => file.path),
  })).filter((item) => item.paths.length > 0);

  return {
    packages: assignParents(dedupePackages(packages)),
    manifestsFound: parsed.map((item) => item.path),
    missingLockfiles,
    outOfSync,
    unsupported,
    parseFailures,
  };
}

function overlay(locked: ResolvedPackage[], manifests: ResolvedPackage[]): ResolvedPackage[] {
  const byName = new Map(manifests.map((pkg) => [pkg.name, pkg]));
  return locked.map((pkg) => {
    const manifest = byName.get(pkg.name);
    if (!manifest) return pkg;
    return {
      ...pkg,
      direct: pkg.direct ?? manifest.direct,
      dev: pkg.dev ?? manifest.dev,
    };
  });
}

function assignParents(packages: ResolvedPackage[]): ResolvedPackage[] {
  const reverse = new Map<string, string[]>();
  const directNames = new Set(packages.filter((pkg) => pkg.direct).map((pkg) => pkg.name));
  for (const pkg of packages) {
    for (const dependency of pkg.dependsOn ?? []) {
      const parents = reverse.get(dependency) ?? [];
      parents.push(pkg.name);
      reverse.set(dependency, parents);
    }
  }
  return packages.map((pkg) => {
    const parents = new Set<string>();
    const stack = [...(reverse.get(pkg.name) ?? [])];
    const seen = new Set<string>([pkg.name]);
    while (stack.length > 0) {
      const name = stack.pop();
      if (!name || seen.has(name)) continue;
      seen.add(name);
      if (directNames.has(name)) parents.add(name);
      else stack.push(...(reverse.get(name) ?? []));
    }
    const rest = { ...pkg };
    delete rest.dependsOn;
    return parents.size > 0 ? { ...rest, parents: [...parents] } : rest;
  });
}
