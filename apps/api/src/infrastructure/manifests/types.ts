import type { Ecosystem, Precision } from '@repoguard/shared';

export interface ResolvedPackage {
  ecosystem: Ecosystem;
  name: string;
  version: string;
  precision: Precision;
  direct?: boolean;
  dev?: boolean;
  parents?: string[];
  dependsOn?: string[];
  source: { path: string; line?: number };
}

export interface ManifestParser {
  readonly id: string;
  readonly ecosystem: Ecosystem;
  readonly precision: Precision;
  matches(path: string): boolean;
  parse(content: string, path: string): ResolvedPackage[];
}

export function fileName(path: string): string {
  const parts = path.split('/');
  return parts[parts.length - 1] ?? path;
}

export function dedupePackages(packages: ResolvedPackage[]): ResolvedPackage[] {
  const merged = new Map<string, ResolvedPackage>();
  for (const pkg of packages) {
    if (!pkg.name || !pkg.version) continue;
    const key = `${pkg.ecosystem}\0${pkg.name}\0${pkg.version}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, { ...pkg, dependsOn: [...(pkg.dependsOn ?? [])] });
      continue;
    }
    existing.direct = mergeDirect(existing.direct, pkg.direct);
    existing.dev = mergeDev(existing.dev, pkg.dev);
    existing.dependsOn = [...new Set([...(existing.dependsOn ?? []), ...(pkg.dependsOn ?? [])])];
  }
  return [...merged.values()];
}

function mergeDirect(left?: boolean, right?: boolean): boolean | undefined {
  if (left === true || right === true) return true;
  if (left === false || right === false) return false;
  return undefined;
}

function mergeDev(left?: boolean, right?: boolean): boolean | undefined {
  if (left === false || right === false) return false;
  if (left === true || right === true) return true;
  return undefined;
}
