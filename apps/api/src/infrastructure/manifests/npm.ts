import { fileName, type ManifestParser, type ResolvedPackage } from './types.js';
import { npmSpecifier } from './specifiers.js';

export class NpmLockParser implements ManifestParser {
  readonly id = 'npm-lock';
  readonly ecosystem = 'npm' as const;
  readonly precision = 'lockfile' as const;

  matches(path: string): boolean {
    return fileName(path) === 'package-lock.json';
  }

  parse(content: string, path: string): ResolvedPackage[] {
    const json = JSON.parse(content) as {
      packages?: Record<string, LockPackage>;
      dependencies?: Record<string, LockV1>;
    };
    if (json.packages) return parseV2(json.packages, path);
    if (json.dependencies) return parseV1(json.dependencies, path, true);
    return [];
  }
}

export class PackageJsonParser implements ManifestParser {
  readonly id = 'package-json';
  readonly ecosystem = 'npm' as const;
  readonly precision = 'manifest-range' as const;

  matches(path: string): boolean {
    return fileName(path) === 'package.json';
  }

  parse(content: string, path: string): ResolvedPackage[] {
    const json = JSON.parse(content) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
    };
    return [
      ...entries(json.dependencies, false, path),
      ...entries(json.devDependencies, true, path),
      ...entries(json.optionalDependencies, false, path),
    ];
  }
}

export class YarnLockParser implements ManifestParser {
  readonly id = 'yarn-lock';
  readonly ecosystem = 'npm' as const;
  readonly precision = 'lockfile' as const;

  matches(path: string): boolean {
    return fileName(path) === 'yarn.lock';
  }

  parse(content: string, path: string): ResolvedPackage[] {
    const packages: ResolvedPackage[] = [];
    const lines = content.split(/\r?\n/);
    let name: string | undefined;
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? '';
      if (!line || line.startsWith('#')) continue;
      if (!line.startsWith(' ') && line.trimEnd().endsWith(':')) {
        name = yarnPackageName(line.trimEnd().slice(0, -1));
        continue;
      }
      const version = /^\s+version[:\s]+"?([^"\s]+)"?/.exec(line);
      if (!version?.[1] || !name) continue;
      packages.push(lockPackage(name, version[1], path, index + 1));
    }
    return packages;
  }
}

export class PnpmLockParser implements ManifestParser {
  readonly id = 'pnpm-lock';
  readonly ecosystem = 'npm' as const;
  readonly precision = 'lockfile' as const;

  matches(path: string): boolean {
    return fileName(path) === 'pnpm-lock.yaml';
  }

  parse(content: string, path: string): ResolvedPackage[] {
    const packages: ResolvedPackage[] = [];
    const lines = content.split(/\r?\n/);
    let section: 'packages' | 'deps' | 'dev' | '' = '';
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? '';
      if (!line.startsWith(' ') && line.endsWith(':')) {
        const key = line.slice(0, -1);
        if (key === 'packages') section = 'packages';
        else if (key === 'dependencies' || key === 'importers') section = 'deps';
        else if (key === 'devDependencies') section = 'dev';
        else if (!line.startsWith(' ')) section = '';
      }
      if (section !== 'packages') continue;
      const header = /^\s{2}\/?((?:@[^/\s]+\/)?[^@\s]+)@([^:(]+)/.exec(line);
      if (!header?.[1] || !header[2]) continue;
      packages.push({ ...lockPackage(header[1], header[2], path, index + 1), direct: undefined });
    }
    const direct = readPnpmDirect(lines);
    return packages.map((pkg) => {
      const flag = direct.get(pkg.name);
      return flag ? { ...pkg, direct: true, dev: flag.dev } : pkg;
    });
  }
}

interface LockPackage {
  version?: string;
  dev?: boolean;
  link?: boolean;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}

function parseV2(packages: Record<string, LockPackage>, path: string): ResolvedPackage[] {
  const root = packages[''] ?? {};
  const direct = new Set(Object.keys(root.dependencies ?? {}));
  const dev = new Set(Object.keys(root.devDependencies ?? {}));
  const resolved: ResolvedPackage[] = [];
  for (const [key, entry] of Object.entries(packages)) {
    if (!key || !entry.version || entry.link) continue;
    const name = nameFromNodeModules(key);
    if (!name) continue;
    resolved.push({
      ecosystem: 'npm',
      name,
      version: entry.version,
      precision: 'lockfile',
      direct: direct.has(name),
      dev: entry.dev === true || dev.has(name),
      dependsOn: Object.keys(entry.dependencies ?? {}),
      source: { path },
    });
  }
  return resolved;
}

interface LockV1 {
  version?: string;
  dev?: boolean;
  requires?: Record<string, string>;
  dependencies?: Record<string, LockV1>;
}

function parseV1(dependencies: Record<string, LockV1>, path: string, top: boolean): ResolvedPackage[] {
  const resolved: ResolvedPackage[] = [];
  for (const [name, entry] of Object.entries(dependencies)) {
    if (entry.version) {
      resolved.push({
        ecosystem: 'npm',
        name,
        version: entry.version,
        precision: 'lockfile',
        direct: top,
        dev: entry.dev === true,
        dependsOn: Object.keys(entry.requires ?? {}),
        source: { path },
      });
    }
    if (entry.dependencies) resolved.push(...parseV1(entry.dependencies, path, false));
  }
  return resolved;
}

function entries(deps: Record<string, string> | undefined, dev: boolean, path: string): ResolvedPackage[] {
  const packages: ResolvedPackage[] = [];
  for (const [name, spec] of Object.entries(deps ?? {})) {
    const parsed = npmSpecifier(spec);
    if (!parsed) continue;
    packages.push({
      ecosystem: 'npm',
      name,
      version: parsed.version,
      precision: parsed.precision,
      direct: true,
      dev,
      source: { path },
    });
  }
  return packages;
}

function lockPackage(name: string, version: string, path: string, line: number): ResolvedPackage {
  return { ecosystem: 'npm', name, version, precision: 'lockfile', source: { path, line } };
}

function nameFromNodeModules(key: string): string | null {
  const parts = key.split('node_modules/').filter(Boolean);
  const last = parts[parts.length - 1];
  if (!last) return null;
  return last.replace(/\/$/, '');
}

function yarnPackageName(header: string): string | undefined {
  const first = header.split(',')[0]?.trim().replace(/^"|"$/g, '');
  if (!first) return undefined;
  if (first.startsWith('@')) {
    const at = first.indexOf('@', 1);
    return at === -1 ? first : first.slice(0, at);
  }
  const at = first.lastIndexOf('@');
  return at <= 0 ? first : first.slice(0, at);
}

function readPnpmDirect(lines: string[]): Map<string, { dev: boolean }> {
  const direct = new Map<string, { dev: boolean }>();
  let dev = false;
  let inImporterDeps = false;
  for (const line of lines) {
    if (/^devDependencies:/.test(line) || /^\s{4}devDependencies:/.test(line)) {
      dev = true;
      inImporterDeps = true;
      continue;
    }
    if (/^dependencies:/.test(line) || /^\s{4}dependencies:/.test(line)) {
      dev = false;
      inImporterDeps = true;
      continue;
    }
    if (line === 'packages:' || (!line.startsWith(' ') && line.endsWith(':'))) {
      if (line === 'packages:') inImporterDeps = false;
    }
    if (!inImporterDeps) continue;
    const name = /^\s{2,6}['"]?((?:@[^/'"]+\/)?[^:'"]+)['"]?:/.exec(line);
    if (name?.[1] && name[1] !== 'specifier' && name[1] !== 'version') direct.set(name[1], { dev });
  }
  return direct;
}
