import { parse as parseToml } from 'smol-toml';
import { fileName, type ManifestParser, type ResolvedPackage } from './types.js';
import { npmSpecifier } from './specifiers.js';

export class CargoLockParser implements ManifestParser {
  readonly id = 'cargo-lock';
  readonly ecosystem = 'crates.io' as const;
  readonly precision = 'lockfile' as const;
  matches(path: string): boolean {
    return fileName(path) === 'Cargo.lock';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const doc = parseToml(content) as { package?: { name?: string; version?: string; source?: string; dependencies?: string[] }[] };
    return (doc.package ?? []).flatMap((pkg) => {
      if (!pkg.name || !pkg.version || !pkg.source) return [];
      return [
        crate(pkg.name, pkg.version, 'lockfile', path, undefined, (pkg.dependencies ?? []).map(depName)),
      ];
    });
  }
}

export class CargoTomlParser implements ManifestParser {
  readonly id = 'cargo-toml';
  readonly ecosystem = 'crates.io' as const;
  readonly precision = 'manifest-range' as const;
  matches(path: string): boolean {
    return fileName(path) === 'Cargo.toml';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const doc = parseToml(content) as {
      dependencies?: Record<string, string | { version?: string }>;
      'dev-dependencies'?: Record<string, string | { version?: string }>;
    };
    return [...cargoTable(doc.dependencies, false, path), ...cargoTable(doc['dev-dependencies'], true, path)];
  }
}

export class GemfileLockParser implements ManifestParser {
  readonly id = 'gemfile-lock';
  readonly ecosystem = 'RubyGems' as const;
  readonly precision = 'lockfile' as const;
  matches(path: string): boolean {
    return fileName(path) === 'Gemfile.lock';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const direct = new Set<string>();
    const deps = /DEPENDENCIES\n([\s\S]*?)\n\n/.exec(content)?.[1] ?? '';
    for (const line of deps.split(/\r?\n/)) {
      const name = /^\s{2}([A-Za-z0-9_-]+)/.exec(line)?.[1];
      if (name) direct.add(name);
    }
    const specs = /specs:\n([\s\S]*?)\n\n[A-Z]/.exec(`${content}\n\nEND`)?.[1] ?? '';
    const packages: ResolvedPackage[] = [];
    for (const line of specs.split(/\r?\n/)) {
      const match = /^\s{4}([A-Za-z0-9_-]+) \(([^)]+)\)/.exec(line);
      if (!match?.[1] || !match[2]) continue;
      packages.push({
        ecosystem: 'RubyGems',
        name: match[1],
        version: match[2].split(/[,\s]/)[0] ?? match[2],
        precision: 'lockfile',
        direct: direct.has(match[1]),
        source: { path },
      });
    }
    return packages;
  }
}

export class GemfileParser implements ManifestParser {
  readonly id = 'gemfile';
  readonly ecosystem = 'RubyGems' as const;
  readonly precision = 'manifest-range' as const;
  matches(path: string): boolean {
    return fileName(path) === 'Gemfile';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const packages: ResolvedPackage[] = [];
    for (const line of content.split(/\r?\n/)) {
      const match = /^\s*gem\s+['"]([^'"]+)['"]\s*(?:,\s*['"]([^'"]+)['"])?/.exec(line);
      if (!match?.[1]) continue;
      const parsed = match[2] ? npmSpecifier(match[2].replace(/[~^]/, '')) : null;
      if (!parsed) continue;
      packages.push({ ecosystem: 'RubyGems', name: match[1], version: parsed.version, precision: parsed.precision, direct: true, source: { path } });
    }
    return packages;
  }
}

export class ComposerLockParser implements ManifestParser {
  readonly id = 'composer-lock';
  readonly ecosystem = 'Packagist' as const;
  readonly precision = 'lockfile' as const;
  matches(path: string): boolean {
    return fileName(path) === 'composer.lock';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const json = JSON.parse(content) as { packages?: ComposerPkg[]; 'packages-dev'?: ComposerPkg[] };
    return [...composerList(json.packages, false, path), ...composerList(json['packages-dev'], true, path)];
  }
}

export class ComposerJsonParser implements ManifestParser {
  readonly id = 'composer-json';
  readonly ecosystem = 'Packagist' as const;
  readonly precision = 'manifest-range' as const;
  matches(path: string): boolean {
    return fileName(path) === 'composer.json';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const json = JSON.parse(content) as { require?: Record<string, string>; 'require-dev'?: Record<string, string> };
    return [...composerRequire(json.require, false, path), ...composerRequire(json['require-dev'], true, path)].filter(
      (pkg) => pkg.name !== 'php',
    );
  }
}

export class NugetLockParser implements ManifestParser {
  readonly id = 'nuget-lock';
  readonly ecosystem = 'NuGet' as const;
  readonly precision = 'lockfile' as const;
  matches(path: string): boolean {
    return fileName(path) === 'packages.lock.json';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const json = JSON.parse(content) as { dependencies?: Record<string, Record<string, { resolved?: string; type?: string }>> };
    const packages: ResolvedPackage[] = [];
    for (const framework of Object.values(json.dependencies ?? {})) {
      for (const [name, meta] of Object.entries(framework)) {
        if (!meta.resolved || meta.type === 'Project') continue;
        packages.push({
          ecosystem: 'NuGet',
          name,
          version: meta.resolved,
          precision: 'lockfile',
          direct: meta.type?.toLowerCase() === 'direct',
          source: { path },
        });
      }
    }
    return packages;
  }
}

export class CsprojParser implements ManifestParser {
  readonly id = 'csproj';
  readonly ecosystem = 'NuGet' as const;
  readonly precision = 'manifest-pinned' as const;
  matches(path: string): boolean {
    return path.endsWith('.csproj');
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const packages: ResolvedPackage[] = [];
    for (const match of content.matchAll(/<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"/g)) {
      if (!match[1] || !match[2]) continue;
      packages.push({ ecosystem: 'NuGet', name: match[1], version: match[2], precision: 'manifest-pinned', direct: true, source: { path } });
    }
    return packages;
  }
}

interface ComposerPkg {
  name?: string;
  version?: string;
}

function composerList(packages: ComposerPkg[] | undefined, dev: boolean, path: string): ResolvedPackage[] {
  return (packages ?? []).flatMap((pkg) =>
    pkg.name && pkg.version
      ? [{ ecosystem: 'Packagist' as const, name: pkg.name, version: pkg.version.replace(/^v/, ''), precision: 'lockfile' as const, dev, source: { path } }]
      : [],
  );
}

function composerRequire(deps: Record<string, string> | undefined, dev: boolean, path: string): ResolvedPackage[] {
  const packages: ResolvedPackage[] = [];
  for (const [name, spec] of Object.entries(deps ?? {})) {
    if (!name.includes('/')) continue;
    const parsed = npmSpecifier(spec.replace(/^v/, ''));
    if (!parsed) continue;
    packages.push({ ecosystem: 'Packagist', name, version: parsed.version, precision: parsed.precision, direct: true, dev, source: { path } });
  }
  return packages;
}

function cargoTable(deps: Record<string, string | { version?: string }> | undefined, dev: boolean, path: string): ResolvedPackage[] {
  const packages: ResolvedPackage[] = [];
  for (const [name, spec] of Object.entries(deps ?? {})) {
    const raw = typeof spec === 'string' ? spec : spec.version ?? '';
    const parsed = npmSpecifier(raw) ?? npmSpecifier(raw.replace(/^\^/, ''));
    if (!parsed) continue;
    packages.push(crate(name, parsed.version, parsed.precision, path, dev));
  }
  return packages;
}

function crate(
  name: string,
  version: string,
  precision: ResolvedPackage['precision'],
  path: string,
  dev: boolean | undefined,
  dependsOn?: string[],
): ResolvedPackage {
  return {
    ecosystem: 'crates.io',
    name,
    version,
    precision,
    ...(dev === undefined ? {} : { dev, direct: true }),
    ...(dependsOn ? { dependsOn } : {}),
    source: { path },
  };
}

function depName(value: string): string {
  return value.split(' ')[0] ?? value;
}
