import { parse as parseToml } from 'smol-toml';
import { fileName, type ManifestParser, type ResolvedPackage } from './types.js';
import { pythonSpecifier } from './specifiers.js';

export class PoetryLockParser implements ManifestParser {
  readonly id = 'poetry-lock';
  readonly ecosystem = 'PyPI' as const;
  readonly precision = 'lockfile' as const;
  matches(path: string): boolean {
    return fileName(path) === 'poetry.lock';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const doc = parseToml(content) as { package?: PoetryPackage[] };
    return (doc.package ?? []).flatMap((pkg) =>
      pkg.name && pkg.version
        ? [pythonPackage(pkg.name, pkg.version, 'lockfile', path, pkg.category === 'dev', true)]
        : [],
    );
  }
}

export class PipfileLockParser implements ManifestParser {
  readonly id = 'pipfile-lock';
  readonly ecosystem = 'PyPI' as const;
  readonly precision = 'lockfile' as const;
  matches(path: string): boolean {
    return fileName(path) === 'Pipfile.lock';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const json = JSON.parse(content) as { default?: Record<string, { version?: string }>; develop?: Record<string, { version?: string }> };
    return [
      ...pipfileSection(json.default, false, path),
      ...pipfileSection(json.develop, true, path),
    ];
  }
}

export class UvLockParser implements ManifestParser {
  readonly id = 'uv-lock';
  readonly ecosystem = 'PyPI' as const;
  readonly precision = 'lockfile' as const;
  matches(path: string): boolean {
    return fileName(path) === 'uv.lock';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    return tomlPackages(content, path);
  }
}

export class PdmLockParser implements ManifestParser {
  readonly id = 'pdm-lock';
  readonly ecosystem = 'PyPI' as const;
  readonly precision = 'lockfile' as const;
  matches(path: string): boolean {
    return fileName(path) === 'pdm.lock';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    return tomlPackages(content, path);
  }
}

export class RequirementsParser implements ManifestParser {
  readonly id = 'requirements-txt';
  readonly ecosystem = 'PyPI' as const;
  readonly precision = 'manifest-range' as const;
  matches(path: string): boolean {
    return /(^|\/)requirements[^/]*\.txt$/.test(path);
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const packages: ResolvedPackage[] = [];
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = (lines[index] ?? '').replace(/#.*$/, '').trim();
      if (!line || line.startsWith('-') || line.includes('://')) continue;
      const name = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(line)?.[1];
      const spec = line.slice(name?.length ?? 0).replace(/\[.*\]/, '').trim();
      const parsed = pythonSpecifier(spec || line.slice(name?.length ?? 0));
      if (!name || !parsed) continue;
      packages.push({ ...pythonPackage(name, parsed.version, parsed.precision, path, false, true), source: { path, line: index + 1 } });
    }
    return packages;
  }
}

export class PyprojectParser implements ManifestParser {
  readonly id = 'pyproject';
  readonly ecosystem = 'PyPI' as const;
  readonly precision = 'manifest-range' as const;
  matches(path: string): boolean {
    return fileName(path) === 'pyproject.toml';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const doc = parseToml(content) as {
      project?: { dependencies?: string[]; 'optional-dependencies'?: Record<string, string[]> };
      tool?: { poetry?: { dependencies?: Record<string, string | { version?: string }>; group?: Record<string, { dependencies?: Record<string, string | { version?: string }> }> } };
    };
    const packages: ResolvedPackage[] = [];
    for (const dep of doc.project?.dependencies ?? []) packages.push(...requirementLine(dep, false, path));
    for (const [group, deps] of Object.entries(doc.project?.['optional-dependencies'] ?? {})) {
      for (const dep of deps) packages.push(...requirementLine(dep, group === 'dev', path));
    }
    packages.push(...poetryTable(doc.tool?.poetry?.dependencies, false, path));
    for (const group of Object.values(doc.tool?.poetry?.group ?? {})) {
      packages.push(...poetryTable(group.dependencies, true, path));
    }
    return packages.filter((pkg) => pkg.name !== 'python');
  }
}

interface PoetryPackage {
  name?: string;
  version?: string;
  category?: string;
}

function pipfileSection(section: Record<string, { version?: string }> | undefined, dev: boolean, path: string): ResolvedPackage[] {
  return Object.entries(section ?? {}).flatMap(([name, meta]) => {
    const parsed = pythonSpecifier((meta.version ?? '').replace(/^==/, '=='));
    if (!parsed) return [];
    return [pythonPackage(name, parsed.version, 'lockfile', path, dev, true)];
  });
}

function tomlPackages(content: string, path: string): ResolvedPackage[] {
  const doc = parseToml(content) as { package?: { name?: string; version?: string }[] };
  return (doc.package ?? []).flatMap((pkg) =>
    pkg.name && pkg.version ? [pythonPackage(pkg.name, pkg.version, 'lockfile', path, false, undefined)] : [],
  );
}

function requirementLine(dep: string, dev: boolean, path: string): ResolvedPackage[] {
  const name = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(dep)?.[1];
  const parsed = pythonSpecifier(dep.slice(name?.length ?? 0));
  if (!name || !parsed) return [];
  return [pythonPackage(name, parsed.version, parsed.precision, path, dev, true)];
}

function poetryTable(deps: Record<string, string | { version?: string }> | undefined, dev: boolean, path: string): ResolvedPackage[] {
  const packages: ResolvedPackage[] = [];
  for (const [name, spec] of Object.entries(deps ?? {})) {
    if (name === 'python') continue;
    const raw = typeof spec === 'string' ? spec : spec.version ?? '';
    const parsed = pythonSpecifier(raw.startsWith('^') || raw.startsWith('~') ? raw : `>=${raw.replace(/[^0-9.].*$/, '')}`);
    const normalized = pythonSpecifier(raw.includes('>') || raw.includes('^') || raw.includes('~') || raw.includes('=') ? raw.replace('^', '>=').replace('~', '>=') : `==${raw}`);
    const chosen = normalized ?? parsed;
    if (!chosen) continue;
    packages.push(pythonPackage(name, chosen.version, chosen.precision, path, dev, true));
  }
  return packages;
}

function pythonPackage(
  name: string,
  version: string,
  precision: ResolvedPackage['precision'],
  path: string,
  dev: boolean,
  direct: boolean | undefined,
): ResolvedPackage {
  return {
    ecosystem: 'PyPI',
    name,
    version,
    precision,
    dev,
    ...(direct === undefined ? {} : { direct }),
    source: { path },
  };
}
