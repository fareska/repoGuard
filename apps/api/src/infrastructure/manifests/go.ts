import { fileName, type ManifestParser, type ResolvedPackage } from './types.js';

export class GoSumParser implements ManifestParser {
  readonly id = 'go-sum';
  readonly ecosystem = 'Go' as const;
  readonly precision = 'lockfile' as const;
  matches(path: string): boolean {
    return fileName(path) === 'go.sum';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const packages: ResolvedPackage[] = [];
    const lines = content.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const match = /^(\S+)\s+(v\S+)\s+h1:/.exec(lines[index] ?? '');
      if (!match?.[1] || !match[2] || match[2].endsWith('/go.mod')) continue;
      packages.push({ ecosystem: 'Go', name: match[1], version: match[2], precision: 'lockfile', source: { path, line: index + 1 } });
    }
    return packages;
  }
}

export class GoModParser implements ManifestParser {
  readonly id = 'go-mod';
  readonly ecosystem = 'Go' as const;
  readonly precision = 'manifest-pinned' as const;
  matches(path: string): boolean {
    return fileName(path) === 'go.mod';
  }
  parse(content: string, path: string): ResolvedPackage[] {
    const packages: ResolvedPackage[] = [];
    const block = /require\s*\(([^)]*)\)/g;
    for (const match of content.matchAll(block)) packages.push(...requireLines(match[1] ?? '', path));
    const single = /^require\s+(\S+)\s+(v\S+)/gm;
    for (const match of content.matchAll(single)) {
      if (!match[1] || !match[2]) continue;
      packages.push(goPackage(match[1], match[2], path, false));
    }
    return packages;
  }
}

function requireLines(block: string, path: string): ResolvedPackage[] {
  const packages: ResolvedPackage[] = [];
  for (const line of block.split(/\r?\n/)) {
    const match = /^\s*(\S+)\s+(v\S+)/.exec(line);
    if (!match?.[1] || !match[2]) continue;
    packages.push(goPackage(match[1], match[2], path, /\/\/\s*indirect/.test(line)));
  }
  return packages;
}

function goPackage(name: string, version: string, path: string, indirect: boolean): ResolvedPackage {
  return {
    ecosystem: 'Go',
    name,
    version,
    precision: 'manifest-pinned',
    direct: !indirect,
    dev: false,
    source: { path },
  };
}
