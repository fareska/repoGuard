import type { Ecosystem } from '@repoguard/shared';
import { fileName, type ManifestParser, type ResolvedPackage } from './types.js';

const PURL_ECOSYSTEM: Record<string, Ecosystem> = {
  npm: 'npm',
  pypi: 'PyPI',
  cargo: 'crates.io',
  gem: 'RubyGems',
  composer: 'Packagist',
  nuget: 'NuGet',
  maven: 'Maven',
  golang: 'Go',
};

export class SbomParser implements ManifestParser {
  readonly id = 'sbom';
  readonly ecosystem = 'npm' as const;
  readonly precision = 'lockfile' as const;

  matches(path: string): boolean {
    const name = fileName(path).toLowerCase();
    return name.endsWith('.cdx.json') || name === 'bom.json' || name.endsWith('.spdx.json') || name === 'spdx.json';
  }

  parse(content: string, path: string): ResolvedPackage[] {
    const json = JSON.parse(content) as {
      bomFormat?: string;
      components?: { type?: string; name?: string; version?: string; purl?: string }[];
      spdxVersion?: string;
      packages?: { name?: string; versionInfo?: string; externalRefs?: { referenceType?: string; referenceLocator?: string }[] }[];
    };
    if (json.bomFormat === 'CycloneDX') return (json.components ?? []).flatMap((component) => fromPurl(component.purl, component.name, component.version, path));
    if (json.spdxVersion) {
      return (json.packages ?? []).flatMap((pkg) => {
        const purl = pkg.externalRefs?.find((ref) => ref.referenceType === 'purl')?.referenceLocator;
        return fromPurl(purl, pkg.name, pkg.versionInfo, path);
      });
    }
    return [];
  }
}

function fromPurl(purl: string | undefined, fallbackName: string | undefined, fallbackVersion: string | undefined, path: string): ResolvedPackage[] {
  if (!purl?.startsWith('pkg:')) {
    return [];
  }
  const body = purl.slice(4).split('?')[0] ?? '';
  const type = body.split('/')[0] ?? '';
  const ecosystem = PURL_ECOSYSTEM[type];
  if (!ecosystem) return [];
  const at = body.lastIndexOf('@');
  if (at === -1) return [];
  const name = decodeURIComponent(body.slice(type.length + 1, at));
  const version = decodeURIComponent(body.slice(at + 1));
  if (!name || !version) return [];
  return [{ ecosystem, name: name || fallbackName || '', version: version || fallbackVersion || '', precision: 'lockfile', direct: true, source: { path } }];
}
