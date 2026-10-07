import { CargoLockParser, CargoTomlParser, ComposerJsonParser, ComposerLockParser, CsprojParser, GemfileLockParser, GemfileParser, NugetLockParser } from './ecosystems.js';
import { GoModParser, GoSumParser } from './go.js';
import { NpmLockParser, PackageJsonParser, PnpmLockParser, YarnLockParser } from './npm.js';
import { PdmLockParser, PipfileLockParser, PoetryLockParser, PyprojectParser, RequirementsParser, UvLockParser } from './pypi.js';
import { SbomParser } from './sbom.js';
import type { ManifestParser } from './types.js';

export function createParsers(): ManifestParser[] {
  return [
    new NpmLockParser(),
    new YarnLockParser(),
    new PnpmLockParser(),
    new PackageJsonParser(),
    new PoetryLockParser(),
    new PipfileLockParser(),
    new UvLockParser(),
    new PdmLockParser(),
    new RequirementsParser(),
    new PyprojectParser(),
    new GoSumParser(),
    new GoModParser(),
    new CargoLockParser(),
    new CargoTomlParser(),
    new GemfileLockParser(),
    new GemfileParser(),
    new ComposerLockParser(),
    new ComposerJsonParser(),
    new NugetLockParser(),
    new CsprojParser(),
    new SbomParser(),
  ];
}

export const ECOSYSTEM_CATALOG = [
  { id: 'npm' as const, lockfiles: ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'], manifests: ['package.json'] },
  { id: 'PyPI' as const, lockfiles: ['poetry.lock', 'Pipfile.lock', 'uv.lock', 'pdm.lock'], manifests: ['requirements.txt', 'pyproject.toml'] },
  { id: 'Go' as const, lockfiles: ['go.sum'], manifests: ['go.mod'] },
  { id: 'crates.io' as const, lockfiles: ['Cargo.lock'], manifests: ['Cargo.toml'] },
  { id: 'RubyGems' as const, lockfiles: ['Gemfile.lock'], manifests: ['Gemfile'] },
  { id: 'Packagist' as const, lockfiles: ['composer.lock'], manifests: ['composer.json'] },
  { id: 'NuGet' as const, lockfiles: ['packages.lock.json'], manifests: ['*.csproj'] },
];
