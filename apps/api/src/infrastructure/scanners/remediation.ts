import type { Ecosystem } from '@repoguard/shared';
import type { Remediation } from '@repoguard/shared';
import { sameMajor } from '../../domain/findings.js';

const ALTERNATIVES: Record<string, Record<string, string>> = {
  npm: {
    request: 'undici',
    'request-promise': 'undici',
    'request-promise-native': 'undici',
    'node-uuid': 'uuid',
  },
};

export function curatedAlternative(ecosystem: string, name: string, deprecation?: string): Remediation['alternative'] | undefined {
  const curated = ALTERNATIVES[ecosystem]?.[name];
  if (curated) return { name: curated, source: 'curated' };
  const match = deprecation?.match(/[`'](@?[A-Za-z0-9._/-]+)[`']/);
  if (match?.[1] && match[1] !== name && !match[1].includes(' ')) return { name: match[1], source: 'registry_deprecation' };
  return undefined;
}

export function upgradeCommand(ecosystem: Ecosystem, name: string, version: string): string {
  switch (ecosystem) {
    case 'npm':
      return `npm install ${name}@${version}`;
    case 'PyPI':
      return `pip install '${name}==${version}'`;
    case 'Go':
      return `go get ${name}@${version.startsWith('v') ? version : `v${version}`}`;
    case 'crates.io':
      return `cargo update -p ${name} --precise ${version}`;
    case 'RubyGems':
      return `bundle update ${name}`;
    case 'Packagist':
      return `composer update ${name}:${version}`;
    case 'NuGet':
      return `dotnet add package ${name} --version ${version}`;
    case 'Maven':
      return `Set ${name} to ${version} in the dependency declaration.`;
    default:
      return `Upgrade ${name} to ${version}.`;
  }
}

export function overrideSteps(ecosystem: Ecosystem, name: string, version: string, parent?: string): string[] {
  const lead = parent
    ? `Update ${parent}, which pulls in ${name}, or pin ${name} yourself.`
    : `Pin ${name} so the vulnerable version cannot be installed.`;
  switch (ecosystem) {
    case 'npm':
      return [lead, `Add "overrides": { "${name}": "${version}" } to package.json, then reinstall.`];
    case 'PyPI':
      return [lead, `Add a constraint forcing ${name}==${version} and regenerate the lockfile.`];
    case 'Go':
      return [lead, `Add a replace directive for ${name} ${version} in go.mod.`];
    case 'crates.io':
      return [lead, `Set ${name} = "${version}" in [patch.crates-io] or update the parent crate.`];
    default:
      return [lead, `Force ${name} ${version} using the ecosystem's override or constraint mechanism.`];
  }
}

export function upgradeEffort(current: string, fixed: string): 'S' | 'M' {
  return sameMajor(current, fixed) ? 'S' : 'M';
}
