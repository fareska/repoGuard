import type { ScanMode } from '@repoguard/shared';
import type { Config } from '../../config/env.js';
import type { EnrichmentClient } from '../enrichment/client.js';
import type { GitHubClient } from '../github/client.js';
import { createParsers } from '../manifests/registry.js';
import { ConfigScanner } from './config.js';
import { DependencyHealthScanner } from './depsHealth.js';
import { DependencyHygieneScanner } from './depsHygiene.js';
import { DependencyVulnScanner } from './depsVuln.js';
import { HygieneScanner } from './hygiene.js';
import { MockScanner } from './mock.js';
import { SecretScanner } from './secrets.js';
import type { Scanner } from './types.js';

export function createScanners(config: Config, enrichment: EnrichmentClient, github: GitHubClient): Scanner[] {
  const parsers = createParsers();
  return [
    new DependencyVulnScanner(parsers, enrichment, config.MAX_MANIFEST_BYTES),
    new DependencyHealthScanner(parsers, enrichment, config.MAX_MANIFEST_BYTES, (projectId, signal) =>
      github.archived(projectId, signal),
    ),
    new DependencyHygieneScanner(parsers, config.MAX_MANIFEST_BYTES),
    new SecretScanner(),
    new ConfigScanner(),
    new HygieneScanner(),
    new MockScanner(config.MOCK_DELAY_MS),
  ];
}

export function scannersForMode(scanners: Scanner[], mode: ScanMode, requested?: string[]): Scanner[] {
  const pool = scanners.filter((scanner) => {
    if (mode === 'mock') return scanner.id === 'mock';
    if (mode === 'hybrid') return true;
    return scanner.id !== 'mock';
  });
  if (!requested || requested.length === 0 || mode === 'mock') return pool;
  const known = new Set(pool.map((scanner) => scanner.id));
  const unknown = requested.filter((id) => !known.has(id));
  if (unknown.length > 0) {
    const error = new Error(`Unknown scanners: ${unknown.join(', ')}`);
    error.name = 'UnknownScannerError';
    throw error;
  }
  return pool.filter((scanner) => requested.includes(scanner.id));
}
