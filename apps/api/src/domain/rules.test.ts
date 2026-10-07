import { describe, expect, it } from 'vitest';
import { assertTransition, IllegalTransitionError } from './stateMachine.js';
import { adjustSeverity, type RawFinding } from './findings.js';
import { parseRepoUrl } from '@repoguard/shared';

describe('state machine', () => {
  it('allows the happy path and rejects terminal writes', () => {
    expect(() => assertTransition('queued', 'fetching')).not.toThrow();
    expect(() => assertTransition('completed', 'failed')).toThrow(IllegalTransitionError);
  });
});

describe('repository URLs', () => {
  it('accepts public github URLs and rejects everything else', () => {
    expect(parseRepoUrl('https://github.com/acme/shop')).toMatchObject({ owner: 'acme', name: 'shop' });
    expect(parseRepoUrl('https://github.com/acme/shop.git')?.name).toBe('shop');
    expect(parseRepoUrl('https://github.com/acme/shop/tree/release/1')?.ref).toBe('release/1');
    expect(parseRepoUrl('https://gitlab.com/acme/shop')).toBeNull();
    expect(parseRepoUrl('http://github.com/acme/shop')).toBeNull();
    expect(parseRepoUrl('https://github.com/acme/shop/issues')).toBeNull();
  });
});

describe('severity adjustments', () => {
  it('raises KEV to critical and lowers dev dependencies without going below low', () => {
    const kev = adjustSeverity(raw({ kev: true, severity: 'medium' }));
    expect(kev.severity).toBe('critical');
    expect(kev.rationale.join(' ')).toContain('CISA KEV');
    const dev = adjustSeverity(raw({ isDevDependency: true, severity: 'low' }));
    expect(dev.severity).toBe('low');
    const ranged = adjustSeverity(raw({ precision: 'manifest-range', severity: 'high' }));
    expect(ranged.severity).toBe('medium');
  });
});

function raw(overrides: { kev?: boolean; severity?: RawFinding['severity']; isDevDependency?: boolean; precision?: RawFinding['context']['precision'] }): RawFinding {
  return {
    scanner: 'deps-vuln',
    category: 'dependency',
    ruleId: 'GHSA-test',
    title: 'test',
    description: 'test',
    severity: overrides.severity ?? 'high',
    confidence: 'high',
    evidence: {},
    cwe: [],
    references: [],
    remediation: { summary: 'upgrade', steps: [], effort: 'S', type: 'upgrade' },
    context: {
      ...(overrides.kev ? { kev: true } : {}),
      ...(overrides.isDevDependency ? { isDevDependency: true } : {}),
      ...(overrides.precision ? { precision: overrides.precision } : {}),
    },
    fingerprintMaterial: 'test',
  };
}
