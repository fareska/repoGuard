import { describe, expect, it } from 'vitest';
import { finalizeFinding, type RawFinding } from '../../domain/findings.js';
import { ruleTriage } from './rules.js';

describe('rule triage', () => {
  it('groups a fixable package and puts the secret in the top risks', () => {
    const secret = finalizeFinding(base('secrets', 'secret', 'critical', 'SECRET_AWS', 'rotate_secret'));
    const vuln = finalizeFinding({
      ...base('deps-vuln', 'dependency', 'high', 'GHSA-1', 'upgrade'),
      evidence: { package: 'qs', ecosystem: 'npm', version: '6.5.2' },
      remediation: { ...base('deps-vuln', 'dependency', 'high', 'GHSA-1', 'upgrade').remediation, fixVersion: '6.5.3' },
      context: { fixAvailable: true, isDirectDependency: true },
    });
    const output = ruleTriage({ repoName: 'shop', findings: [secret, vuln], languages: ['TypeScript'], scannersRun: ['secrets', 'deps-vuln'] });
    expect(output.summary.riskLevel).toBe('critical');
    expect(output.topRisks[0]?.findingId).toBe(secret.id);
    expect(output.nextActions.some((action) => action.type === 'rotate_secret')).toBe(true);
    expect(output.nextActions.some((action) => action.title.includes('qs'))).toBe(true);
  });
});

function base(scanner: string, category: RawFinding['category'], severity: RawFinding['severity'], ruleId: string, type: RawFinding['remediation']['type']): RawFinding {
  return {
    scanner,
    category,
    ruleId,
    title: ruleId,
    description: 'because',
    severity,
    confidence: 'high',
    evidence: {},
    cwe: [],
    references: [],
    remediation: { summary: 'do it', steps: ['do it'], effort: 'S', type },
    context: {},
    fingerprintMaterial: ruleId,
  };
}
