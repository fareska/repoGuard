import {
  countsOf,
  severityRank,
  type Finding,
  type NextAction,
  type RiskLevel,
  type TriageOutput,
} from '@repoguard/shared';

export interface TriageInput {
  repoName: string;
  findings: Finding[];
  languages: string[];
  scannersRun: string[];
}

const CONFIDENCE_SCORE = { high: 3, medium: 2, low: 1 } as const;

export function ruleTriage(input: TriageInput): TriageOutput {
  const findings = [...input.findings].sort(compareFindings);
  const riskLevel = riskOf(findings);
  const topRisks = findings
    .filter((finding) => finding.category !== 'hygiene' && finding.adjustedSeverity !== 'info')
    .slice(0, 5)
    .map((finding) => ({ findingId: finding.id, whyItMatters: whyItMatters(finding) }));
  const nextActions = buildActions(findings);
  const counts = countsOf(findings);
  const notable = counts.bySeverity.critical + counts.bySeverity.high;
  const first = nextActions[0];
  const headline = headlineFor(riskLevel, input.repoName, notable);
  const text = [
    findings.length === 0
      ? `${input.repoName} has no findings in the scanners that ran.`
      : `${input.repoName} has ${findings.length} findings, including ${counts.bySeverity.critical} critical and ${counts.bySeverity.high} high.`,
    first ? `Start with: ${first.title}.` : 'Nothing in the scanned scope needs a change.',
    `${input.scannersRun.length} ${input.scannersRun.length === 1 ? 'scanner' : 'scanners'} ran${input.languages.length ? ` across ${input.languages.join(', ')}` : ''}.`,
  ].join(' ');
  return {
    summary: { headline, riskLevel, text },
    topRisks,
    nextActions,
    groups: nextActions.map((action) => ({ label: action.title, findingIds: action.findingIds })),
  };
}

function buildActions(findings: Finding[]): NextAction[] {
  const actions: NextAction[] = [];
  const dependencies = new Map<string, Finding[]>();
  const secrets: Finding[] = [];
  const config: Finding[] = [];
  const hygiene: Finding[] = [];
  for (const finding of findings) {
    if (finding.category === 'dependency') {
      const name = String(finding.evidence.package ?? finding.ruleId);
      const ecosystem = String(finding.evidence.ecosystem ?? '');
      const key = `${ecosystem}:${name}`;
      const list = dependencies.get(key) ?? [];
      list.push(finding);
      dependencies.set(key, list);
    } else if (finding.category === 'secret') secrets.push(finding);
    else if (finding.category === 'config') config.push(finding);
    else if (finding.category === 'hygiene') hygiene.push(finding);
  }
  for (const [, group] of dependencies) actions.push(dependencyAction(group));
  if (secrets.length > 0) {
    actions.push({
      id: 'act_rotate_secrets',
      title: `Rotate and remove ${secrets.length} leaked secret${secrets.length === 1 ? '' : 's'}`,
      description: 'Revoke each credential, delete it from the tree, and keep the replacement out of git.',
      type: 'rotate_secret',
      effort: 'S',
      impact: 'high',
      findingIds: secrets.map((finding) => finding.id),
    });
  }
  if (config.length > 0) {
    actions.push({
      id: 'act_harden_config',
      title: 'Harden CI and container config',
      description: 'Apply the configuration changes grouped here. They are local edits, not dependency upgrades.',
      type: 'config_change',
      effort: maxEffort(config),
      impact: impactOf(config),
      findingIds: config.map((finding) => finding.id),
    });
  }
  if (hygiene.length > 0) {
    actions.push({
      id: 'act_hygiene',
      title: 'Close repository hygiene gaps',
      description: 'These do not change the exploitability of the code, but they make the next scan and the next reporter more useful.',
      type: 'process',
      effort: 'S',
      impact: 'low',
      findingIds: hygiene.map((finding) => finding.id),
    });
  }
  return actions.sort((left, right) => impactRank(right.impact) - impactRank(left.impact) || effortRank(left.effort) - effortRank(right.effort));
}

function dependencyAction(group: Finding[]): NextAction {
  const sample = group[0];
  const name = String(sample?.evidence.package ?? 'dependency');
  const version = String(sample?.evidence.version ?? '');
  const fixed = group.map((finding) => finding.remediation.fixVersion).find(Boolean);
  const malicious = group.some((finding) => finding.remediation.type === 'remove' || finding.evidence.malicious === true);
  const replace = group.some((finding) => finding.remediation.type === 'replace' || !finding.context.fixAvailable);
  const transitive = group.every((finding) => finding.context.isDirectDependency === false);
  const parent = group.flatMap((finding) => finding.context.parents ?? [])[0];
  const ids = group.map((finding) => finding.id);
  if (!sample) {
    return { id: 'act_empty', title: 'Review dependencies', description: '', type: 'upgrade', effort: 'S', impact: 'low', findingIds: [] };
  }
  if (malicious) {
    return {
      id: `act_remove_${slug(name)}`,
      title: `Remove ${name} now`,
      description: `${name} is flagged as malicious. Remove it and rotate anything the install could have touched.`,
      type: 'remove',
      effort: 'S',
      impact: 'high',
      findingIds: ids,
    };
  }
  if (replace && !fixed) {
    return {
      id: `act_replace_${slug(name)}`,
      title: `Replace ${name}`,
      description: `${name} ${version} has no fixed version, or the maintainers have walked away. Replacing it is the durable fix.`,
      type: 'replace',
      effort: 'M',
      impact: impactOf(group),
      findingIds: ids,
    };
  }
  if (transitive && !parent) {
    return {
      id: `act_override_${slug(name)}`,
      title: `Pin ${name}${fixed ? ` to ${fixed}` : ''}`,
      description: `${name} is transitive and the parent that pulls it in is not recorded. Pin it with the ecosystem override mechanism.`,
      type: 'override',
      effort: 'M',
      impact: impactOf(group),
      findingIds: ids,
    };
  }
  const target = fixed ? `${version} → ${fixed}` : version;
  const parentNote = parent ? ` Update ${parent}, which pulls it in.` : '';
  return {
    id: `act_upgrade_${slug(name)}`,
    title: `Upgrade ${name} ${target} — closes ${group.length} advisory${group.length === 1 ? '' : 'ies'}`.replace('advisoryies', 'advisories'),
    description: `Upgrade ${name} to clear ${group.length} finding${group.length === 1 ? '' : 's'}.${parentNote}`,
    type: 'upgrade',
    effort: maxEffort(group),
    impact: impactOf(group),
    findingIds: ids,
  };
}

function whyItMatters(finding: Finding): string {
  if (finding.context.kev) return `${finding.title} is actively exploited in the wild.`;
  const epss = finding.severityRationale.find((line) => line.includes('EPSS'));
  if (epss) return epss;
  return finding.severityRationale[0] ?? finding.description;
}

function riskOf(findings: Finding[]): RiskLevel {
  const security = findings.filter((finding) => finding.category !== 'hygiene' && finding.adjustedSeverity !== 'info');
  if (security.length === 0) return findings.some((finding) => finding.category === 'hygiene' && finding.adjustedSeverity !== 'info') ? 'low' : 'clean';
  const max = Math.max(...security.map((finding) => severityRank(finding.adjustedSeverity)));
  if (max >= severityRank('critical')) return 'critical';
  if (max >= severityRank('high')) return 'high';
  if (max >= severityRank('medium')) return 'medium';
  return 'low';
}

function headlineFor(level: RiskLevel, name: string, notable: number): string {
  if (level === 'clean') return `${name} looks clean in the scanners that ran`;
  if (level === 'critical') return `${name} has critical issues to handle first`;
  if (level === 'high') return `${name} has ${notable} high-priority issues`;
  if (level === 'medium') return `${name} has issues worth scheduling`;
  return `${name} has a few lower-priority gaps`;
}

function compareFindings(left: Finding, right: Finding): number {
  const severity = severityRank(right.adjustedSeverity) - severityRank(left.adjustedSeverity);
  if (severity !== 0) return severity;
  const confidence = CONFIDENCE_SCORE[right.confidence] - CONFIDENCE_SCORE[left.confidence];
  if (confidence !== 0) return confidence;
  return Number(right.context.fixAvailable === true) - Number(left.context.fixAvailable === true);
}

function impactOf(findings: Finding[]): NextAction['impact'] {
  const max = Math.max(...findings.map((finding) => severityRank(finding.adjustedSeverity)));
  if (max >= severityRank('high')) return 'high';
  if (max >= severityRank('medium')) return 'medium';
  return 'low';
}

function maxEffort(findings: Finding[]): NextAction['effort'] {
  if (findings.some((finding) => finding.remediation.effort === 'L')) return 'L';
  if (findings.some((finding) => finding.remediation.effort === 'M')) return 'M';
  return 'S';
}

function impactRank(impact: NextAction['impact']): number {
  if (impact === 'high') return 3;
  if (impact === 'medium') return 2;
  return 1;
}

function effortRank(effort: NextAction['effort']): number {
  if (effort === 'S') return 0;
  if (effort === 'M') return 1;
  return 2;
}

function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'pkg';
}
