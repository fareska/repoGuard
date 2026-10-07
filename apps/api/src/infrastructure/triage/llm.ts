import { z } from 'zod';
import type { Finding, TriageOutput } from '@repoguard/shared';
import type { Config } from '../../config/env.js';
import { ruleTriage, type TriageInput } from './rules.js';

const PROMPT_VERSION = 'rules-llm-1';

const outputSchema = z.object({
  summary: z.object({
    headline: z.string().min(1).max(180),
    riskLevel: z.enum(['critical', 'high', 'medium', 'low', 'clean']),
    text: z.string().min(1).max(800),
  }),
  topRisks: z.array(z.object({ findingId: z.string(), whyItMatters: z.string().min(1).max(400) })).max(5),
  nextActions: z.array(
    z.object({
      id: z.string(),
      title: z.string(),
      description: z.string(),
      type: z.enum(['upgrade', 'override', 'replace', 'remove', 'rotate_secret', 'code_change', 'config_change', 'process']),
      effort: z.enum(['S', 'M', 'L']),
      impact: z.enum(['high', 'medium', 'low']),
      findingIds: z.array(z.string()),
    }),
  ),
  groups: z.array(z.object({ label: z.string(), findingIds: z.array(z.string()) })),
});

export class RuleBasedTriageProvider {
  readonly id = 'rules';
  triage(input: TriageInput): Promise<TriageOutput> {
    return Promise.resolve(ruleTriage(input));
  }
}

export class LlmTriageProvider {
  readonly id = 'llm';
  readonly promptVersion = PROMPT_VERSION;

  constructor(
    private readonly config: Config,
    private readonly fallback: RuleBasedTriageProvider,
  ) {}

  async triage(input: TriageInput): Promise<TriageOutput> {
    try {
      return await this.ask(input, false);
    } catch {
      try {
        return await this.ask(input, true);
      } catch {
        return this.fallback.triage(input);
      }
    }
  }

  private async ask(input: TriageInput, strict: boolean): Promise<TriageOutput> {
    const response = await fetch(`${this.config.LLM_BASE_URL}/chat/completions`, {
      method: 'POST',
      headers: {
        authorization: `Bearer ${this.config.LLM_API_KEY ?? ''}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: this.config.LLM_MODEL,
        max_tokens: this.config.LLM_MAX_TOKENS,
        temperature: 0,
        response_format: { type: 'json_object' },
        messages: [
          {
            role: 'system',
            content:
              'You prioritize existing security findings. Return JSON only. Do not invent findings or package names. Every findingId must come from the input. Label any replacement you suggest as unverified.',
          },
          { role: 'user', content: JSON.stringify(redactedInput(input, strict)) },
        ],
      }),
      signal: AbortSignal.timeout(this.config.STAGE_TIMEOUT_TRIAGE_MS),
    });
    if (!response.ok) throw new Error(`LLM HTTP ${response.status}`);
    const body = (await response.json()) as { choices?: { message?: { content?: string } }[] };
    const content = body.choices?.[0]?.message?.content;
    if (!content) throw new Error('LLM returned an empty response');
    const parsed = outputSchema.parse(JSON.parse(content));
    return keepKnownFindings(parsed, input.findings);
  }
}

function redactedInput(input: TriageInput, strict: boolean) {
  return {
    repoName: input.repoName,
    languages: input.languages,
    scannersRun: input.scannersRun,
    instruction: strict ? 'Previous JSON was invalid. Return only the schema.' : undefined,
    findings: input.findings.map((finding) => ({
      id: finding.id,
      title: finding.title,
      severity: finding.adjustedSeverity,
      category: finding.category,
      confidence: finding.confidence,
      rationale: finding.severityRationale,
      remediation: finding.remediation.summary,
      path: finding.location?.path,
      snippet: finding.location?.snippet?.split('\n').slice(0, 20).join('\n'),
    })),
  };
}

function keepKnownFindings(output: TriageOutput, findings: Finding[]): TriageOutput {
  const ids = new Set(findings.map((finding) => finding.id));
  return {
    summary: output.summary,
    topRisks: output.topRisks.filter((risk) => ids.has(risk.findingId)).slice(0, 5),
    nextActions: output.nextActions
      .map((action) => ({ ...action, findingIds: action.findingIds.filter((id) => ids.has(id)) }))
      .filter((action) => action.findingIds.length > 0),
    groups: output.groups
      .map((group) => ({ ...group, findingIds: group.findingIds.filter((id) => ids.has(id)) }))
      .filter((group) => group.findingIds.length > 0),
  };
}

export { PROMPT_VERSION };
