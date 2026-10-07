import { parse as parseYaml } from 'yaml';
import type { RawFinding } from '../../domain/findings.js';
import { countPhrase } from '../../domain/text.js';
import type { RepoContext } from '../github/repoContext.js';
import type { ProgressReporter, Scanner } from './types.js';

const SECRET_NAME = /(SECRET|PASSWORD|TOKEN|API_KEY|PASSWD|ACCESS_KEY|PRIVATE_KEY)/i;
const SHA = /^[0-9a-f]{40}$/i;

export class ConfigScanner implements Scanner {
  readonly id = 'config';
  readonly displayName = 'Configuration and CI';
  readonly description = 'Dockerfile, Compose, GitHub Actions, and committed environment files.';
  readonly weight = 12;

  supports(): boolean {
    return true;
  }

  async run(context: RepoContext, reporter: ProgressReporter, signal: AbortSignal): Promise<RawFinding[]> {
    const findings: RawFinding[] = [];
    const files = context.files.filter((file) => !file.skipReason || file.skipReason === 'too_large');
    for (let index = 0; index < files.length; index += 1) {
      if (index % 40 === 0) signal.throwIfAborted();
      const file = files[index];
      if (!file) continue;
      const content = context.readText(file.path, Math.min(file.size || 1_000_000, 1_000_000));
      if (!content) continue;
      findings.push(...scanConfigFile(file.path, content));
      if (index % 30 === 0) reporter.progress((index + 1) / files.length, `Checked ${index + 1}/${files.length} files`);
    }
    for (const finding of findings) reporter.finding(finding);
    reporter.log('info', `Configuration scan produced ${countPhrase(findings.length, 'finding')}`);
    return findings;
  }
}

export function scanConfigFile(path: string, content: string): RawFinding[] {
  const name = path.split('/').at(-1) ?? path;
  if (name === 'Dockerfile' || name.endsWith('.Dockerfile') || path.endsWith('/Dockerfile')) return scanDockerfile(path, content);
  if (/^(docker-)?compose.ya?ml$/.test(name)) return scanCompose(path, content);
  if (path.startsWith('.github/workflows/') && /\.ya?ml$/.test(name)) return scanWorkflow(path, content);
  if (isEnvFile(name)) return [configFinding('COMMITTED_ENV', 'high', `Committed environment file ${path}`, 'Environment files often hold secrets and should not be tracked.', path, 'config_change', ['Add the file to .gitignore.', 'Remove it from the index and rotate any real secrets it contains.'])];
  if (name === '.gitignore' && !/(^|\n)\s*\.env\b/.test(content) && !content.includes('.env*')) {
    return [configFinding('GITIGNORE_ENV', 'low', '.gitignore does not ignore .env files', 'A tracked .env file is easy to commit by accident.', path, 'config_change', ['Add `.env` and `.env.*` to .gitignore, with a negation for `.env.example` if you keep one.'])];
  }
  if (['.npmrc', '.pypirc', 'pip.conf', '.netrc'].includes(name) && /(token|_auth|password)\s*[:=]\s*\S+/i.test(content)) {
    return [configFinding('REGISTRY_AUTH', 'critical', `Registry credentials in ${path}`, 'A package-manager auth file with a token is committed.', path, 'rotate_secret', ['Revoke the token.', `Delete ${path} from the repository and from git history.`])];
  }
  return [];
}

function scanDockerfile(path: string, content: string): RawFinding[] {
  const findings: RawFinding[] = [];
  const lines = content.split(/\r?\n/);
  let nonRootUser = false;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]?.trim() ?? '';
    if (/^USER\s+(?!root\b)\S+/i.test(line)) nonRootUser = true;
    if (/^FROM\s+\S+:latest\b/i.test(line)) findings.push(configFinding('DOCKER_LATEST', 'medium', 'Image uses the latest tag', '`:latest` moves without a review.', path, 'config_change', ['Pin the base image to a digest or an immutable version tag.'], index + 1));
    if (/^(ENV|ARG)\s+/.test(line) && SECRET_NAME.test(line) && /=\s*\S+/.test(line) && !/\$\{?[A-Za-z_]/.test(line.split('=').slice(1).join('='))) {
      findings.push(configFinding('DOCKER_SECRET', 'high', 'Secret passed as an image ENV or ARG', 'Build arguments and environment values are visible in image history.', path, 'config_change', ['Pass secrets with BuildKit secret mounts instead of ENV or ARG.', 'Rotate the exposed value.'], index + 1));
    }
    if (/^ADD\s+https?:\/\//i.test(line)) findings.push(configFinding('DOCKER_ADD_URL', 'medium', 'Dockerfile ADD fetches a remote URL', 'ADD of a URL downloads content into the image with no integrity pin.', path, 'config_change', ['Download with a pinned checksum in a RUN step, or COPY a vendored file.'], index + 1));
    if (/\b(curl|wget)\b.*\|\s*(sh|bash)\b/i.test(line)) findings.push(configFinding('DOCKER_CURL_PIPE', 'high', 'Dockerfile pipes a remote script into a shell', 'The image build executes whatever that URL returns.', path, 'config_change', ['Vendor the script and verify its checksum before running it.'], index + 1));
  }
  if (/^FROM\s+/m.test(content) && !nonRootUser) {
    findings.push(configFinding('DOCKER_ROOT', 'medium', 'Container runs as root', 'The Dockerfile never sets a non-root USER.', path, 'config_change', ['Add a USER instruction after installing packages.']));
  }
  return findings;
}

function scanCompose(path: string, content: string): RawFinding[] {
  const findings: RawFinding[] = [];
  let doc: { services?: Record<string, ComposeService> };
  try {
    doc = parseYaml(content) as { services?: Record<string, ComposeService> };
  } catch {
    return findings;
  }
  for (const [name, service] of Object.entries(doc.services ?? {})) {
    if (service.privileged === true) findings.push(configFinding('COMPOSE_PRIVILEGED', 'high', `${name} runs privileged`, 'privileged: true removes container isolation.', path, 'config_change', [`Remove privileged from ${name} and grant only the capabilities it needs.`]));
    if (service.network_mode === 'host' || service.pid === 'host') findings.push(configFinding('COMPOSE_HOST_NAMESPACE', 'high', `${name} shares a host namespace`, 'Host network or PID gives the container broad access to the machine.', path, 'config_change', ['Use a user-defined network and the container PID namespace.']));
    const env = normalizeEnv(service.environment);
    for (const [key, value] of Object.entries(env)) {
      if (SECRET_NAME.test(key) && value && !value.startsWith('$')) {
        findings.push(configFinding('COMPOSE_INLINE_SECRET', 'high', `Inline secret ${key} in ${name}`, 'Compose environment values are stored in the repository.', path, 'rotate_secret', ['Move the value to a secret store or an untracked env file.', 'Rotate the exposed credential.']));
      }
    }
  }
  return findings;
}

function scanWorkflow(path: string, content: string): RawFinding[] {
  const findings: RawFinding[] = [];
  let doc: Workflow = {};
  try {
    doc = parseYaml(content) as Workflow;
  } catch {
    return findings;
  }
  if (permissionsWriteAll(doc.permissions)) findings.push(configFinding('ACTIONS_WRITE_ALL', 'high', 'Workflow grants write-all permissions', 'The default token can modify the repository and its packages.', path, 'config_change', ['Set the narrowest permissions the jobs need, and prefer contents: read.']));
  const raw = content;
  if (/pull_request_target/.test(raw) && /github\.event\.pull_request\.head/.test(raw)) {
    findings.push(configFinding('ACTIONS_PR_TARGET_CHECKOUT', 'critical', 'pull_request_target checks out PR head', 'Untrusted pull request code runs with the base repository token.', path, 'config_change', ['Do not check out the PR head in a pull_request_target workflow, or split the privileged job from the untrusted one.']));
  }
  for (const [jobName, job] of Object.entries(doc.jobs ?? {})) {
    if (permissionsWriteAll(job.permissions)) findings.push(configFinding('ACTIONS_WRITE_ALL', 'high', `${jobName} grants write-all`, 'This job token is broader than the workflow needs.', path, 'config_change', [`Restrict permissions on ${jobName}.`]));
    for (const step of job.steps ?? []) {
      if (typeof step.uses === 'string' && !step.uses.startsWith('./') && !isPinned(step.uses)) {
        findings.push(configFinding('ACTIONS_UNPINNED', 'medium', `Unpinned action ${step.uses}`, 'A mutable tag can change the code that runs in CI.', path, 'config_change', [`Pin ${step.uses.split('@')[0]} to a full commit SHA.`]));
      }
      if (typeof step.run === 'string') {
        if (/\$\{\{\s*github\.event\./.test(step.run)) findings.push(configFinding('ACTIONS_SCRIPT_INJECTION', 'high', `${jobName} interpolates event data into a script`, 'GitHub expression values in run: steps can break out of a string and execute.', path, 'config_change', ['Pass event data through an environment variable instead of interpolating it in the script.']));
        if (/echo\b/i.test(step.run) && /secrets\./.test(step.run)) findings.push(configFinding('ACTIONS_SECRET_ECHO', 'high', `${jobName} prints a secret`, 'Echoing secrets writes them to the workflow log.', path, 'rotate_secret', ['Remove the echo.', 'Rotate the secret if the workflow has already run.']));
      }
    }
  }
  return findings;
}

function isPinned(uses: string): boolean {
  const ref = uses.split('@')[1] ?? '';
  return SHA.test(ref);
}

function permissionsWriteAll(value: unknown): boolean {
  return value === 'write-all';
}

function isEnvFile(name: string): boolean {
  return name.startsWith('.env') && !name.endsWith('.example') && !name.endsWith('.sample') && !name.endsWith('.template');
}

function normalizeEnv(environment: ComposeService['environment']): Record<string, string> {
  if (!environment) return {};
  if (Array.isArray(environment)) {
    return Object.fromEntries(environment.map((entry) => {
      const [key, ...rest] = entry.split('=');
      return [key ?? '', rest.join('=')];
    }));
  }
  return Object.fromEntries(Object.entries(environment).map(([key, value]) => [key, String(value ?? '')]));
}

interface ComposeService {
  privileged?: boolean;
  network_mode?: string;
  pid?: string;
  environment?: Record<string, string> | string[];
}

interface Workflow {
  permissions?: unknown;
  jobs?: Record<string, { permissions?: unknown; steps?: { uses?: string; run?: string }[] }>;
}

function configFinding(
  ruleId: string,
  severity: RawFinding['severity'],
  title: string,
  description: string,
  path: string,
  type: RawFinding['remediation']['type'],
  steps: string[],
  line?: number,
): RawFinding {
  return {
    scanner: 'config',
    category: 'config',
    ruleId,
    title,
    description,
    severity,
    confidence: 'high',
    location: { path, ...(line ? { startLine: line, endLine: line } : {}) },
    evidence: { path, ruleId },
    cwe: ['CWE-250'],
    owasp: ['A05:2021'],
    references: [],
    remediation: { type, effort: 'S', summary: title, steps },
    context: {},
    fingerprintMaterial: `${ruleId}|${path}|${line ?? 0}`,
  };
}
