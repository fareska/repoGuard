import type { Config } from '../../config/env.js';
import { ScanFailure } from '../../domain/failures.js';
import { downloadToFile } from './extract.js';
import { CircuitBreaker, fetchUpstream, UpstreamError } from '../enrichment/http.js';

export interface GitHubMetadata {
  defaultBranch: string;
  sizeKb: number;
  private: boolean;
}

export class GitHubClient {
  constructor(
    private readonly config: Config,
    private readonly breaker: CircuitBreaker,
  ) {}

  async metadata(owner: string, name: string, signal: AbortSignal): Promise<GitHubMetadata> {
    const response = await this.request(`https://api.github.com/repos/${owner}/${name}`, signal);
    if (response.status === 404) throw new ScanFailure('REPO_NOT_FOUND', 'GitHub could not find that repository');
    if (response.status === 401 || response.status === 403) throw mapDenied(response);
    if (!response.ok) throw new ScanFailure('UPSTREAM_UNAVAILABLE', 'GitHub repository lookup failed');
    const body = (await response.json()) as { default_branch?: string; size?: number; private?: boolean };
    if (body.private) throw new ScanFailure('REPO_PRIVATE_OR_FORBIDDEN', 'RepoGuard only scans public repositories');
    return { defaultBranch: body.default_branch || 'main', sizeKb: body.size ?? 0, private: false };
  }

  async commitSha(owner: string, name: string, ref: string, signal: AbortSignal): Promise<string> {
    const response = await this.request(
      `https://api.github.com/repos/${owner}/${name}/commits/${encodeURIComponent(ref)}`,
      signal,
    );
    if (response.status === 404) throw new ScanFailure('REPO_NOT_FOUND', 'GitHub could not find that branch or commit');
    if (response.status === 401 || response.status === 403) throw mapDenied(response);
    if (!response.ok) throw new ScanFailure('UPSTREAM_UNAVAILABLE', 'GitHub commit lookup failed');
    const body = (await response.json()) as { sha?: string };
    if (!body.sha) throw new ScanFailure('UPSTREAM_UNAVAILABLE', 'GitHub did not return a commit SHA');
    return body.sha;
  }

  async archived(projectId: string, signal: AbortSignal): Promise<boolean | null> {
    if (!projectId.startsWith('github.com/')) return null;
    const [owner, name] = projectId.slice('github.com/'.length).split('/');
    if (!owner || !name) return null;
    try {
      const response = await this.request(`https://api.github.com/repos/${owner}/${name}`, signal);
      if (!response.ok) return null;
      const body = (await response.json()) as { archived?: boolean };
      return body.archived === true;
    } catch {
      return null;
    }
  }

  async downloadTarball(
    owner: string,
    name: string,
    ref: string,
    dest: string,
    maxBytes: number,
    signal: AbortSignal,
  ): Promise<void> {
    const response = await this.request(
      `https://api.github.com/repos/${owner}/${name}/tarball/${encodeURIComponent(ref)}`,
      signal,
    );
    if (response.status === 404) throw new ScanFailure('REPO_NOT_FOUND', 'GitHub could not download that repository');
    if (response.status === 401 || response.status === 403) throw mapDenied(response);
    if (!response.ok) throw new ScanFailure('UPSTREAM_UNAVAILABLE', 'GitHub tarball download failed');
    await downloadToFile(response, dest, maxBytes, signal);
  }

  private request(url: string, signal: AbortSignal) {
    return fetchUpstream(url, {
      breaker: this.breaker,
      signal,
      retries: this.config.UPSTREAM_RETRIES,
      timeoutMs: this.config.UPSTREAM_TIMEOUT_MS,
      headers: githubHeaders(this.config.GITHUB_TOKEN),
    });
  }
}

function githubHeaders(token?: string): Record<string, string> {
  return {
    accept: 'application/vnd.github+json',
    'user-agent': 'RepoGuard',
    'x-github-api-version': '2022-11-28',
    ...(token ? { authorization: `Bearer ${token}` } : {}),
  };
}

function mapDenied(response: Response): ScanFailure {
  const remaining = response.headers.get('x-ratelimit-remaining');
  if (response.status === 403 && remaining === '0') {
    return new ScanFailure('RATE_LIMITED_UPSTREAM', 'GitHub rate limit reached. Set GITHUB_TOKEN for a higher limit.');
  }
  return new ScanFailure('REPO_PRIVATE_OR_FORBIDDEN', 'GitHub refused access. RepoGuard only scans public repositories.');
}

export function mapUpstream(error: unknown): ScanFailure | null {
  if (error instanceof ScanFailure) return error;
  if (error instanceof UpstreamError) return new ScanFailure(error.code, error.message);
  return null;
}
