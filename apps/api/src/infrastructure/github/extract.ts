import { once } from 'node:events';
import { createWriteStream } from 'node:fs';
import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { finished } from 'node:stream/promises';
import tar from 'tar';
import type { RepoRef } from '@repoguard/shared';
import type { Config } from '../../config/env.js';
import { ScanFailure } from '../../domain/failures.js';
import { buildRepoContext, type RepoContext } from './repoContext.js';
import { GitHubClient, type GitHubMetadata } from './client.js';

export function assertSafeTarPath(entryPath: string, type: string): void {
  const normalized = entryPath.replaceAll('\\', '/');
  if (normalized.startsWith('/') || /^[A-Za-z]:/.test(normalized)) {
    throw new ScanFailure('REPO_TOO_LARGE', 'Archive entry uses an absolute path');
  }
  if (normalized.split('/').includes('..')) {
    throw new ScanFailure('REPO_TOO_LARGE', 'Archive entry escapes the extract directory');
  }
  const allowed = new Set(['File', 'Directory', 'ContinuousFile']);
  if (type && !allowed.has(type)) {
    throw new ScanFailure('REPO_TOO_LARGE', `Archive entry type ${type} is not allowed`);
  }
}

export async function fetchRepository(
  client: GitHubClient,
  repo: RepoRef,
  config: Config,
  signal: AbortSignal,
  onProgress: (fraction: number, message: string) => void,
): Promise<{ context: RepoContext; cleanup: () => Promise<void> }> {
  const root = join(config.WEB_DIST ? tmpdir() : tmpdir(), 'repoguard');
  await mkdir(root, { recursive: true, mode: 0o700 });
  const workspace = await mkdtemp(join(root, 'scan-'));
  const cleanup = async () => {
    await rm(workspace, { recursive: true, force: true });
  };
  try {
    onProgress(0.1, 'Resolving repository metadata');
    const metadata = await client.metadata(repo.owner, repo.name, signal);
    assertSizeHint(metadata, config.MAX_EXTRACTED_BYTES);
    const ref = repo.ref || metadata.defaultBranch;
    onProgress(0.25, 'Resolving commit');
    const commitSha = await client.commitSha(repo.owner, repo.name, ref, signal);
    const archivePath = join(workspace, 'repo.tar.gz');
    onProgress(0.4, 'Downloading tarball');
    await client.downloadTarball(repo.owner, repo.name, ref, archivePath, config.MAX_EXTRACTED_BYTES, signal);
    onProgress(0.7, 'Extracting files');
    const sourceDir = join(workspace, 'src');
    await mkdir(sourceDir, { recursive: true, mode: 0o700 });
    await extractArchive(archivePath, sourceDir, config.MAX_FILES, config.MAX_EXTRACTED_BYTES);
    const resolved: RepoRef = {
      ...repo,
      ref,
      defaultBranch: metadata.defaultBranch,
      commitSha,
    };
    const context = buildRepoContext(sourceDir, resolved, config.MAX_FILE_BYTES);
    const readable = context.files.filter((file) => !file.skipReason);
    if (context.files.length === 0) throw new ScanFailure('REPO_EMPTY', 'The repository has no files');
    onProgress(0.95, `Indexed ${context.files.length.toLocaleString()} files`);
    return {
      context,
      cleanup,
      ...(readable.length === 0 ? {} : {}),
    };
  } catch (error) {
    await cleanup();
    throw error;
  }
}

function assertSizeHint(metadata: GitHubMetadata, maxBytes: number): void {
  const hinted = metadata.sizeKb * 1024;
  if (metadata.sizeKb > 0 && hinted > maxBytes * 8) {
    throw new ScanFailure('REPO_TOO_LARGE', 'GitHub reports this repository is larger than the scan limit');
  }
}

async function extractArchive(archivePath: string, dest: string, maxFiles: number, maxBytes: number): Promise<void> {
  let files = 0;
  let bytes = 0;
  const inspect = (entryPath: string, type: string, size: number) => {
    assertSafeTarPath(entryPath, type);
    if (type === 'Directory') return;
    files += 1;
    bytes += size;
    if (files > maxFiles || bytes > maxBytes) {
      throw new ScanFailure('REPO_TOO_LARGE', 'Extracted repository exceeds the file or size limit');
    }
  };
  await tar.t({
    file: archivePath,
    onentry(entry) {
      inspect(entry.path, entry.type, entry.size);
    },
  });
  files = 0;
  bytes = 0;
  await tar.x({
    file: archivePath,
    cwd: dest,
    strip: 1,
    strict: true,
    filter(entryPath, entry) {
      inspect(entryPath, entry.type, entry.size);
      return true;
    },
  });
}

export async function downloadToFile(
  response: Response,
  dest: string,
  maxBytes: number,
  signal: AbortSignal,
): Promise<void> {
  const declared = Number(response.headers.get('content-length') ?? 0);
  if (declared > maxBytes) throw new ScanFailure('REPO_TOO_LARGE', 'Tarball is larger than the scan limit');
  if (!response.body) throw new ScanFailure('REPO_EMPTY', 'GitHub returned an empty archive');
  const file = createWriteStream(dest, { mode: 0o600 });
  let received = 0;
  try {
    const reader = response.body.getReader();
    while (true) {
      if (signal.aborted) throw abortError();
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > maxBytes) {
        await reader.cancel();
        throw new ScanFailure('REPO_TOO_LARGE', 'Tarball is larger than the scan limit');
      }
      if (!file.write(Buffer.from(value))) await once(file, 'drain');
    }
  } catch (error) {
    file.destroy();
    throw error;
  }
  file.end();
  await finished(file);
}

function abortError(): Error {
  const error = new Error('Aborted');
  error.name = 'AbortError';
  return error;
}
