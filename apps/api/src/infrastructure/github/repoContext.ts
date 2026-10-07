import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative, extname } from 'node:path';
import type { RepoRef } from '@repoguard/shared';

const SKIP_DIRECTORIES = new Set([
  'node_modules',
  'dist',
  'build',
  '.git',
  'vendor',
  'third_party',
  '__pycache__',
  '.next',
  'coverage',
  '.venv',
  'venv',
  'target',
  '.turbo',
]);

const BINARY_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.ico', '.pdf', '.zip', '.gz', '.tgz', '.bz2', '.7z',
  '.woff', '.woff2', '.ttf', '.eot', '.otf', '.mp4', '.mp3', '.wav', '.wasm', '.jar', '.class',
  '.exe', '.dll', '.so', '.dylib', '.bin', '.dmg', '.iso', '.sqlite', '.webp',
]);

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  '.ts': 'TypeScript',
  '.tsx': 'TypeScript',
  '.js': 'JavaScript',
  '.jsx': 'JavaScript',
  '.mjs': 'JavaScript',
  '.py': 'Python',
  '.go': 'Go',
  '.rs': 'Rust',
  '.rb': 'Ruby',
  '.php': 'PHP',
  '.cs': 'C#',
  '.java': 'Java',
};

export type SkipReason = 'binary' | 'too_large' | 'vendored' | 'generated' | 'minified';

export interface IndexedFile {
  path: string;
  size: number;
  skipReason?: SkipReason;
}

export interface RepoContext {
  rootDir: string;
  repo: RepoRef;
  files: IndexedFile[];
  languages: string[];
  frameworks: string[];
  readText(relativePath: string, maxBytes: number): string | null;
}

export function buildRepoContext(rootDir: string, repo: RepoRef, maxFileBytes: number): RepoContext {
  const files = walk(rootDir, rootDir, maxFileBytes);
  const languages = [...new Set(files.flatMap((file) => languageOf(file.path) ?? []))].sort();
  return {
    rootDir,
    repo,
    files,
    languages,
    frameworks: detectFrameworks(rootDir, files),
    readText(relativePath: string, maxBytes: number) {
      return readTextFile(join(rootDir, relativePath), maxBytes);
    },
  };
}

export function readTextFile(absolutePath: string, maxBytes: number): string | null {
  try {
    const info = statSync(absolutePath);
    if (!info.isFile() || info.size > maxBytes) return null;
    const buffer = readFileSync(absolutePath);
    if (buffer.subarray(0, 8000).includes(0)) return null;
    return buffer.toString('utf8');
  } catch {
    return null;
  }
}

function walk(root: string, directory: string, maxFileBytes: number): IndexedFile[] {
  const files: IndexedFile[] = [];
  let entries;
  try {
    entries = readdirSync(directory, { withFileTypes: true, encoding: 'utf8' });
  } catch {
    return files;
  }
  for (const entry of entries) {
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      if (SKIP_DIRECTORIES.has(entry.name)) continue;
      files.push(...walk(root, join(directory, entry.name), maxFileBytes));
      continue;
    }
    if (!entry.isFile()) continue;
    const absolute = join(directory, entry.name);
    let size = 0;
    try {
      size = statSync(absolute).size;
    } catch {
      continue;
    }
    const path = relative(root, absolute).split('\\').join('/');
    files.push({ path, size, ...skipOf(path, size, maxFileBytes) });
  }
  return files;
}

function skipOf(path: string, size: number, maxFileBytes: number): { skipReason?: SkipReason } {
  const extension = extname(path).toLowerCase();
  if (BINARY_EXTENSIONS.has(extension)) return { skipReason: 'binary' };
  if (path.endsWith('.min.js') || path.endsWith('.min.css')) return { skipReason: 'minified' };
  if (size > maxFileBytes) return { skipReason: 'too_large' };
  return {};
}

function languageOf(path: string): string | undefined {
  return LANGUAGE_BY_EXTENSION[extname(path).toLowerCase()];
}

function detectFrameworks(root: string, files: IndexedFile[]): string[] {
  const found = new Set<string>();
  const packageJson = files.find((file) => file.path === 'package.json');
  if (packageJson) noteDependencies(readTextFile(join(root, packageJson.path), 1_000_000) ?? '', NPM_FRAMEWORKS, found);
  const requirements = files.find((file) => /(^|\/)requirements.*\.txt$/.test(file.path) || file.path === 'pyproject.toml');
  if (requirements) noteDependencies(readTextFile(join(root, requirements.path), 1_000_000) ?? '', PY_FRAMEWORKS, found);
  const goMod = files.find((file) => file.path === 'go.mod');
  if (goMod) noteDependencies(readTextFile(join(root, goMod.path), 1_000_000) ?? '', GO_FRAMEWORKS, found);
  return [...found];
}

function noteDependencies(content: string, table: Record<string, string>, found: Set<string>): void {
  for (const [name, label] of Object.entries(table)) {
    if (content.includes(name)) found.add(label);
  }
}

const NPM_FRAMEWORKS: Record<string, string> = {
  '"react"': 'React',
  '"next"': 'Next.js',
  '"vue"': 'Vue',
  '"express"': 'Express',
  '"fastify"': 'Fastify',
};

const PY_FRAMEWORKS: Record<string, string> = {
  django: 'Django',
  flask: 'Flask',
  fastapi: 'FastAPI',
};

const GO_FRAMEWORKS: Record<string, string> = {
  'github.com/gin-gonic/gin': 'Gin',
  'github.com/labstack/echo': 'Echo',
};
