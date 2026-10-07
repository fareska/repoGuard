export const ERROR_CODES = [
  'INVALID_REPO_URL',
  'REPO_NOT_FOUND',
  'REPO_PRIVATE_OR_FORBIDDEN',
  'REPO_TOO_LARGE',
  'REPO_EMPTY',
  'RATE_LIMITED_UPSTREAM',
  'UPSTREAM_UNAVAILABLE',
  'TIMEOUT',
  'INTERRUPTED',
  'QUEUE_FULL',
  'INTERNAL',
  'NOT_FOUND',
  'NOT_READY',
  'ILLEGAL_TRANSITION',
  'MOCK_MODE_DISABLED',
  'UNKNOWN_SCANNER',
] as const;

export type ErrorCode = (typeof ERROR_CODES)[number];

export const ERROR_TITLES: Record<ErrorCode, string> = {
  INVALID_REPO_URL: 'Invalid repository URL',
  REPO_NOT_FOUND: 'Repository not found',
  REPO_PRIVATE_OR_FORBIDDEN: 'Repository is private or forbidden',
  REPO_TOO_LARGE: 'Repository is too large',
  REPO_EMPTY: 'Repository is empty',
  RATE_LIMITED_UPSTREAM: 'Upstream rate limit reached',
  UPSTREAM_UNAVAILABLE: 'Upstream service unavailable',
  TIMEOUT: 'Scan timed out',
  INTERRUPTED: 'Scan was interrupted',
  QUEUE_FULL: 'Scan queue is full',
  INTERNAL: 'Internal error',
  NOT_FOUND: 'Not found',
  NOT_READY: 'Result not ready',
  ILLEGAL_TRANSITION: 'Illegal scan transition',
  MOCK_MODE_DISABLED: 'Mock mode is disabled',
  UNKNOWN_SCANNER: 'Unknown scanner',
};

export const ERROR_DETAILS: Record<ErrorCode, string> = {
  INVALID_REPO_URL: 'Use a public GitHub URL such as https://github.com/owner/name.',
  REPO_NOT_FOUND: 'GitHub could not find that repository.',
  REPO_PRIVATE_OR_FORBIDDEN: 'RepoGuard only scans public repositories.',
  REPO_TOO_LARGE: 'The repository exceeds the size limit, so the scan stopped before analysis.',
  REPO_EMPTY: 'The default branch has no files to scan.',
  RATE_LIMITED_UPSTREAM: 'GitHub or an enrichment API rate-limited the scan after retries.',
  UPSTREAM_UNAVAILABLE: 'An upstream service is unavailable. Try the scan again shortly.',
  TIMEOUT: 'The scan exceeded its time limit.',
  INTERRUPTED: 'The scanner process restarted before this scan finished.',
  QUEUE_FULL: 'Too many scans are waiting. Try again in a moment.',
  INTERNAL: 'The scan failed for an unexpected reason.',
  NOT_FOUND: 'That scan does not exist.',
  NOT_READY: 'The report is not ready yet.',
  ILLEGAL_TRANSITION: 'The scan is already finished.',
  MOCK_MODE_DISABLED: 'Mock mode is turned off on this server.',
  UNKNOWN_SCANNER: 'One or more requested scanners are not available.',
};

export interface Problem {
  type: 'about:blank';
  title: string;
  status: number;
  detail: string;
  code: ErrorCode;
  scanId?: string;
}

export function problem(code: ErrorCode, status: number, detail?: string, scanId?: string): Problem {
  return {
    type: 'about:blank',
    title: ERROR_TITLES[code],
    status,
    detail: detail ?? ERROR_DETAILS[code],
    code,
    ...(scanId ? { scanId } : {}),
  };
}
