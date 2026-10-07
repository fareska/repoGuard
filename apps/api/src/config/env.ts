import { z } from 'zod';

const MB = 1024 * 1024;
const MINUTE = 60_000;

const optionalText = z
  .string()
  .optional()
  .transform((value) => {
    const trimmed = value?.trim();
    return trimmed ? trimmed : undefined;
  });

const flag = (fallback: boolean) =>
  z
    .string()
    .optional()
    .transform((value) => {
      if (value === undefined || value.trim() === '') return fallback;
      return value === 'true';
    });

const schema = z.object({
  PORT: z.coerce.number().int().positive().default(8787),
  HOST: z.string().default('0.0.0.0'),
  DATABASE_URL: z.string().default('./data/repoguard.sqlite'),
  SCAN_MODE: z.enum(['real', 'mock', 'hybrid']).default('real'),
  ALLOW_MOCK_MODE: flag(true),
  GITHUB_TOKEN: optionalText,
  OSV_BASE_URL: z.string().default('https://api.osv.dev'),
  DEPS_DEV_BASE_URL: z.string().default('https://api.deps.dev'),
  EPSS_URL: z.string().default('https://api.first.org/data/v1/epss'),
  KEV_URL: z
    .string()
    .default('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
  ENRICHMENT_CACHE_TTL_OSV_MS: z.coerce.number().int().positive().default(6 * 60 * MINUTE),
  ENRICHMENT_CACHE_TTL_DEPS_MS: z.coerce.number().int().positive().default(24 * 60 * MINUTE),
  ENRICHMENT_CACHE_TTL_EXPLOIT_MS: z.coerce.number().int().positive().default(24 * 60 * MINUTE),
  TRIAGE_PROVIDER: z.enum(['rules', 'llm']).default('rules'),
  LLM_API_KEY: optionalText,
  LLM_BASE_URL: z.string().default('https://api.openai.com/v1'),
  LLM_MODEL: z.string().default('gpt-4o-mini'),
  LLM_MAX_TOKENS: z.coerce.number().int().positive().default(1800),
  MAX_CONCURRENT_SCANS: z.coerce.number().int().positive().default(2),
  MAX_QUEUE_LENGTH: z.coerce.number().int().positive().default(20),
  SCANNER_CONCURRENCY: z.coerce.number().int().positive().default(3),
  SCAN_TIMEOUT_MS: z.coerce.number().int().positive().default(10 * MINUTE),
  STAGE_TIMEOUT_FETCH_MS: z.coerce.number().int().positive().default(120_000),
  STAGE_TIMEOUT_SCANNER_MS: z.coerce.number().int().positive().default(240_000),
  STAGE_TIMEOUT_TRIAGE_MS: z.coerce.number().int().positive().default(60_000),
  STALE_AFTER_MS: z.coerce.number().int().positive().default(90_000),
  WATCHDOG_INTERVAL_MS: z.coerce.number().int().positive().default(30_000),
  SHUTDOWN_GRACE_MS: z.coerce.number().int().positive().default(30_000),
  MAX_FILES: z.coerce.number().int().positive().default(20_000),
  MAX_EXTRACTED_BYTES: z.coerce.number().int().positive().default(200 * MB),
  MAX_FILE_BYTES: z.coerce.number().int().positive().default(MB),
  MAX_MANIFEST_BYTES: z.coerce.number().int().positive().default(20 * MB),
  LARGE_FILE_BYTES: z.coerce.number().int().positive().default(5 * MB),
  RETENTION_EVENT_DAYS: z.coerce.number().int().positive().default(7),
  RETENTION_REPORT_DAYS: z.coerce.number().int().positive().default(30),
  RATE_LIMIT_SCAN_MAX: z.coerce.number().int().positive().default(10),
  RATE_LIMIT_SCAN_WINDOW_MS: z.coerce.number().int().positive().default(10 * MINUTE),
  RATE_LIMIT_READ_MAX: z.coerce.number().int().positive().default(300),
  RATE_LIMIT_READ_WINDOW_MS: z.coerce.number().int().positive().default(MINUTE),
  SSE_MAX_PER_SCAN: z.coerce.number().int().positive().default(20),
  SSE_MAX_PER_IP: z.coerce.number().int().positive().default(10),
  SSE_KEEPALIVE_MS: z.coerce.number().int().positive().default(15_000),
  PROGRESS_FLUSH_MS: z.coerce.number().int().nonnegative().default(500),
  DEDUPE_INFLIGHT: flag(true),
  CORS_ORIGINS: z.string().default('http://localhost:5173'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  LOG_PRETTY: flag(false),
  SCAN_LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  METRICS_TOKEN: optionalText,
  MOCK_DELAY_MS: z.coerce.number().int().nonnegative().default(350),
  WEB_DIST: optionalText,
  BODY_LIMIT_BYTES: z.coerce.number().int().positive().default(16 * 1024),
  UPSTREAM_TIMEOUT_MS: z.coerce.number().int().positive().default(30_000),
  UPSTREAM_RETRIES: z.coerce.number().int().positive().default(3),
  CIRCUIT_FAILURES: z.coerce.number().int().positive().default(5),
  CIRCUIT_OPEN_MS: z.coerce.number().int().positive().default(60_000),
  IDEMPOTENCY_TTL_MS: z.coerce.number().int().positive().default(24 * 60 * MINUTE),
  OSV_BATCH_SIZE: z.coerce.number().int().positive().max(1000).default(1000),
});

export type Config = z.infer<typeof schema> & { corsOrigins: string[] };

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const message = parsed.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join('\n');
    throw new Error(`Invalid configuration\n${message}`);
  }
  if (parsed.data.TRIAGE_PROVIDER === 'llm' && !parsed.data.LLM_API_KEY) {
    throw new Error('Invalid configuration\nLLM_API_KEY: required when TRIAGE_PROVIDER=llm');
  }
  return {
    ...parsed.data,
    corsOrigins: parsed.data.CORS_ORIGINS.split(',').map((origin) => origin.trim()).filter(Boolean),
  };
}
