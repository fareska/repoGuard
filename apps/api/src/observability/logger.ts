import { pino, type Logger } from 'pino';
import type { Config } from '../config/env.js';
import { redactSecrets } from '../infrastructure/scanners/secrets.js';

export function createLogger(config: Config): Logger {
  return pino({
    level: config.LOG_LEVEL,
    redact: {
      paths: ['req.headers.authorization', 'githubToken', 'llmApiKey', 'GITHUB_TOKEN', 'LLM_API_KEY'],
      censor: '[redacted]',
    },
    ...(config.LOG_PRETTY
      ? { transport: { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss' } } }
      : {}),
    hooks: {
      logMethod(args, method) {
        const redacted = args.map((arg) => (typeof arg === 'string' ? redactSecrets(arg) : arg));
        method.apply(this, redacted as Parameters<typeof method>);
      },
    },
  });
}

export type AppLogger = Logger;
