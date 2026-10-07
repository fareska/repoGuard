import { afterAll, describe, expect, it } from 'vitest';
import { loadConfig } from '../config/env.js';
import { createApplication } from '../main.js';

describe('mock scan API', () => {
  const appPromise = createApplication(loadConfig({
    DATABASE_URL: ':memory:',
    SCAN_MODE: 'mock',
    ALLOW_MOCK_MODE: 'true',
    MOCK_DELAY_MS: '0',
    LOG_LEVEL: 'silent',
    DEDUPE_INFLIGHT: 'false',
  }));

  afterAll(async () => {
    const application = await appPromise;
    await application.shutdown();
  });

  it('runs a mock scan from submit to report', async () => {
    const application = await appPromise;
    const created = await application.app.inject({
      method: 'POST',
      url: '/api/v1/scans',
      payload: { repoUrl: 'https://github.com/acme/shop', mode: 'mock' },
    });
    expect(created.statusCode).toBe(202);
    const id = created.json().id as string;
    let status = 'queued';
    for (let attempt = 0; attempt < 50 && status !== 'completed' && status !== 'failed'; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 30));
      const snapshot = await application.app.inject({ method: 'GET', url: `/api/v1/scans/${id}` });
      status = snapshot.json().status as string;
    }
    expect(status).toBe('completed');
    const result = await application.app.inject({ method: 'GET', url: `/api/v1/scans/${id}/result` });
    expect(result.statusCode).toBe(200);
    expect(result.json().summary.riskLevel).toBe('critical');
    expect(result.json().findings.length).toBeGreaterThan(0);
    const rejected = await application.app.inject({ method: 'POST', url: '/api/v1/scans', payload: { repoUrl: 'https://example.com/acme/shop' } });
    expect(rejected.statusCode).toBe(400);
  });
});
