export const openApi = {
  openapi: '3.1.0',
  info: {
    title: 'RepoGuard API',
    version: '0.1.0',
    description: 'Submit a public GitHub repository and follow a prioritized security scan.',
  },
  paths: {
    '/api/v1/scans': {
      post: { summary: 'Start a scan', requestBody: { required: true }, responses: { '202': { description: 'Scan accepted' }, '200': { description: 'Existing in-flight scan' } } },
      get: { summary: 'List scans', responses: { '200': { description: 'Recent scans' } } },
    },
    '/api/v1/scans/{id}': { get: { summary: 'Scan snapshot', responses: { '200': { description: 'Progress snapshot' } } } },
    '/api/v1/scans/{id}/events': { get: { summary: 'Scan events', responses: { '200': { description: 'Server-sent events' } } } },
    '/api/v1/scans/{id}/result': { get: { summary: 'Scan report', responses: { '200': { description: 'Report' }, '409': { description: 'Not ready' } } } },
    '/api/v1/scans/{id}/findings': { get: { summary: 'Filtered findings', responses: { '200': { description: 'Findings page' } } } },
    '/api/v1/scans/{id}/cancel': { post: { summary: 'Cancel a scan', responses: { '202': { description: 'Cancel requested' } } } },
    '/api/v1/scanners': { get: { summary: 'Scanner catalog', responses: { '200': { description: 'Scanners and ecosystems' } } } },
    '/api/v1/privacy': { get: { summary: 'Privacy notes', responses: { '200': { description: 'What the scanner stores and sends' } } } },
    '/healthz': { get: { summary: 'Liveness', responses: { '200': { description: 'Process is up' } } } },
    '/readyz': { get: { summary: 'Readiness', responses: { '200': { description: 'Ready' } } } },
  },
} as const;

export const privacy = {
  fetches: 'The public GitHub tarball of the requested repository at the default branch, or the ref in the URL.',
  stores: 'Findings with redacted snippets, reports, and scan events. Raw secrets are never stored.',
  deletes: 'Extracted repository files are deleted when the scan finishes. DELETE /api/v1/scans/:id purges a scan on request.',
  retention: 'Noisy progress events are pruned after 7 days. Findings and reports are kept for 30 days.',
  thirdParties: 'OSV, deps.dev, EPSS, and CISA KEV receive package names, versions, and CVE ids. An LLM provider, when enabled, receives redacted findings and short snippets.',
  training: 'RepoGuard does not train on scan data. LLM calls use the provider account you configure.',
};
