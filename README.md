# RepoGuard

RepoGuard scans a **public** GitHub repository and returns a prioritized report: what matters, why, and what to do next. It is for someone reviewing a repo before they trust it, not for private-org monitoring, pull-request bots, or language-specific code analysis.

It does not sign you in, scan private repos, run the repo's code, or open fix pull requests.

## Quick start

Mock mode needs no tokens.

```bash
pnpm install
pnpm dev
```

Open http://localhost:5173 and choose **Mock**. The API listens on http://localhost:8787.

```bash
docker compose up --build
```

That serves the built UI and API together on http://localhost:8787, in mock mode.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SCAN_MODE` | `real` | `real`, `mock`, or `hybrid` |
| `ALLOW_MOCK_MODE` | `true` | Shows the Real / Mock toggle |
| `GITHUB_TOKEN` | empty | Raises the GitHub rate limit for real scans |
| `DATABASE_URL` | `./data/repoguard.sqlite` | SQLite file |
| `TRIAGE_PROVIDER` | `rules` | `llm` needs `LLM_API_KEY` |
| `PORT` | `8787` | API port |

See `.env.example` for the rest.

## Walkthrough

1. **Submit.** Paste `https://github.com/owner/name`. Real mode runs the scanners you leave checked. Mock mode replays a stable demo for that URL.
2. **Progress.** A stepper, a percentage, live finding counts, and a log. Cancel stops a running scan. The page follows server-sent events and falls back to polling.
3. **Result.** A headline and risk level, the top risks, ordered next actions, then every finding with a detail drawer. Export JSON hits the same report the API returns.

A clean report still says what was not scanned. "No issues" is not the same as "we did not look."

## Architecture

```text
Browser  -- REST + SSE -->  Fastify
                              |-- ScanService
                              |-- SQLite snapshots + append-only events
                              |-- in-process queue
                              '-- worker: fetch tarball, scanners, triage, report
```

One process hosts the API and the worker. Progress is a list of events (`scan.queued`, `stage.progress`, `scan.completed`, …) plus a snapshot row updated in the same write. The UI reduces those events with the same function the server uses.

Real scans download the GitHub tarball, reject path traversal and links, and delete the files when the scan ends. Scanners only parse text. They do not install dependencies or execute the repo.

## Decisions

- **Tarball, not git clone.** No git binary, no history, and a size check before analysis. History scanning would be a second fetcher behind the same interface.
- **Events plus a snapshot.** Clients can reconnect with `Last-Event-ID` (browsers pass `afterSeq`) without replaying business logic two different ways.
- **SSE, then polling.** The stream is primary. Two stream errors and the page polls `GET /scans/:id`.
- **SQLite and an in-process queue.** One container, no Redis. The repository and queue are swappable later.
- **Rules first, LLM behind a flag.** The default triage is deterministic. `TRIAGE_PROVIDER=llm` may rephrase and regroup; unknown finding ids are dropped, and a bad model response falls back to the rules.
- **Static analysis only.** Repository content is hostile. Nothing in the tree is executed.
- **Own parsers.** Lockfiles yield exact versions. Manifest ranges are evaluated at the lower bound and marked medium confidence, with a "commit a lockfile" action. Maven and Gradle are detected and reported as not analyzed.
- **Exploit signals, not CVSS alone.** CISA KEV and EPSS move severity, and the report says why.

## What a scan covers

| Scanner | Looks for |
| --- | --- |
| Dependency vulnerabilities | OSV advisories for npm, PyPI, Go, crates.io, RubyGems, Packagist, NuGet, and committed SBOMs |
| Dependency health | Deprecated, yanked, malicious, unmaintained, or archived upstream packages |
| Dependency hygiene | Missing or drifted lockfiles, remote install scripts, unsupported ecosystems |
| Leaked secrets | AWS, GitHub, Slack, Stripe, Google, private keys, high-entropy assignments. Values are masked. |
| Configuration and CI | Dockerfile, Compose, GitHub Actions, committed `.env`, registry auth files |
| Repository hygiene | `SECURITY.md`, license, Dependabot or Renovate, large files |

Not in this version: private repos, SAST, Terraform, git history, and auto-fix pull requests.

## Security and privacy

What we fetch: the public tarball at the default branch, or the ref in a `/tree/<ref>` URL. What we store: findings, redacted snippets, reports, events. What we delete: the extracted tree at the end of every scan. Findings and reports are kept 30 days. Progress noise is pruned after 7 days.

`DELETE /api/v1/scans/:id` purges one scan. `GET /api/v1/privacy` returns the same notes. OSV and deps.dev see package names and versions. EPSS and CISA see CVE ids. The LLM, if you enable it, sees redacted findings and short snippets, not the repository.

Submitted URLs must be `https://github.com/<owner>/<repo>`. The fetcher builds GitHub API URLs itself.

## Assumptions you can change

Public repos only, tarball fetch, language-agnostic checks, one branch per scan, rule-based triage by default, one process, no API auth, and severity from explicit rules. Each of those sits behind a function you can replace: fetcher, scanner, triage provider, repository, queue.

## Extending

- **Scanner.** Add a class in `apps/api/src/infrastructure/scanners`, register it in `registry.ts`. See `scanners/README.md`.
- **Parser.** Implement `matches` and `parse`, add it in `manifests/registry.ts`. Lockfile parsers should set `precision: 'lockfile'`.
- **Triage.** Implement `triage(input)` and select it with `TRIAGE_PROVIDER`.
- **Persistence.** `SqliteScanRepository` is the only storage adapter. A Postgres version would keep the same methods.

## API

Interactive docs: http://localhost:8787/api/docs. Spec: `/api/v1/openapi.json`.

Errors use `application/problem+json` with a `code` such as `INVALID_REPO_URL`, `REPO_TOO_LARGE`, `QUEUE_FULL`, `TIMEOUT`, or `INTERRUPTED`. `GET /scans/:id/result` returns 409 until the scan finishes, and a partial report if a failed scan already saved findings.

## Roadmap

Language-specific rules, Maven and Gradle resolution, infrastructure-as-code, secrets in git history, and authenticated org scans are intentionally out of this version. The finding record already has a place for them (`category: 'code'`, parser precision, scanner plugins).

## Known limits

Mock mode does not contact GitHub. Real mode needs a network and, for busy demos, a `GITHUB_TOKEN`. Manifest-only repos are less precise than lockfiles. Transitive parent links exist when the lockfile records them. The queue is in-memory: a restart fails scans that were already running and requeues ones that were still waiting.
