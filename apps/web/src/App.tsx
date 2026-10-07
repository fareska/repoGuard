import { useEffect, useState, type FormEvent, type ReactNode } from 'react';
import { parseRepoUrl, type Finding, type Report, type ScanSnapshot, type ScanStatus, type ScanSummary, type ScannersResponse, type Severity, type Stage } from '@repoguard/shared';
import { api, useRoute, useScan, type LogLine } from './api';

export function App() {
  const { path, navigate } = useRoute();
  const result = /^\/scans\/([^/]+)\/result$/.exec(path);
  const progress = /^\/scans\/([^/]+)$/.exec(path);
  if (result?.[1]) return <ResultScreen id={result[1]} navigate={navigate} path={path} />;
  if (progress?.[1]) return <ProgressScreen id={progress[1]} navigate={navigate} path={path} />;
  return <SubmitScreen navigate={navigate} path={path} />;
}

function SubmitScreen({ navigate, path }: { navigate: (path: string) => void; path: string }) {
  const [catalog, setCatalog] = useState<ScannersResponse | null>(null);
  const [recent, setRecent] = useState<ScanSummary[]>([]);
  const [url, setUrl] = useState(() => new URLSearchParams(window.location.search).get('retry') ?? '');
  const [mode, setMode] = useState<'real' | 'mock'>('real');
  const [selected, setSelected] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const parsed = parseRepoUrl(url);

  useEffect(() => {
    void api.scanners().then((next) => {
      setCatalog(next);
      setMode(next.defaultMode === 'mock' ? 'mock' : 'real');
      setSelected(next.scanners.filter((scanner) => scanner.id !== 'mock').map((scanner) => scanner.id));
    }).catch((err: unknown) => setError(err instanceof Error ? err.message : 'Could not load scanners'));
    void api.scans().then(setRecent).catch(() => setRecent([]));
  }, []);

  const realScanners = catalog?.scanners.filter((scanner) => scanner.id !== 'mock') ?? [];

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!parsed) {
      setError('Use a public GitHub URL such as https://github.com/owner/name.');
      return;
    }
    setPending(true);
    setError(null);
    try {
      const created = await api.create({
        repoUrl: parsed.url,
        ...(catalog?.allowMockMode ? { mode } : {}),
        ...(mode === 'real' ? { scanners: selected } : {}),
      });
      navigate(`/scans/${created.body.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start the scan');
      setPending(false);
    }
  }

  return (
    <Shell path={path} navigate={navigate}>
      <section className="hero">
        <h1>GitHub repository scanner</h1>
        <p className="lede">Paste a public repository URL. RepoGuard ranks the risks and tells you what to fix first.</p>
        <form onSubmit={(event) => void submit(event)}>
          <label className="sr-only" htmlFor="repo-url">Repository URL</label>
          <div className="search">
            <GitHubMark />
            <input id="repo-url" value={url} placeholder="Enter GitHub repository URL (e.g. https://github.com/facebook/react)" onChange={(event) => setUrl(event.target.value)} autoComplete="off" spellCheck={false} />
            <button type="submit" disabled={pending || !parsed}>{pending ? 'Starting' : 'Scan'}</button>
          </div>
        </form>
        <button type="button" className="example" onClick={() => setUrl('https://github.com/facebook/react')}>Example: https://github.com/facebook/react</button>
        <p className={parsed || url.trim() === '' ? 'hint' : 'hint bad'}>{parsed ? `${parsed.owner}/${parsed.name}${parsed.ref ? ` @ ${parsed.ref}` : ''}` : url.trim() ? 'That is not a public github.com repository URL.' : 'Public repositories only. No tokens, no private repos.'}</p>
        {error && <p className="banner" role="alert">{error}</p>}
      </section>
      <section className="features" aria-label="What a scan covers">
        <Feature tone="blue" title="Dependencies" text="Known vulnerabilities, abandoned packages, and missing lockfiles." icon={<BoxIcon />} />
        <Feature tone="green" title="Secrets" text="Credentials in the tree, shown masked, with a rotate action." icon={<SearchIcon />} />
        <Feature tone="violet" title="Configuration" text="Dockerfile, Compose, and GitHub Actions settings that widen access." icon={<BulbIcon />} />
        <Feature tone="amber" title="Next actions" text="A short list of what to change, ordered by severity and effort." icon={<BoltIcon />} />
      </section>
      <div className="workspace">
        <aside className="panel side">
          <p className="side-link">Scan repository</p>
          {catalog?.allowMockMode && (
            <>
              <h2>Mode</h2>
              <div className="segmented" role="group" aria-label="Scan mode">
                <button type="button" aria-pressed={mode === 'real'} onClick={() => setMode('real')}>Real</button>
                <button type="button" aria-pressed={mode === 'mock'} onClick={() => setMode('mock')}>Mock</button>
              </div>
            </>
          )}
          {mode === 'real' && (
            <>
              <h2>Scanners</h2>
              <ul className="checks">
                {realScanners.map((scanner) => {
                  const on = selected.includes(scanner.id);
                  return (
                    <li key={scanner.id}>
                      <label>
                        <input type="checkbox" checked={on} onChange={() => setSelected((current) => on ? current.filter((id) => id !== scanner.id) : [...current, scanner.id])} />
                        {scanner.displayName}
                      </label>
                    </li>
                  );
                })}
              </ul>
            </>
          )}
          {mode === 'mock' && <p className="hint">Mock mode replays a stable demo and does not call GitHub.</p>}
        </aside>
        <section className="panel" id="scans">
          <div className="panel-head">
            <h2>Recent scans</h2>
            <span>{recent.length === 0 ? '' : `${recent.length}`}</span>
          </div>
          {recent.length === 0 ? <p className="empty">No scans yet.</p> : (
            <ul className="scan-list">
              {recent.map((scan) => (
                <li key={scan.id}>
                  <button type="button" className="scan-row" onClick={() => navigate(scan.status === 'completed' ? `/scans/${scan.id}/result` : `/scans/${scan.id}`)}>
                    <span className="avatar" aria-hidden="true">{scan.repo.owner.slice(0, 1).toUpperCase()}</span>
                    <span className="scan-copy">
                      <strong>{scan.repo.owner}/{scan.repo.name}</strong>
                      <span>{scan.findings} {scan.findings === 1 ? 'finding' : 'findings'} · {scan.mode}</span>
                    </span>
                    <StatusBadge status={scan.status} />
                    <span className="when">{timeAgo(scan.finishedAt ?? scan.createdAt)}</span>
                    <span className="chevron" aria-hidden="true">›</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </Shell>
  );
}

function progressAnnouncement(snapshot: ScanSnapshot | null, current: Stage | undefined): string {
  if (!snapshot) return 'Loading scan';
  if (snapshot.status === 'completed') return `Scan complete. ${snapshot.progress.percent} percent.`;
  if (snapshot.status === 'failed' || snapshot.status === 'cancelled') return `Scan ${snapshot.status}.`;
  if (current) return `${current.label} ${current.status}. ${snapshot.progress.percent} percent.`;
  return `${snapshot.status}. ${snapshot.progress.percent} percent.`;
}

function ProgressScreen({ id, navigate, path }: { id: string; navigate: (path: string) => void; path: string }) {
  const { snapshot, logs, transport, error } = useScan(id);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const current = snapshot?.progress.stages.find((stage) => stage.id === snapshot.progress.currentStage);
  const announcement = progressAnnouncement(snapshot, current);

  return (
    <Shell path={path} navigate={navigate}>
      <p className="sr-only" aria-live="polite">{announcement}</p>
      <header className="page-head">
        <div>
          <p className="eyebrow">{snapshot ? `${snapshot.mode} · ${transport}` : 'Scan'}</p>
          <h1>{snapshot ? `${snapshot.repo.owner}/${snapshot.repo.name}` : 'Loading scan'}</h1>
        </div>
        <div className="page-actions">
          {snapshot && <StatusBadge status={snapshot.status} />}
          {snapshot && !['completed', 'failed', 'cancelled'].includes(snapshot.status) && (
            <button type="button" className="ghost" onClick={() => void api.cancel(id).catch((err: unknown) => setCancelError(err instanceof Error ? err.message : 'Cancel failed'))}>Cancel</button>
          )}
        </div>
      </header>
      {error && <p className="banner" role="alert">{error}</p>}
      {cancelError && <p className="banner" role="alert">{cancelError}</p>}
      {snapshot && (
        <section className="panel" style={{ padding: '1rem 1.1rem' }}>
          <div className="percent-label"><span>Progress</span><span>{snapshot.progress.percent}%</span></div>
          <div className="percent" aria-hidden="true"><div style={{ width: `${snapshot.progress.percent}%` }} /></div>
          <div className="counts">
            {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((severity) => (
              <span key={severity} className={`pill ${severity}`}>{snapshot.counts.bySeverity[severity]} {severity}</span>
            ))}
          </div>
          <div className="progress-grid">
            <ol className="stepper">
              {snapshot.progress.stages.map((stage) => (
                <li key={stage.id} className={stage.status}>
                  <span className="dot" aria-hidden="true" />
                  <div>
                    <strong>{stage.label}</strong>
                    <p>{stage.message || stage.status}{stage.stats?.findings != null ? ` · ${stage.stats.findings} ${stage.stats.findings === 1 ? 'finding' : 'findings'}` : ''}</p>
                    {stage.error && <p className="bad">{stage.error.message}</p>}
                  </div>
                </li>
              ))}
            </ol>
            <section className="log" aria-label="Scan log">
              <h2>Log</h2>
              {logs.length === 0 ? <p className="empty">Waiting for the first log line.</p> : (
                <ul>{logs.map((line) => <LogRow key={line.seq} line={line} />)}</ul>
              )}
            </section>
          </div>
          {snapshot.status === 'completed' && <button type="button" className="primary" onClick={() => navigate(`/scans/${id}/result`)}>Open result</button>}
          {snapshot.status === 'failed' && (
            <div className="banner" role="alert">
              <p>{snapshot.error?.message ?? 'The scan failed.'}</p>
              <button type="button" onClick={() => navigate(`/?retry=${encodeURIComponent(snapshot.repo.url)}`)}>Scan again</button>
            </div>
          )}
          {snapshot.status === 'cancelled' && <p className="note">This scan was cancelled.</p>}
        </section>
      )}
    </Shell>
  );
}

function ResultScreen({ id, navigate, path }: { id: string; navigate: (path: string) => void; path: string }) {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState('all');
  const [category, setCategory] = useState('all');
  const [scanner, setScanner] = useState('all');
  const [open, setOpen] = useState<Finding | null>(null);

  useEffect(() => {
    void api.result(id).then(setReport).catch((err: unknown) => setError(err instanceof Error ? err.message : 'Report unavailable'));
  }, [id]);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(null);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const findings = (report?.findings ?? []).filter((finding) =>
    (severity === 'all' || finding.adjustedSeverity === severity) &&
    (category === 'all' || finding.category === category) &&
    (scanner === 'all' || finding.scanner === scanner),
  );

  return (
    <Shell path={path} navigate={navigate}>
      <header className="page-head">
        <div>
          <p className="eyebrow">{report ? `${report.repo.owner}/${report.repo.name}` : 'Report'}</p>
          <h1>{report?.summary.headline ?? 'Loading report'}</h1>
        </div>
        {report && <a className="ghost" href={`/api/v1/scans/${id}/result`}>Export JSON</a>}
      </header>
      {error && <p className="banner" role="alert">{error} <button type="button" onClick={() => navigate('/')}>Back</button></p>}
      {report && (
        <>
          <section className="summary">
            <span className={`risk ${report.summary.riskLevel}`}>{report.summary.riskLevel}</span>
            <p>{report.summary.text}</p>
            <p className="coverage">
              {report.coverage.scannersRun.length} {report.coverage.scannersRun.length === 1 ? 'scanner' : 'scanners'} ran
              {report.coverage.scannersFailed.length > 0 ? `, ${report.coverage.scannersFailed.length} failed` : ''}
              {report.coverage.partial ? ' · partial report' : ''}.
              {report.coverage.unsupportedEcosystems.length > 0 ? ` Not analyzed: ${report.coverage.unsupportedEcosystems.map((item) => item.ecosystem).join(', ')}.` : ''}
              {' '}Files scanned {report.coverage.filesScanned}, skipped {report.coverage.filesSkipped.count}.
            </p>
          </section>
          <section>
            <h2>Top risks</h2>
            {report.topRisks.length === 0 ? <p className="empty">No high-priority risks. Hygiene notes, if any, are in the next actions.</p> : (
              <div className="cards">
                {report.topRisks.map((risk) => (
                  <article key={risk.findingId} className="card">
                    <span className={`pill ${risk.finding.adjustedSeverity}`}>{risk.finding.adjustedSeverity}</span>
                    <h3>{risk.finding.title}</h3>
                    <p>{risk.whyItMatters}</p>
                  </article>
                ))}
              </div>
            )}
          </section>
          <section>
            <h2>Next actions</h2>
            {report.nextActions.length === 0 ? <p className="empty">Nothing to do in the scanned scope.</p> : (
              <ol className="actions">
                {report.nextActions.map((action) => (
                  <li key={action.id}>
                    <div>
                      <strong>{action.title}</strong>
                      <p>{action.description}</p>
                    </div>
                    <span className="pill">{action.effort === 'S' ? 'Small' : action.effort === 'M' ? 'Medium' : 'Large'}</span>
                    <span className={`pill ${action.impact === 'high' ? 'high' : action.impact === 'medium' ? 'medium' : 'low'}`}>{action.impact} impact</span>
                    <span className="mono">{action.findingIds.length}</span>
                  </li>
                ))}
              </ol>
            )}
          </section>
          <section>
            <h2>All findings</h2>
            <div className="filters">
              <Filter label="Severity" value={severity} options={['all', 'critical', 'high', 'medium', 'low', 'info']} onChange={setSeverity} />
              <Filter label="Category" value={category} options={['all', ...new Set(report.findings.map((finding) => finding.category))]} onChange={setCategory} />
              <Filter label="Scanner" value={scanner} options={['all', ...new Set(report.findings.map((finding) => finding.scanner))]} onChange={setScanner} />
            </div>
            {findings.length === 0 ? <p className="empty">No findings match these filters. {report.findings.length === 0 ? 'The scanners that ran did not flag anything.' : ''}</p> : (
              <div className="table-wrap">
              <table>
                <thead><tr><th>Severity</th><th>Finding</th><th>Location</th><th>Scanner</th></tr></thead>
                <tbody>
                  {findings.map((finding) => (
                    <tr key={finding.id}>
                      <td><span className={`pill ${finding.adjustedSeverity}`}>{finding.adjustedSeverity}</span></td>
                      <td><button type="button" className="linkish" onClick={() => setOpen(finding)}>{finding.title}</button></td>
                      <td className="mono">{finding.location?.path ?? '—'}</td>
                      <td>{finding.scanner}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            )}
          </section>
          {open && (
            <div className="drawer-backdrop" onClick={() => setOpen(null)}>
              <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby="finding-title" onClick={(event) => event.stopPropagation()}>
                <button type="button" className="ghost" onClick={() => setOpen(null)}>Close</button>
                <span className={`pill ${open.adjustedSeverity}`}>{open.adjustedSeverity}</span>
                <h2 id="finding-title">{open.title}</h2>
                <p>{open.description}</p>
                {open.location?.snippet && <pre>{open.location.snippet}</pre>}
                <h3>Why this severity</h3>
                <ul>{open.severityRationale.map((line) => <li key={line}>{line}</li>)}</ul>
                <h3>What to do</h3>
                <p>{open.remediation.summary}</p>
                <ol>{open.remediation.steps.map((step) => <li key={step}>{step}</li>)}</ol>
                {open.references.length > 0 && (
                  <>
                    <h3>References</h3>
                    <ul>{open.references.map((link) => <li key={link.url}><a href={link.url}>{link.title}</a></li>)}</ul>
                  </>
                )}
              </aside>
            </div>
          )}
        </>
      )}
    </Shell>
  );
}

function Filter({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) {
  return (
    <label>
      {label}
      <select value={value} onChange={(event) => onChange(event.target.value)}>
        {options.map((option) => <option key={option} value={option}>{option}</option>)}
      </select>
    </label>
  );
}

function LogRow({ line }: { line: LogLine }) {
  return <li className={line.level}><span className="mono">{line.level}</span> {line.message}</li>;
}

function StatusBadge({ status }: { status: ScanStatus }) {
  const label = status === 'completed' ? 'Completed'
    : status === 'failed' ? 'Failed'
      : status === 'cancelled' ? 'Cancelled'
        : status === 'queued' ? 'Queued'
          : 'In progress';
  return <span className={`badge ${status}`}>{label}</span>;
}

function timeAgo(iso: string): string {
  const minutes = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 60000));
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} ${minutes === 1 ? 'minute' : 'minutes'} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} ${hours === 1 ? 'hour' : 'hours'} ago`;
  const days = Math.round(hours / 24);
  return `${days} ${days === 1 ? 'day' : 'days'} ago`;
}

function Shell({ path, navigate, children }: { path: string; navigate: (to: string) => void; children: ReactNode }) {
  const home = (event: { preventDefault: () => void }, to: string) => {
    event.preventDefault();
    navigate(to);
  };
  return (
    <>
      <header className="topbar">
        <div className="topbar-inner">
          <a className="brand" href="/" onClick={(event) => home(event, '/')}>
            <span className="brand-mark" aria-hidden="true"><ShieldIcon /></span>
            RepoGuard
          </a>
          <nav className="nav-links">
            <a className={path === '/' ? 'active' : ''} href="/" onClick={(event) => home(event, '/')}>Home</a>
            <a href="/#scans" onClick={(event) => { event.preventDefault(); navigate('/'); window.setTimeout(() => document.getElementById('scans')?.scrollIntoView({ behavior: 'smooth' }), 0); }}>Scans</a>
          </nav>
          <span className="top-links"><a href="/api/docs">API</a></span>
        </div>
      </header>
      <main>{children}</main>
    </>
  );
}

function Feature({ tone, title, text, icon }: { tone: string; title: string; text: string; icon: ReactNode }) {
  return (
    <article className="feature">
      <div className={`icon ${tone}`}>{icon}</div>
      <h2>{title}</h2>
      <p>{text}</p>
    </article>
  );
}

function ShieldIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <path d="M12 3 5 6v6c0 4.2 2.8 7.4 7 9 4.2-1.6 7-4.8 7-9V6l-7-3Z" />
    </svg>
  );
}

function GitHubMark() {
  return (
    <svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M8 0C3.58 0 0 3.58 0 8a8 8 0 0 0 5.47 7.59c.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82A7.7 7.7 0 0 1 8 3.87a7.7 7.7 0 0 1 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  );
}

function BoxIcon() {
  return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 3 4 7.5v9L12 21l8-4.5v-9L12 3Z" /><path d="M12 12 4 7.5M12 12v9M12 12l8-4.5" /></svg>;
}

function SearchIcon() {
  return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="6" /><path d="m20 20-3.5-3.5" /></svg>;
}

function BulbIcon() {
  return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M9 18h6M10 21h4" /><path d="M8 14a6 6 0 1 1 8 0c-.8.8-1.2 1.6-1.4 2.5H9.4C9.2 15.6 8.8 14.8 8 14Z" /></svg>;
}

function BoltIcon() {
  return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M13 2 4 14h7l-1 8 9-12h-7l1-8Z" /></svg>;
}
