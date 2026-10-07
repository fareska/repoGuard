import React from 'react';
import {
  SCAN_EVENT_TYPES,
  applyScanEvent,
  isTerminal,
  type LogLevel,
  type ScanEvent,
  type ScanEventType,
  type ScanSnapshot,
  type ScannersResponse,
} from '@repoguard/shared';

export class ApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<{ status: number; body: T }> {
  const response = await fetch(path, {
    ...init,
    headers: {
      ...(init?.body ? { 'content-type': 'application/json' } : {}),
      ...init?.headers,
    },
  });
  if (response.status === 204) return { status: 204, body: undefined as T };
  const body = (await response.json().catch(() => ({}))) as T & { detail?: string; title?: string };
  if (!response.ok) throw new ApiError(body.detail || body.title || `Request failed (${response.status})`, response.status);
  return { status: response.status, body };
}

export const api = {
  scanners: () => request<ScannersResponse>('/api/v1/scanners').then((result) => result.body),
  scans: () => request<{ items: import('@repoguard/shared').ScanSummary[] }>('/api/v1/scans?limit=8').then((result) => result.body.items),
  create: (body: { repoUrl: string; mode?: 'real' | 'mock'; scanners?: string[] }) =>
    request<ScanSnapshot>('/api/v1/scans', { method: 'POST', body: JSON.stringify(body) }),
  scan: (id: string) => request<ScanSnapshot>(`/api/v1/scans/${id}`).then((result) => result.body),
  result: (id: string) => request<import('@repoguard/shared').Report>(`/api/v1/scans/${id}/result`).then((result) => result.body),
  cancel: (id: string) => request<ScanSnapshot>(`/api/v1/scans/${id}/cancel`, { method: 'POST' }).then((result) => result.body),
};

export interface LogLine {
  seq: number;
  level: LogLevel;
  message: string;
  stageId?: string;
}

export function useRoute() {
  const [path, setPath] = React.useState(window.location.pathname);
  React.useEffect(() => {
    const onPop = () => setPath(window.location.pathname);
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);
  const navigate = React.useCallback((to: string) => {
    window.history.pushState({}, '', to);
    setPath(window.location.pathname);
  }, []);
  return { path, navigate };
}

export function useScan(scanId: string) {
  const [snapshot, setSnapshot] = React.useState<ScanSnapshot | null>(null);
  const [logs, setLogs] = React.useState<LogLine[]>([]);
  const [transport, setTransport] = React.useState<'connecting' | 'sse' | 'poll'>('connecting');
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    let cancelled = false;
    let source: EventSource | null = null;
    let pollTimer = 0;
    let failures = 0;
    let appliedSeq = 0;

    const apply = (type: ScanEventType, payload: ScanEvent['payload'], seq: number, ts: string) => {
      if (type === 'log') {
        const entry = payload as { level: LogLevel; message: string; stageId?: string };
        setLogs((current) => {
          if (current.some((line) => line.seq === seq)) return current;
          return [...current, { seq, level: entry.level, message: entry.message, stageId: entry.stageId }].slice(-200);
        });
      }
      if (seq <= appliedSeq) return;
      appliedSeq = seq;
      setSnapshot((current) => (current ? applyScanEvent(current, { scanId, seq, ts, type, payload } as ScanEvent) : current));
    };

    const startPoll = () => {
      if (cancelled) return;
      source?.close();
      setTransport('poll');
      const tick = async () => {
        try {
          const next = await api.scan(scanId);
          if (cancelled) return;
          setSnapshot(next);
          if (isTerminal(next.status)) window.clearInterval(pollTimer);
        } catch (err) {
          if (!cancelled) setError(err instanceof Error ? err.message : 'Polling failed');
        }
      };
      void tick();
      pollTimer = window.setInterval(() => void tick(), 2000);
    };

    const startStream = (afterSeq: number) => {
      source = new EventSource(`/api/v1/scans/${scanId}/events?afterSeq=${afterSeq}`);
      source.onopen = () => {
        failures = 0;
        setTransport('sse');
      };
      source.onerror = () => {
        failures += 1;
        source?.close();
        if (failures >= 2) startPoll();
        else window.setTimeout(() => startStream(0), 800);
      };
      for (const type of SCAN_EVENT_TYPES) {
        source.addEventListener(type, (event) => {
          const message = event as MessageEvent;
          apply(type, JSON.parse(message.data) as ScanEvent['payload'], Number(message.lastEventId), new Date().toISOString());
        });
      }
    };

    void api.scan(scanId).then((next) => {
      if (cancelled) return;
      setSnapshot(next);
      appliedSeq = next.lastEventSeq;
      startStream(0);
    }).catch((err: unknown) => {
      if (!cancelled) setError(err instanceof Error ? err.message : 'Could not load the scan');
    });

    return () => {
      cancelled = true;
      source?.close();
      window.clearInterval(pollTimer);
    };
  }, [scanId]);

  return { snapshot, logs, transport, error };
}
