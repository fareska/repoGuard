import type { Precision } from '@repoguard/shared';

export function npmSpecifier(spec: string): { version: string; precision: Precision } | null {
  const cleaned = spec.trim();
  if (!cleaned || cleaned === '*' || cleaned === 'latest') return null;
  if (/^(file:|link:|workspace:|git\+|git:|github:|http:|https:|npm:)/.test(cleaned)) return null;
  const exact = /^v?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)$/.exec(cleaned);
  if (exact?.[1]) return { version: exact[1], precision: 'manifest-pinned' };
  const lower = /(?:\^|~|>=|=>|>)?v?(\d+\.\d+\.\d+)/.exec(cleaned);
  if (!lower?.[1]) return null;
  const precision: Precision = cleaned === lower[1] || cleaned === `v${lower[1]}` ? 'manifest-pinned' : 'manifest-range';
  return { version: lower[1], precision };
}

export function pythonSpecifier(spec: string): { version: string; precision: Precision } | null {
  const match = /^(?:==|===|~=|>=|>)?\s*v?(\d+(?:\.\d+){1,2}(?:[-.][\w*]+)*)/.exec(spec.trim());
  if (!match?.[1]) return null;
  const pinned = spec.trim().startsWith('==') || spec.trim().startsWith('===');
  const version = match[1].split('.').length === 2 ? `${match[1]}.0` : match[1];
  return { version, precision: pinned ? 'manifest-pinned' : 'manifest-range' };
}
