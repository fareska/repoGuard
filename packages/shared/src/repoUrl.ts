export interface ParsedRepoUrl {
  url: string;
  owner: string;
  name: string;
  ref?: string;
}

const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;

export function parseRepoUrl(input: string): ParsedRepoUrl | null {
  const trimmed = input.trim();
  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:') return null;
  if (url.username || url.password) return null;
  if (url.hostname !== 'github.com' && url.hostname !== 'www.github.com') return null;

  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length < 2) return null;

  const owner = parts[0] ?? '';
  let name = parts[1] ?? '';
  if (name.endsWith('.git')) name = name.slice(0, -4);
  if (!OWNER.test(owner) || !REPO.test(name) || name === '.' || name === '..') return null;

  let ref: string | undefined;
  if (parts.length === 2) {
    ref = undefined;
  } else if (parts[2] === 'tree' && parts.length >= 4) {
    ref = decodeURIComponent(parts.slice(3).join('/'));
    if (!ref || ref.length > 250 || ref.includes('..')) return null;
  } else {
    return null;
  }

  return {
    url: `https://github.com/${owner}/${name}`,
    owner,
    name,
    ...(ref ? { ref } : {}),
  };
}
