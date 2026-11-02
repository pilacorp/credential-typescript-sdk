import type { IncomingHttpHeaders } from 'node:http';
import { get, type Limits } from './safehttp';

const maxLifetimeMs = 24 * 3600 * 1000;

export async function cachedGet(
  rawURL: string,
  mediaTypes: string[],
  limits: Limits,
  ceilingMs = maxLifetimeMs,
  signal?: AbortSignal,
): Promise<{ body: Buffer; freshMs: number }> {
  const { body, headers } = await get(rawURL, mediaTypes, limits, signal);
  return { body, freshMs: Math.min(ceilingMs, freshness(headers, ceilingMs)) };
}

export function freshness(h: IncomingHttpHeaders, ceilingMs: number): number {
  const cc = headerValues(h, 'cache-control').join(',');
  if (cc.includes('"')) return 0;
  for (const v of headerValues(h, 'vary')) {
    for (const m of v.split(',')) {
      const t = m.trim();
      if (t && t.toLowerCase() !== 'accept' && t.toLowerCase() !== 'accept-encoding') return 0;
    }
  }
  let maxAge = 0;
  let seen = false;
  for (const d of cc.split(',')) {
    const [nameRaw, arg] = d.trim().split('=');
    const name = (nameRaw ?? '').toLowerCase();
    if (name === 'no-store' || name === 'no-cache') return 0;
    if (name === 'max-age') {
      const n = deltaSeconds(arg ?? '');
      if (seen || n === null) return 0;
      seen = true;
      maxAge = n;
    }
  }
  if (!seen) return 0;
  const age = Number(headerValues(h, 'age')[0] ?? 0);
  const remaining = Math.max(0, maxAge - (Number.isFinite(age) ? age : 0));
  return Math.min(ceilingMs, remaining * 1000);
}

function headerValues(h: IncomingHttpHeaders, name: string): string[] {
  const v = h[name];
  if (v === undefined) return [];
  return Array.isArray(v) ? v : [v];
}

function deltaSeconds(arg: string): number | null {
  if (!/^[0-9]+$/.test(arg)) return null;
  const n = Number(arg);
  return Number.isFinite(n) ? n : null;
}
