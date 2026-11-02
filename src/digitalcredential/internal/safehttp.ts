import * as dns from 'node:dns/promises';
import * as http from 'node:http';
import * as https from 'node:https';
import { blockedAddress, ErrAddressBlocked } from './blocked';
import type { Redirects } from './allowlist';
import { follows } from './allowlist';
import { allowsHTTPOrHTTPS, defaultPort, httpsURL, parseURL } from './url';

export { defaultPort, httpsURL, parseURL };

export { ErrAddressBlocked };

export const ErrNotFollowed = Object.assign(new Error('redirect refused'), { name: 'SafeHTTPError' });
export const ErrRedirectTargetNotAllowed = Object.assign(new Error('safehttp: redirect target not allowed'), {
  name: 'SafeHTTPError',
});
export const ErrTooManyRedirects = Object.assign(new Error('safehttp: too many redirects'), { name: 'SafeHTTPError' });
export const ErrContentTypeNotAccepted = Object.assign(new Error('safehttp: content type not accepted'), {
  name: 'SafeHTTPError',
});
export const ErrBodyTooLarge = Object.assign(new Error('safehttp: body too large'), { name: 'SafeHTTPError' });

export class StatusError extends Error {
  constructor(readonly code: number) {
    super(`safehttp: status ${code}`);
    this.name = 'StatusError';
  }
}

export interface Limits {
  timeoutMs: number;
  maxRedirects: number;
  maxBytes: number;
  allowHTTP?: boolean;
  redirects?: Redirects;
  anyContentType?: boolean;
  /** Trusted fetch, skipping the default address block (like Config.HTTPClient). */
  fetch?: typeof fetch;
}

export function allows(l: Limits, u: URL): boolean {
  return allowsHTTPOrHTTPS(u, Boolean(l.allowHTTP));
}

export interface GetResult {
  body: Buffer;
  headers: http.IncomingHttpHeaders;
}

export async function get(
  rawURL: string,
  mediaTypes: string[],
  limits: Limits,
  signal?: AbortSignal,
): Promise<GetResult> {
  const start = parseURL(rawURL);
  if (!allows(limits, start)) {
    throw ErrRedirectTargetNotAllowed;
  }
  let current = start.href;
  for (let hops = 0; hops <= limits.maxRedirects; hops++) {
    const res = await oneRequest(current, mediaTypes, limits, signal);
    if (res.status >= 300 && res.status < 400 && res.headers.location) {
      if (hops >= limits.maxRedirects) throw ErrTooManyRedirects;
      const next = new URL(String(res.headers.location), current);
      if (!allows(limits, next)) throw ErrRedirectTargetNotAllowed;
      if (!follows(limits.redirects, parseURL(rawURL), next)) throw ErrNotFollowed;
      current = next.href;
      continue;
    }
    if (res.status < 200 || res.status >= 300) throw new StatusError(res.status);
    if (!limits.anyContentType && !acceptsType(String(res.headers['content-type'] ?? ''), mediaTypes)) {
      throw ErrContentTypeNotAccepted;
    }
    if (res.body.length > limits.maxBytes) throw ErrBodyTooLarge;
    return { body: res.body, headers: res.headers };
  }
  throw ErrTooManyRedirects;
}

function acceptsType(contentType: string, mediaTypes: string[]): boolean {
  const mt = contentType.split(';')[0].trim().toLowerCase();
  return mediaTypes.some((want) => mt === want.toLowerCase());
}

async function oneRequest(
  rawURL: string,
  mediaTypes: string[],
  limits: Limits,
  signal?: AbortSignal,
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: Buffer }> {
  if (limits.fetch) {
    const ac = AbortSignal.any(
      [AbortSignal.timeout(limits.timeoutMs), signal].filter(Boolean) as AbortSignal[],
    );
    const res = await limits.fetch(rawURL, {
      redirect: 'manual',
      signal: ac,
      headers: { Accept: mediaTypes.join(', ') },
    });
    const buf = Buffer.from(await res.arrayBuffer());
    const headers: http.IncomingHttpHeaders = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    return { status: res.status, headers, body: buf };
  }

  const u = parseURL(rawURL);
  const ac = AbortSignal.any(
    [AbortSignal.timeout(limits.timeoutMs), signal].filter(Boolean) as AbortSignal[],
  );
  const lib = u.protocol === 'http:' ? http : https;
  const addrs = await dns.lookup(u.hostname, { all: true });
  const usable = addrs.filter((a) => !blockedAddress(a.address));
  if (!usable.length) throw ErrAddressBlocked;
  const chosen = usable[0];

  return new Promise((resolve, reject) => {
    const req = lib.request(
      {
        hostname: chosen.address,
        servername: u.hostname,
        port: u.port || (u.protocol === 'http:' ? 80 : 443),
        path: u.pathname + u.search,
        method: 'GET',
        headers: {
          Host: u.host,
          Accept: mediaTypes.join(', '),
        },
        timeout: limits.timeoutMs,
        lookup: (_h, _o, cb) => cb(null, chosen.address, chosen.family),
      },
      (res) => {
        const chunks: Buffer[] = [];
        let n = 0;
        res.on('data', (c: Buffer) => {
          n += c.length;
          if (n > limits.maxBytes + 1) {
            req.destroy();
            reject(ErrBodyTooLarge);
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks) }));
        res.on('error', reject);
      },
    );
    ac.addEventListener('abort', () => {
      req.destroy();
      reject(ac.reason ?? new Error('aborted'));
    });
    req.on('error', reject);
    req.end();
  });
}
