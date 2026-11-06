import { defaultPort, httpsURL, parseURL } from './url';

export interface Origin {
  host: string;
  port: string;
  subdomain: boolean;
}

export class OriginList {
  constructor(readonly any: boolean, readonly origins: Origin[]) {}

  covers(u: URL): boolean {
    return this.any || this.origins.some((o) => covers(o, u));
  }
}

export function checkOriginEntry(e: string, hints: { all: string; finer?: string }): string {
  if (e === '*') return `is "*", which is not an entry; to cover every https origin, ${hints.all}`;
  if (e.length < 8 || e.slice(0, 8).toLowerCase() !== 'https://') {
    return 'does not start with https://; list origins as "https://host" or "https://*.host"';
  }
  const o = parseOrigin(e);
  const notOrigin =
    'is not an origin "https://host" or "https://*.host", with an optional port and final "/": an entry names a whole origin, so it has no path, query, userinfo or other "*"';
  if (!o) return hints.finer ? `${notOrigin}; to trust some URLs of an origin, ${hints.finer}` : notOrigin;
  if (!plainHost(o.host)) {
    return 'has a host that is not ASCII or has an empty label, a final "." included; write the host in ASCII, each non-ASCII label as its A-label ("xn--..."), with no empty label';
  }
  if ((o.host.includes(':') || e.includes('[')) && (o.subdomain || !isIPv6Host(o.host))) {
    return 'has ":" or "[" in a host that is not an IPv6 address, or "*." before an IPv6 address; write the port once, after the host, and an IPv6 address alone, as "https://[address]"';
  }
  if (!plainPort(o.port)) {
    return 'has a port that is not a number from 1 to 65535 without leading zeros';
  }
  return '';
}

export function newOriginList(entries: string[]): OriginList {
  return new OriginList(entries.length === 0, parseAll(entries));
}

export interface Redirects {
  any: boolean;
  to: OriginList;
}

export function redirectsTo(entries: string[]): Redirects {
  return { any: false, to: new OriginList(false, parseAll(entries)) };
}

export function redirectsAny(): Redirects {
  return { any: true, to: new OriginList(false, []) };
}

export function follows(r: Redirects | undefined, start: URL, target: URL): boolean {
  if (!r || r.any) return r?.any ? true : sameOrigin(start, target);
  return sameOrigin(start, target) || r.to.covers(target);
}

function parseAll(entries: string[]): Origin[] {
  return entries.map(parseOrigin).filter((o): o is Origin => o !== null);
}

function parseOrigin(e: string): Origin | null {
  let raw = e;
  let subdomain = false;
  if (raw.slice(8).startsWith('*.')) {
    subdomain = true;
    raw = 'https://' + raw.slice(10);
  }
  let u: URL;
  try {
    u = parseURL(raw);
  } catch {
    return null;
  }
  if (!httpsURL(u) || (u.pathname !== '' && u.pathname !== '/') || /[?#*]/.test(e)) return null;
  return { host: asciiLower(u.hostname), port: defaultPort(u), subdomain };
}

function covers(o: Origin, u: URL): boolean {
  const host = asciiLower(u.hostname);
  if (o.subdomain) {
    if (host.includes(':') || !host.endsWith('.' + o.host)) return false;
  } else if (host !== o.host) return false;
  return defaultPort(u) === o.port;
}

function sameOrigin(a: URL, b: URL): boolean {
  return asciiLower(a.hostname) === asciiLower(b.hostname) && defaultPort(a) === defaultPort(b);
}

function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => c.toLowerCase());
}

function plainHost(host: string): boolean {
  for (let i = 0; i < host.length; i++) if (host.charCodeAt(i) >= 0x80) return false;
  return !host.startsWith('.') && !host.endsWith('.') && !host.includes('..');
}

function isIPv6Host(host: string): boolean {
  return host.includes(':');
}

function plainPort(port: string): boolean {
  const n = Number(port);
  return Number.isInteger(n) && n >= 1 && n <= 65535 && port === String(n);
}
