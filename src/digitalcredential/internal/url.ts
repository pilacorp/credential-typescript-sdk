export function parseURL(raw: string): URL {
  return new URL(raw);
}

export function httpsURL(u: URL): boolean {
  return u.protocol === 'https:' && u.hostname !== '' && u.username === '' && u.password === '';
}

export function defaultPort(u: URL): string {
  if (u.port) return u.port;
  return u.protocol === 'http:' ? '80' : '443';
}

export function allowsHTTPOrHTTPS(u: URL, allowHTTP: boolean): boolean {
  if (allowHTTP && u.protocol === 'http:') {
    return u.hostname !== '' && u.username === '' && u.password === '';
  }
  return httpsURL(u);
}
