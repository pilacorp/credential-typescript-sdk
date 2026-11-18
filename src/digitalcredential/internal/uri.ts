/** RFC 3986 URI check used by draft-ietf-oauth-sd-jwt-vc-19 and status-list-21. */

export function validURI(s: string): boolean {
  let rest = s;
  const hash = rest.indexOf('#');
  if (hash >= 0) {
    if (!uriChars(rest.slice(hash + 1), ':@/?')) return false;
    rest = rest.slice(0, hash);
  }
  const q = rest.indexOf('?');
  if (q >= 0) {
    if (!uriChars(rest.slice(q + 1), ':@/?')) return false;
    rest = rest.slice(0, q);
  }
  const colon = rest.indexOf(':');
  if (colon < 0 || !isScheme(rest.slice(0, colon))) return false;
  let path = rest.slice(colon + 1);
  if (path.startsWith('//')) {
    const slash = path.indexOf('/', 2);
    const authority = slash < 0 ? path.slice(2) : path.slice(2, slash);
    if (!isAuthority(authority)) return false;
    path = slash < 0 ? '' : path.slice(slash + 1);
  }
  return uriChars(path, ':@/');
}

export function checkURI(s: string): void {
  if (!validURI(s)) throw new Error('is not a URI (RFC 3986)');
  const colon = s.indexOf(':');
  const scheme = s.slice(0, colon);
  if (/^https?$/i.test(scheme) && !hasHost(s.slice(colon + 1))) {
    throw new Error('is an http or https URI without a host (RFC 9110 §4.2.1, §4.2.2)');
  }
}

function hasHost(rest: string): boolean {
  if (!rest.startsWith('//')) return false;
  let authority = rest.slice(2);
  const cut = authority.search(/[/?#]/);
  if (cut >= 0) authority = authority.slice(0, cut);
  const at = authority.lastIndexOf('@');
  if (at >= 0) authority = authority.slice(at + 1);
  const host = authority.split(':')[0];
  return host !== '' || authority.startsWith('[');
}

function isScheme(s: string): boolean {
  if (!s || !isAlpha(s.charCodeAt(0))) return false;
  for (let i = 1; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (!isAlpha(c) && !isDigit(c) && s[i] !== '+' && s[i] !== '-' && s[i] !== '.') return false;
  }
  return true;
}

function isAuthority(s: string): boolean {
  let rest = s;
  const at = rest.indexOf('@');
  if (at >= 0) {
    if (!uriChars(rest.slice(0, at), ':')) return false;
    rest = rest.slice(at + 1);
  }
  let host = rest;
  let port = '';
  if (rest.startsWith('[')) {
    const end = rest.indexOf(']');
    if (end < 0) return false;
    if (!isIPLiteral(rest.slice(1, end))) return false;
    const after = rest.slice(end + 1);
    if (after) {
      if (!after.startsWith(':')) return false;
      port = after.slice(1);
    }
    host = '';
  } else {
    const c = rest.indexOf(':');
    if (c >= 0) {
      host = rest.slice(0, c);
      port = rest.slice(c + 1);
    }
  }
  for (let i = 0; i < port.length; i++) {
    if (!isDigit(port.charCodeAt(i))) return false;
  }
  return uriChars(host, '');
}

function isIPLiteral(s: string): boolean {
  if (s && (s[0] === 'v' || s[0] === 'V')) {
    const rest = s.slice(1);
    const dot = rest.indexOf('.');
    if (dot < 1 || rest.length === dot + 1 || rest.includes('%')) return false;
    const hex = rest.slice(0, dot);
    const tail = rest.slice(dot + 1);
    for (let i = 0; i < hex.length; i++) if (!isHex(hex.charCodeAt(i))) return false;
    return uriChars(tail, ':');
  }
  return false;
}

function uriChars(s: string, extra: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (s[i] === '%') {
      if (i + 2 >= s.length || !isHex(s.charCodeAt(i + 1)) || !isHex(s.charCodeAt(i + 2))) return false;
      i += 2;
      continue;
    }
    if (isAlpha(c) || isDigit(c) || "-._~!$&'()*+,;=".includes(s[i]) || extra.includes(s[i])) continue;
    return false;
  }
  return true;
}

function isAlpha(c: number): boolean {
  return (c >= 65 && c <= 90) || (c >= 97 && c <= 122);
}
function isDigit(c: number): boolean {
  return c >= 48 && c <= 57;
}
function isHex(c: number): boolean {
  return isDigit(c) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70);
}
