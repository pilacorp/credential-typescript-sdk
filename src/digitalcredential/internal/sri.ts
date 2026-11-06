import { createHash } from 'node:crypto';

const algs = [
  { name: 'sha512', bytes: 64 },
  { name: 'sha384', bytes: 48 },
  { name: 'sha256', bytes: 32 },
] as const;

export function wellFormedIntegrity(integrity: string): boolean {
  for (const tok of splitASCIISpace(integrity)) {
    if (parseToken(tok) === null) return false;
  }
  return true;
}

export function checkIntegrityBytes(data: Uint8Array, integrity: string): void {
  if (!wellFormedIntegrity(integrity)) {
    throw new Error(
      'integrity metadata is not well formed: each token is sha256-, sha384- or sha512- and base64, tokens separated by spaces (W3C SRI §3.5)',
    );
  }
  const { alg, digests } = strongest(integrity);
  if (alg < 0) throw new Error('integrity metadata holds no sha256, sha384 or sha512 hash expression');
  const sum = createHash(algs[alg].name).update(data).digest();
  for (const d of digests) {
    if (d.length === sum.length && Buffer.compare(d, sum) === 0) return;
  }
  throw new Error(`the document does not match its ${algs[alg].name} integrity metadata`);
}

function strongest(integrity: string): { alg: number; digests: Buffer[] } {
  let alg = -1;
  let digests: Buffer[] = [];
  for (const tok of splitASCIISpace(integrity)) {
    const parsed = parseToken(tok)!;
    if (alg >= 0 && parsed.alg > alg) continue;
    let d: Buffer;
    try {
      d = Buffer.from(parsed.value.replace(/=+$/, ''), 'base64');
    } catch {
      d = Buffer.alloc(0);
    }
    if (parsed.alg < alg || alg < 0) {
      alg = parsed.alg;
      digests = [];
    }
    digests.push(d);
  }
  return { alg, digests };
}

function parseToken(tok: string): { alg: number; value: string } | null {
  const q = tok.indexOf('?');
  const opts = q >= 0 ? tok.slice(q + 1) : '';
  const body = q >= 0 ? tok.slice(0, q) : tok;
  for (let i = 0; i < opts.length; i++) {
    const c = opts.charCodeAt(i);
    if (c < 0x21 || c > 0x7e) return null;
  }
  const dash = body.indexOf('-');
  if (dash < 0) return null;
  const name = body.slice(0, dash);
  const value = body.slice(dash + 1);
  if (!base64Value(value)) return null;
  for (let j = 0; j < algs.length; j++) {
    if (name.length === algs[j].name.length && name.toLowerCase() === algs[j].name) {
      return { alg: j, value };
    }
  }
  return null;
}

function base64Value(s: string): boolean {
  const body = s.replace(/=+$/, '');
  if (!body || s.length - body.length > 2) return false;
  return /^[A-Za-z0-9+/]+$/.test(body);
}

function splitASCIISpace(s: string): string[] {
  return s.split(/[ \t\n\f\r]+/).filter(Boolean);
}
