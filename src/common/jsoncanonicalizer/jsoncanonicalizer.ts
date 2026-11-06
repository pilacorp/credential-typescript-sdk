/**
 * JSON Canonicalization Scheme (RFC 8785) — Node port of
 * credential/common/jsoncanonicalizer/{jsoncanonicalizer.go,es6numfmt.go}.
 *
 * Transform an input JSON value to its canonical UTF-8 byte representation:
 *  - Object keys sorted by UTF-16 code units
 *  - ES6-formatted numbers
 *  - Standard JSON escapes
 *
 * The implementation accepts either raw JSON bytes/string OR an already-parsed
 * value. Callers in this repo mostly hand off raw bytes mirroring the Go API.
 */

const INVALID_PATTERN = 0x7ff0000000000000n;

export function transform(input: string | Uint8Array | unknown): Uint8Array {
  return Buffer.from(transformToString(input), 'utf8');
}

export function transformToString(input: string | Uint8Array | unknown): string {
  let value: unknown = input;
  if (typeof input === 'string' || input instanceof Uint8Array || Buffer.isBuffer(input)) {
    const text = typeof input === 'string' ? input : Buffer.from(input as Uint8Array).toString('utf8');
    value = JSON.parse(text);
    rejectDuplicateKeys(text);
  }
  // Like Go: only an object or array is a document, never a bare scalar.
  if (value === null || typeof value !== 'object') {
    throw new Error('canonicalizer: top-level value must be an object or array');
  }
  return serialize(value);
}

/**
 * JSON.parse keeps the last of two equal keys; Go's canonicalizer refuses them.
 * Walks the (already valid) text: every string followed by ":" is a key.
 */
function rejectDuplicateKeys(text: string): void {
  const stack: (Set<string> | null)[] = [];
  const tok = /"(?:[^"\\]|\\.)*"|[{}[\]]/g;
  const colon = /\s*:/y;
  for (let m = tok.exec(text); m; m = tok.exec(text)) {
    const t = m[0];
    if (t === '{') stack.push(new Set());
    else if (t === '[') stack.push(null);
    else if (t === '}' || t === ']') stack.pop();
    else {
      colon.lastIndex = tok.lastIndex;
      if (!colon.test(text)) continue;
      const keys = stack[stack.length - 1];
      const key = JSON.parse(t) as string;
      if (keys?.has(key)) throw new Error(`canonicalizer: duplicate key: ${key}`);
      keys?.add(key);
    }
  }
}

function checkSurrogates(s: string): void {
  if (/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/.test(s)) {
    throw new Error('canonicalizer: lone surrogate in string');
  }
}

function serialize(value: unknown): string {
  if (value === null) return 'null';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') return numberToJSON(value);
  if (typeof value === 'string') return decorateString(value);
  if (Array.isArray(value)) {
    return '[' + value.map(serialize).join(',') + ']';
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const entries: [string, string][] = Object.keys(obj).map((k) => [k, k]);
    entries.sort((a, b) => compareUTF16(a[0], b[0]));
    const parts = entries.map(([key]) => decorateString(key) + ':' + serialize(obj[key]));
    return '{' + parts.join(',') + '}';
  }
  throw new Error(`canonicalizer: unsupported value type ${typeof value}`);
}

function compareUTF16(a: string, b: string): number {
  const aUnits = stringToUTF16Units(a);
  const bUnits = stringToUTF16Units(b);
  const min = Math.min(aUnits.length, bUnits.length);
  for (let i = 0; i < min; i++) {
    const diff = aUnits[i] - bUnits[i];
    if (diff !== 0) return diff;
  }
  return aUnits.length - bUnits.length;
}

function stringToUTF16Units(s: string): number[] {
  const out: number[] = [];
  for (let i = 0; i < s.length; i++) {
    out.push(s.charCodeAt(i));
  }
  return out;
}

const asciiEscapes: Record<number, string> = {
  0x08: '\\b',
  0x09: '\\t',
  0x0a: '\\n',
  0x0c: '\\f',
  0x0d: '\\r',
  0x22: '\\"',
  0x5c: '\\\\',
};

function decorateString(raw: string): string {
  checkSurrogates(raw);
  let out = '"';
  // Iterate by Unicode code point (RFC 8785 §3.2.2.2): the 7 named escapes and
  // other control chars (< 0x20) are escaped, everything else — including
  // non-ASCII — is emitted as-is and encoded to raw UTF-8 by the caller.
  // (Iterating UTF-8 bytes and emitting String.fromCharCode per byte mangled
  // every multi-byte character into mojibake, which then double-encoded.)
  for (const ch of raw) {
    const cp = ch.codePointAt(0) as number;
    if (asciiEscapes[cp]) {
      out += asciiEscapes[cp];
    } else if (cp < 0x20) {
      out += '\\u' + cp.toString(16).padStart(4, '0');
    } else {
      out += ch;
    }
  }
  out += '"';
  return out;
}

/**
 * Convert an IEEE-754 double into the canonical JSON number format
 * specified by ES6 / RFC 8785 §3.2.2.3.
 */
export function numberToJSON(value: number): string {
  if (!Number.isFinite(value)) {
    throw new Error(`Invalid JSON number: ${value}`);
  }
  // Special case: -0 and 0 both become "0"
  if (value === 0) return '0';

  let sign = '';
  let v = value;
  if (v < 0) {
    sign = '-';
    v = -v;
  }

  // ES6 "g" format boundary
  if (v < 1e21 && v >= 1e-6) {
    return sign + formatFloat(v);
  }
  return sign + formatExponential(v);
}

function formatFloat(v: number): string {
  // Use shortest-roundtrip representation. JS's number toString gets us there
  // in the f-format range, but we need to strip a trailing ".0" or normalize.
  const s = v.toString();
  // For integers JS yields "1234"; ES6 standard wants integer literal without
  // trailing ".0". JS already does this, so we can return directly except
  // when the value is in scientific notation (covered by exponential path).
  if (s.includes('e') || s.includes('E')) {
    // Fallback: rare due to range guard but possible for subnormal values
    return v.toString();
  }
  return s;
}

function formatExponential(v: number): string {
  // JS produces e.g. "1e+21" or "1.234e-7"; ES6 expects e+/-N with N having no leading zero.
  let s = v.toExponential();
  // Normalize "1.0e+21" → "1e+21" if mantissa is integer-equivalent
  // (toExponential() already does this for integer mantissas).
  // Strip leading zero in exponent: "e+09" -> "e+9".
  s = s.replace(/e([+-])0*(\d)/, 'e$1$2');
  return s;
}
