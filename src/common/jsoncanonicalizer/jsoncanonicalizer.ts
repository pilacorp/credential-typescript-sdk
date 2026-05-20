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
  let value: unknown;
  if (typeof input === 'string') {
    value = JSON.parse(input);
  } else if (input instanceof Uint8Array || Buffer.isBuffer(input)) {
    value = JSON.parse(Buffer.from(input as Uint8Array).toString('utf8'));
  } else {
    value = input;
  }
  return Buffer.from(serialize(value), 'utf8');
}

export function transformToString(input: string | Uint8Array | unknown): string {
  if (typeof input === 'string') return serialize(JSON.parse(input));
  if (input instanceof Uint8Array || Buffer.isBuffer(input)) {
    return serialize(JSON.parse(Buffer.from(input as Uint8Array).toString('utf8')));
  }
  return serialize(input);
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
  let out = '"';
  const bytes = Buffer.from(raw, 'utf8');
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    if (asciiEscapes[c]) {
      out += asciiEscapes[c];
    } else if (c < 0x20) {
      out += '\\u' + c.toString(16).padStart(4, '0');
    } else {
      out += String.fromCharCode(c);
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
