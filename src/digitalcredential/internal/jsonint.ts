export class JsonIntError extends Error {
  constructor(readonly kind: 'not-integer' | 'too-large', message: string) {
    super(message);
    this.name = 'JsonIntError';
  }
}

const maxExp = 1 << 40;

export function nonNegativeInt(n: string): number {
  let s = n;
  let neg = false;
  if (s.startsWith('-')) {
    s = s.slice(1);
    neg = true;
  }
  let i = digits(s, 0);
  if (i === 0 || (s[0] === '0' && i > 1)) throw new JsonIntError('not-integer', 'not a non-negative integer');
  const whole = s.slice(0, i);
  let frac = '';
  if (i < s.length && s[i] === '.') {
    const j = digits(s, i + 1);
    if (j === i + 1) throw new JsonIntError('not-integer', 'not a non-negative integer');
    frac = s.slice(i + 1, j);
    i = j;
  }
  let exp = 0;
  if (i < s.length && (s[i] === 'e' || s[i] === 'E')) {
    i++;
    let expNeg = false;
    if (i < s.length && (s[i] === '-' || s[i] === '+')) {
      expNeg = s[i] === '-';
      i++;
    }
    const j = digits(s, i);
    if (j === i) throw new JsonIntError('not-integer', 'not a non-negative integer');
    for (let k = i; k < j; k++) {
      if (exp < maxExp) exp = exp * 10 + (s.charCodeAt(k) - 48);
    }
    if (expNeg) exp = -exp;
    i = j;
  }
  if (i !== s.length) throw new JsonIntError('not-integer', 'not a non-negative integer');
  const all = whole + frac;
  let lo = 0;
  let hi = all.length;
  while (lo < hi && all[lo] === '0') lo++;
  if (lo === hi) return 0;
  while (all[hi - 1] === '0') hi--;
  if (neg) throw new JsonIntError('not-integer', 'not a non-negative integer');
  let shift = exp - frac.length + (all.length - hi);
  if (shift < 0) throw new JsonIntError('not-integer', 'not a non-negative integer');
  if (hi - lo + shift > 19) throw new JsonIntError('too-large', 'integer too large');
  let v = 0n;
  for (let k = lo; k < hi; k++) v = v * 10n + BigInt(all.charCodeAt(k) - 48);
  while (shift > 0) {
    v *= 10n;
    shift--;
  }
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new JsonIntError('too-large', 'integer too large');
  return Number(v);
}

function digits(s: string, i: number): number {
  while (i < s.length && s[i] >= '0' && s[i] <= '9') i++;
  return i;
}
