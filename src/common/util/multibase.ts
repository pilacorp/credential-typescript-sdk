const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function encodeBase58Btc(raw: Uint8Array): string {
  if (raw.length === 0) return 'z';
  let zeros = 0;
  while (zeros < raw.length && raw[zeros] === 0) zeros += 1;
  let value = BigInt('0x' + Buffer.from(raw).toString('hex')) || 0n;
  let out = '';
  while (value > 0n) {
    const rem = value % 58n;
    value /= 58n;
    out = ALPHABET[Number(rem)] + out;
  }
  return 'z' + '1'.repeat(zeros) + out;
}

export function decodeBase58Btc(multibase: string): Uint8Array {
  if (!multibase || multibase[0] !== 'z') {
    throw new Error("expected base58btc multibase prefix 'z'");
  }
  const input = multibase.slice(1);
  if (!input) return new Uint8Array();
  let value = 0n;
  for (const ch of input) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error('invalid base58 character');
    value = value * 58n + BigInt(idx);
  }
  let hex = value.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const decoded = hex.length ? Buffer.from(hex, 'hex') : Buffer.alloc(0);
  let zeros = 0;
  while (zeros < input.length && input[zeros] === '1') zeros += 1;
  const out = new Uint8Array(zeros + decoded.length);
  out.set(decoded, zeros);
  return out;
}
