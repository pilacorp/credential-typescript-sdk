/**
 * Hex helpers — small utility shared by crypto and key-material modules.
 */

export function normalizeHex(hex: string): string {
  return hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = normalizeHex(hex);
  if (clean.length % 2 !== 0) {
    throw new Error(`hex string must be even length, got ${clean.length}`);
  }
  // Strict like Go's hex.DecodeString: parseInt would take "1g", "+1", " 1".
  const bad = clean.search(/[^0-9a-fA-F]/);
  if (bad >= 0) {
    throw new Error(`invalid hex character at position ${bad}`);
  }
  return new Uint8Array(Buffer.from(clean, 'hex'));
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

export function keyToBytes(key: string): Uint8Array {
  if (!key.startsWith('0x')) {
    throw new Error('key is not in hex format');
  }
  return hexToBytes(key);
}
