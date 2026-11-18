/** Go normalizeHash32: trim, lowercase, drop "0x", require exactly 32 bytes of hex. */
export function normalizeHash32(value: string): { hex: string; raw: Uint8Array } {
  const rawHex = value.trim().toLowerCase().replace(/^0x/, '');
  if (rawHex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(rawHex)) {
    throw new Error(`invalid 32-byte hash ${JSON.stringify(value)}: invalid hex`);
  }
  const raw = Uint8Array.from(Buffer.from(rawHex, 'hex'));
  if (raw.length !== 32) {
    throw new Error(`invalid 32-byte hash ${JSON.stringify(value)}: got ${raw.length} bytes`);
  }
  return { hex: `0x${rawHex}`, raw };
}

export function hexHash(raw: Uint8Array): string {
  return `0x${Buffer.from(raw).toString('hex')}`;
}
