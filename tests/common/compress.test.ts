import {
  compressToBase64,
  compressToBase64URL,
  decompressFromBase64,
  decompressFromBase64URL,
} from '../../src/common/util/compress';

describe('compress/decompress roundtrip', () => {
  const payload = Buffer.from(JSON.stringify({ hello: 'world', n: 1, b: true }), 'utf8');

  it('base64 roundtrip', () => {
    const compressed = compressToBase64(payload);
    const out = decompressFromBase64(compressed);
    expect(Buffer.from(out).toString()).toBe(payload.toString());
  });

  it('base64url roundtrip', () => {
    const compressed = compressToBase64URL(payload);
    const out = decompressFromBase64URL(compressed);
    expect(Buffer.from(out).toString()).toBe(payload.toString());
  });
});
