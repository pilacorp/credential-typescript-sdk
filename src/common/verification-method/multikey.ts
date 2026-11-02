import { p256 } from '@noble/curves/nist';
import { decodeBase58Btc, encodeBase58Btc } from '../util/multibase';

/** p256-pub multicodec 0x1200 as varint 0x80 0x24 */
export const P256_PUB_MULTICODEC = new Uint8Array([0x80, 0x24]);

export function encodeP256PublicMultibase(uncompressedOrCompressed: Uint8Array): string {
  const point = p256.ProjectivePoint.fromHex(uncompressedOrCompressed);
  const compressed = point.toRawBytes(true);
  const raw = new Uint8Array(P256_PUB_MULTICODEC.length + compressed.length);
  raw.set(P256_PUB_MULTICODEC, 0);
  raw.set(compressed, P256_PUB_MULTICODEC.length);
  return encodeBase58Btc(raw);
}

export function decodeP256PublicMultibase(multibase: string): Uint8Array {
  const raw = decodeBase58Btc(multibase);
  if (raw.length < 3 || raw[0] !== 0x80 || raw[1] !== 0x24) {
    throw new Error('multikey: not a p256-pub multikey');
  }
  const compressed = raw.slice(2);
  return p256.ProjectivePoint.fromHex(compressed).toRawBytes(false);
}

export function isP256PublicMultibase(multibase: string): boolean {
  try {
    decodeP256PublicMultibase(multibase);
    return true;
  } catch {
    return false;
  }
}
