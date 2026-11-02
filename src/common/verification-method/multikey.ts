import { p256 } from '@noble/curves/nist';
import { decodeBase58Btc, encodeBase58Btc } from '../util/multibase';

/** p256-pub multicodec 0x1200 as varint 0x80 0x24 */
export const P256_PUB_MULTICODEC = new Uint8Array([0x80, 0x24]);
/** p256-priv multicodec as varint 0x86 0x26 */
export const P256_PRIV_MULTICODEC = new Uint8Array([0x86, 0x26]);

export function encodeP256PublicMultikeyBytes(uncompressedOrCompressed: Uint8Array): Uint8Array {
  const point = p256.ProjectivePoint.fromHex(uncompressedOrCompressed);
  const compressed = point.toRawBytes(true);
  const raw = new Uint8Array(P256_PUB_MULTICODEC.length + compressed.length);
  raw.set(P256_PUB_MULTICODEC, 0);
  raw.set(compressed, P256_PUB_MULTICODEC.length);
  return raw;
}

export function decodeP256PublicMultikeyBytes(raw: Uint8Array): Uint8Array {
  if (raw.length < 3 || raw[0] !== 0x80 || raw[1] !== 0x24) {
    throw new Error('multikey: not a p256-pub multikey');
  }
  const compressed = raw.slice(2);
  if (compressed.length !== 33) {
    throw new Error(`multikey: unexpected p256-pub length ${raw.length}, trailing bytes not allowed`);
  }
  return p256.ProjectivePoint.fromHex(compressed).toRawBytes(false);
}

export function decodeP256SecretMultibase(multibase: string): Uint8Array {
  const raw = decodeBase58Btc(multibase);
  if (raw.length < 3 || raw[0] !== 0x86 || raw[1] !== 0x26) {
    throw new Error('multikey: not a p256-priv multikey');
  }
  const d = raw.slice(2);
  if (d.length !== 32) {
    throw new Error(`multikey: p256 secret key must be 32 bytes, got ${d.length}`);
  }
  return d;
}

export function encodeP256PublicMultibase(uncompressedOrCompressed: Uint8Array): string {
  return encodeBase58Btc(encodeP256PublicMultikeyBytes(uncompressedOrCompressed));
}

export function decodeP256PublicMultibase(multibase: string): Uint8Array {
  return decodeP256PublicMultikeyBytes(decodeBase58Btc(multibase));
}

export function isP256PublicMultibase(multibase: string): boolean {
  try {
    decodeP256PublicMultibase(multibase);
    return true;
  } catch {
    return false;
  }
}
