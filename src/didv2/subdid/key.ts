import { hkdfSync } from 'node:crypto';
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes, normalizeHex } from '../../common/crypto/hex';
import { addressFromPublicKeyHex } from '../document';
import type { KeyPair } from '../types';
import { parseSubID } from './document';

const kdfSalt = 'subdid-keygen-v1';
const kdfInfoPrefix = 'subdid-key-v1';
const kdfLength = 48;

export function deriveSubDIDKey(rootPrivateKeyHex: string, subID: string): KeyPair {
  const root = hexToBytes(normalizeHex(rootPrivateKeyHex));
  if (root.length !== 32) throw new Error('subdid: root private key must be 32 bytes of hex');
  const rootScalar = BigInt(`0x${bytesToHex(root)}`);
  if (rootScalar === 0n || rootScalar >= secp256k1.CURVE.n) {
    throw new Error('subdid: root private key is out of range');
  }
  const id = parseSubID(subID);
  const okm = new Uint8Array(
    hkdfSync('sha256', Buffer.from(root), Buffer.from(kdfSalt), Buffer.from(kdfInfoPrefix + id), kdfLength),
  );
  const child = reduceToP256Scalar(okm);
  const secpPub = secp256k1.getPublicKey(child, true);
  const p256Pub = p256.getPublicKey(child, false);
  return {
    privateKeyHex: `0x${bytesToHex(child)}`,
    publicKeyHex: `0x${bytesToHex(secpPub)}`,
    address: addressFromPublicKeyHex(`0x${bytesToHex(secpPub)}`),
    p256PublicKeyXY: {
      x: bytesToHex(p256Pub.slice(1, 33)),
      y: bytesToHex(p256Pub.slice(33, 65)),
    },
  };
}

function reduceToP256Scalar(okm: Uint8Array): Uint8Array {
  const nMinusOne = p256.CURVE.n - 1n;
  let k = BigInt(`0x${bytesToHex(okm)}`) % nMinusOne;
  k += 1n;
  const hex = k.toString(16).padStart(64, '0');
  return hexToBytes(hex);
}
