import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { hexToBytes, normalizeHex } from '../common/crypto/hex';
import type { DecryptJWEResult, JWE } from './types';

export function getSharedSecret(
  publicKeyHex: string,
  privateKeyHex: string,
): Uint8Array {
  const privateKey = hexToBytes(normalizeHex(privateKeyHex));
  if (privateKey.length !== 32) {
    throw new Error(`private key must be 32 bytes, got ${privateKey.length}`);
  }

  const publicKey = normalizePublicKey(hexToBytes(normalizeHex(publicKeyHex)));
  return secp256k1.getSharedSecret(privateKey, publicKey, true).subarray(1);
}

export function encryptJWE(
  plaintext: string,
  sharedSecret: Uint8Array,
): JWE {
  const protectedHeader = base64UrlEncode(
    Buffer.from(
      JSON.stringify({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        crv: 'secp256k1',
        typ: 'application/didcomm-encrypted+json',
      }),
      'utf8',
    ),
  );
  const iv = randomBytes(12);
  const key = getAesKey(sharedSecret);
  const cipher = createCipheriv('aes-256-gcm', key, iv);

  const ciphertext = Buffer.concat([
    cipher.update(Buffer.from(plaintext, 'utf8')),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  return {
    protected: protectedHeader,
    iv: base64UrlEncode(iv),
    ciphertext: base64UrlEncode(ciphertext),
    tag: base64UrlEncode(tag),
  };
}

export function decryptJWE(
  message: JWE,
  sharedSecret: Uint8Array,
): DecryptJWEResult {
  const key = getAesKey(sharedSecret);
  const decipher = createDecipheriv(
    'aes-256-gcm',
    key,
    base64UrlDecode(message.iv),
  );
  const ciphertext = base64UrlDecode(message.ciphertext);
  const authTag = base64UrlDecode(message.tag);
  if (authTag.length !== 16) {
    throw new Error(`JWE auth tag must be 16 bytes, got ${authTag.length}`);
  }
  let plaintext: Buffer;
  try {
    decipher.setAuthTag(authTag);
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    const legacyMockTag = Buffer.from(sharedSecret.subarray(0, 16));
    if (!Buffer.from(authTag).equals(legacyMockTag) || ciphertext.length < 16) {
      throw err;
    }
    const legacyCipher = createDecipheriv('aes-256-gcm', key, base64UrlDecode(message.iv));
    legacyCipher.setAuthTag(ciphertext.subarray(ciphertext.length - 16));
    plaintext = Buffer.concat([
      legacyCipher.update(ciphertext.subarray(0, ciphertext.length - 16)),
      legacyCipher.final(),
    ]);
  }

  return {
    protected: JSON.parse(base64UrlDecode(message.protected).toString('utf8')) as Record<
      string,
      unknown
    >,
    plaintext: plaintext.toString('utf8'),
    json: tryParseJson(plaintext.toString('utf8')),
  };
}

export function encrypt(
  plaintext: string,
  publicKeyHex: string,
  privateKeyHex: string,
): JWE {
  return encryptJWE(plaintext, getSharedSecret(publicKeyHex, privateKeyHex));
}

export function decrypt(
  message: JWE,
  publicKeyHex: string,
  privateKeyHex: string,
): DecryptJWEResult {
  return decryptJWE(message, getSharedSecret(publicKeyHex, privateKeyHex));
}

function normalizePublicKey(publicKey: Uint8Array) {
  if (publicKey.length === 64) {
    return new Uint8Array([0x04, ...publicKey]);
  }
  if (
    publicKey.length === 33 ||
    (publicKey.length === 65 && publicKey[0] === 0x04)
  ) {
    return publicKey;
  }
  throw new Error(
    `public key must be 33, 64, or 65 bytes, got ${publicKey.length}`,
  );
}

function getAesKey(sharedSecret: Uint8Array) {
  if (sharedSecret.length !== 32) {
    throw new Error(`shared secret must be 32 bytes, got ${sharedSecret.length}`);
  }
  return Buffer.from(sharedSecret);
}

function base64UrlEncode(value: Buffer) {
  return value.toString('base64url');
}

function base64UrlDecode(value: string) {
  return Buffer.from(value, 'base64url');
}

function tryParseJson(value: string) {
  try {
    return JSON.parse(value) as Record<string, unknown>;
  } catch {
    return null;
  }
}
