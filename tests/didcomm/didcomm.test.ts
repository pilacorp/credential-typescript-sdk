import { secp256k1 } from '@noble/curves/secp256k1';
import {
  decrypt,
  decryptJWE,
  encrypt,
  encryptJWE,
  getSharedSecret,
} from '../../src/didcomm';
import { hexToBytes } from '../../src/common/crypto/hex';

describe('didcomm', () => {
  it('derives the same shared secret from both sides', () => {
    const alicePriv = hexToBytes(
      '1111111111111111111111111111111111111111111111111111111111111111',
    );
    const bobPriv = hexToBytes(
      '2222222222222222222222222222222222222222222222222222222222222222',
    );
    const alicePub = Buffer.from(secp256k1.getPublicKey(alicePriv, true)).toString(
      'hex',
    );
    const bobPub = Buffer.from(secp256k1.getPublicKey(bobPriv, true)).toString(
      'hex',
    );

    const aliceSecret = getSharedSecret(bobPub, Buffer.from(alicePriv).toString('hex'));
    const bobSecret = getSharedSecret(alicePub, Buffer.from(bobPriv).toString('hex'));

    expect(Buffer.from(aliceSecret).toString('hex')).toBe(
      Buffer.from(bobSecret).toString('hex'),
    );
  });

  it('round-trips a DIDComm JWE payload', () => {
    const alicePriv = hexToBytes(
      '1111111111111111111111111111111111111111111111111111111111111111',
    );
    const bobPriv = hexToBytes(
      '2222222222222222222222222222222222222222222222222222222222222222',
    );
    const alicePub = Buffer.from(secp256k1.getPublicKey(alicePriv, true)).toString(
      'hex',
    );
    const bobPub = Buffer.from(secp256k1.getPublicKey(bobPriv, true)).toString(
      'hex',
    );

    const message = encrypt(
      JSON.stringify({ hello: 'world' }),
      bobPub,
      Buffer.from(alicePriv).toString('hex'),
    );
    const decrypted = decrypt(
      message,
      alicePub,
      Buffer.from(bobPriv).toString('hex'),
    );

    expect(decrypted.protected).toEqual({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      crv: 'secp256k1',
      typ: 'application/didcomm-encrypted+json',
    });
    expect(decrypted.plaintext).toBe('{"hello":"world"}');
    expect(decrypted.json).toEqual({ hello: 'world' });
  });

  it('supports encrypt/decrypt with a precomputed shared secret', () => {
    const alicePriv = hexToBytes(
      '1111111111111111111111111111111111111111111111111111111111111111',
    );
    const bobPriv = hexToBytes(
      '2222222222222222222222222222222222222222222222222222222222222222',
    );
    const alicePub = Buffer.from(secp256k1.getPublicKey(alicePriv, true)).toString(
      'hex',
    );
    const secret = getSharedSecret(
      alicePub,
      Buffer.from(bobPriv).toString('hex'),
    );

    const message = encryptJWE('plain-text', secret);
    const decrypted = decryptJWE(message, secret);

    expect(decrypted.plaintext).toBe('plain-text');
    expect(decrypted.json).toBeNull();
  });

  it('authenticates the JWE tag field', () => {
    const secret = new Uint8Array(32).fill(7);
    const message = encryptJWE('authenticated', secret);
    const tag = Buffer.from(message.tag, 'base64url');
    const ciphertext = Buffer.from(message.ciphertext, 'base64url');
    expect(tag).toHaveLength(16);
    expect(ciphertext).toHaveLength(Buffer.byteLength('authenticated'));

    const legacyMessage = {
      ...message,
      ciphertext: Buffer.concat([ciphertext, tag]).toString('base64url'),
      tag: Buffer.from(secret.subarray(0, 16)).toString('base64url'),
    };
    expect(decryptJWE(legacyMessage, secret).plaintext).toBe('authenticated');

    message.tag = Buffer.from(tag.map((byte, index) => index === 0 ? byte ^ 1 : byte)).toString('base64url');
    expect(() => decryptJWE(message, secret)).toThrow();
  });
});
