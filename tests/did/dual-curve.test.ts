import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import {
  DIDGenerator,
  generateDualCurveKeyPair,
  validateDidDocument,
} from '../../src/did';
import { hexToBytes, normalizeHex } from '../../src/common/crypto/hex';
import { encodeP256PublicMultibase } from '../../src/common/verification-method/multikey';

describe('generateDualCurveKeyPair', () => {
  it('reuses one P-256 scalar on secp256k1', () => {
    const dual = generateDualCurveKeyPair();
    expect(dual.secp256k1.privateKeyHex).toBe(dual.p256.privateKeyHex);
    const scalar = hexToBytes(normalizeHex(dual.p256.privateKeyHex));
    expect(Buffer.from(secp256k1.getPublicKey(scalar, false)).toString('hex')).toBe(
      normalizeHex(dual.secp256k1.publicKeyHex),
    );
    expect(Buffer.from(p256.getPublicKey(scalar, false)).toString('hex')).toBe(
      normalizeHex(dual.p256.publicKeyHex),
    );
  });
});

describe('DIDGenerator withP256', () => {
  it('returns the P-256 private key that matches #key-2', async () => {
    const generator = new DIDGenerator({
      chainId: 6789,
      didAddress: '0x0000000000000000000000000000000000018888',
      method: 'did:nda',
    });
    const generated = await generator.generateDID({ type: 'people', withP256: true });
    expect(generated.secret.p256PrivateKeyHex).toBe(generated.secret.privateKeyHex);
    expect(generated.document.verificationMethod).toHaveLength(2);
    const vm = generated.document.verificationMethod[1];
    const pub = p256.getPublicKey(hexToBytes(normalizeHex(generated.secret.p256PrivateKeyHex!)), false);
    expect(vm.publicKeyMultibase).toBe(encodeP256PublicMultibase(pub));
    validateDidDocument(generated.document);
  });
});

describe('validateDidDocument', () => {
  it('rejects duplicate VM ids and type/material mismatch', () => {
    expect(() =>
      validateDidDocument({
        '@context': [],
        id: 'did:example:x',
        verificationMethod: [
          {
            id: 'did:example:x#key-1',
            type: 'Multikey',
            controller: 'did:example:x',
            publicKeyHex: '0x04' + '11'.repeat(32),
          },
        ],
        authentication: ['did:example:x#key-1'],
        assertionMethod: ['did:example:x#key-1'],
      }),
    ).toThrow(/does not match its key material/);
  });
});
