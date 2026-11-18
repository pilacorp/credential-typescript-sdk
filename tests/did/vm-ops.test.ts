import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/nist';
import { bytesToHex } from '../../src/common/crypto/hex';
import { encodeP256PublicMultibase } from '../../src/common/verification-method/multikey';
import { buildDidDocument } from '../../src/did/did';
import {
  addVerificationMethod,
  addVerificationMethodPurposes,
  removeVerificationMethodPurposes,
  revokeVerificationMethod,
  rotateVerificationMethod,
} from '../../src/did/vm-ops';

const DID = 'did:nda:0x0000000000000000000000000000000000000001';

function secpHex(seed: number): string {
  const priv = new Uint8Array(32).fill(seed);
  priv[31] = seed;
  return `0x${bytesToHex(secp256k1.getPublicKey(priv, true))}`;
}

describe('DIDv2 verification-method mutation', () => {
  it('adds sequential ids, copies purposes on rotate, and keeps revoked VMs', () => {
    const doc = buildDidDocument(secpHex(1), DID);
    const id2 = addVerificationMethod(doc, { publicKeyHex: secpHex(2) }, ['authentication']);
    expect(id2).toBe(`${DID}#key-2`);
    expect(doc.authentication).toContain(id2);

    const newId = rotateVerificationMethod(doc, `${DID}#key-1`, { publicKeyHex: secpHex(3) });
    expect(newId).toBe(`${DID}#key-3`);
    const old = doc.verificationMethod.find((vm) => vm.id === `${DID}#key-1`)!;
    expect(old.revoked).toBeInstanceOf(Date);
    expect(old.revocationReason).toBe('superseded');
    expect(doc.authentication).toContain(newId);
    expect(doc.assertionMethod).toContain(newId);
    expect(doc.verificationMethod.some((vm) => vm.id === `${DID}#key-1`)).toBe(true);
    expect(doc['@context']).toContain('https://www.w3.org/ns/cid/v1');
  });

  it('rejects duplicate ids, second revoke, and new purposes on revoked VMs', () => {
    const doc = buildDidDocument(secpHex(1), DID);
    expect(() =>
      addVerificationMethod(doc, { id: '#key-1', publicKeyHex: secpHex(2) }),
    ).toThrow(/already exists/);
    revokeVerificationMethod(doc, '#key-1', 'compromised');
    expect(() => revokeVerificationMethod(doc, '#key-1', 'again')).toThrow(/already revoked/);
    expect(() =>
      addVerificationMethodPurposes(doc, '#key-1', ['authentication']),
    ).toThrow(/is revoked/);
  });

  it('dedupes purpose refs and adds CID context for Multikey', () => {
    const doc = buildDidDocument(secpHex(1), DID);
    addVerificationMethodPurposes(doc, '#key-1', ['authentication', 'assertionMethod']);
    expect(doc.authentication).toHaveLength(1);
    const pub = p256.getPublicKey(p256.utils.randomPrivateKey(), false);
    const id = addVerificationMethod(
      doc,
      { publicKeyMultibase: encodeP256PublicMultibase(pub) },
      ['assertionMethod'],
    );
    expect(id).toBe(`${DID}#key-2`);
    expect(doc['@context']).toContain('https://www.w3.org/ns/cid/v1');
    removeVerificationMethodPurposes(doc, '#key-2', ['assertionMethod']);
    expect(doc.assertionMethod).not.toContain(id);
  });
});
