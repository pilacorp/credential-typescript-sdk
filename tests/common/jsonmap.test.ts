import { addECDSAProof } from '../../src/common/jsonmap/jsonmap';
import { SignerProvider } from '../../src/common/signer/signer';

class StubSigner implements SignerProvider {
  constructor(private readonly sig: Uint8Array) {}
  sign(): Uint8Array {
    return this.sig;
  }
}

describe('addECDSAProof signature length handling', () => {
  const baseDoc = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    issuer: 'did:example:issuer',
    type: 'VerifiableCredential',
  };

  it('issues a base58btc (multibase "z") proofValue for a 64-byte P-256 signature', async () => {
    const m = { ...baseDoc } as Record<string, unknown>;
    const sig = new Uint8Array(64).fill(0xab);
    await addECDSAProof(m, new StubSigner(sig), 'did:example:issuer#key-1', 'assertionMethod');
    const proof = m.proof as Record<string, unknown>;
    // Go no longer issues hex proofValues; ecdsa-rdfc-2019 is multibase base58btc.
    expect((proof.proofValue as string).startsWith('z')).toBe(true);
    expect(proof.cryptosuite).toBe('ecdsa-rdfc-2019');
    expect(proof.jws).toBeUndefined();
  });

  it('rejects a 65-byte signature (misrouted secp256k1 signer)', async () => {
    const m = { ...baseDoc } as Record<string, unknown>;
    const sig = new Uint8Array(65).fill(0xcd);
    await expect(
      addECDSAProof(m, new StubSigner(sig), 'did:example:issuer#key-1', 'assertionMethod'),
    ).rejects.toThrow(/64-byte P-256 signature/);
  });

  it('rejects an invalid signature length', async () => {
    const m = { ...baseDoc } as Record<string, unknown>;
    const sig = new Uint8Array(66);
    await expect(
      addECDSAProof(m, new StubSigner(sig), 'did:example:issuer#key-1', 'assertionMethod'),
    ).rejects.toThrow(/64-byte P-256 signature/);
  });
});
