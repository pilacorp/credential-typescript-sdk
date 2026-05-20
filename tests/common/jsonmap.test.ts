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

  it('accepts 64-byte signature', async () => {
    const m = { ...baseDoc } as Record<string, unknown>;
    const sig = new Uint8Array(64).fill(0xab);
    await addECDSAProof(m, new StubSigner(sig), 'did:example:issuer#key-1', 'assertionMethod');
    const proof = m.proof as Record<string, unknown>;
    expect((proof.proofValue as string).length).toBe(128);
  });

  it('accepts 65-byte signature', async () => {
    const m = { ...baseDoc } as Record<string, unknown>;
    const sig = new Uint8Array(65).fill(0xcd);
    await addECDSAProof(m, new StubSigner(sig), 'did:example:issuer#key-1', 'assertionMethod');
    const proof = m.proof as Record<string, unknown>;
    expect((proof.proofValue as string).length).toBe(130);
  });

  it('rejects invalid signature length', async () => {
    const m = { ...baseDoc } as Record<string, unknown>;
    const sig = new Uint8Array(66);
    await expect(
      addECDSAProof(m, new StubSigner(sig), 'did:example:issuer#key-1', 'assertionMethod'),
    ).rejects.toThrow(/invalid signature length/);
  });
});
