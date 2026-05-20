import { selectVMForPurpose, selectLatestActiveVMForPurpose } from '../../src/common/verification-method/selector';
import { normalizeVerificationMethodURL, resolveVerificationMethodURL } from '../../src/common/verification-method/resolve-vm-url';
import { ResolverProvider } from '../../src/common/verification-method/provider';
import { DIDDocument } from '../../src/common/verification-method/verification-method';

const did = 'did:pila:abc123';

class StubResolver implements ResolverProvider {
  constructor(private readonly doc: DIDDocument | null, private readonly err: Error | null = null) {}
  async resolveDocument(): Promise<DIDDocument> {
    if (this.err) throw this.err;
    if (!this.doc) throw new Error('no doc');
    return this.doc;
  }
}

describe('normalizeVerificationMethodURL', () => {
  it.each([
    ['', ''],
    ['did:pila:abc123#key-1', 'did:pila:abc123#key-1'],
    ['#key-1', `${did}#key-1`],
    ['key-2', `${did}#key-2`],
  ])('normalizes %s', (input, want) => {
    expect(normalizeVerificationMethodURL(did, input)).toBe(want);
  });
});

describe('selectVMForPurpose', () => {
  const doc: DIDDocument = {
    '@context': [],
    id: did,
    verificationMethod: [
      { id: `${did}#key-1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: did },
      { id: `${did}#key-2`, type: 'EcdsaSecp256k1VerificationKey2019', controller: did },
    ],
    authentication: [`${did}#key-1`, `${did}#key-2`],
    assertionMethod: [`${did}#key-1`],
  };

  it.each([
    ['full URL', `${did}#key-1`, `${did}#key-1`],
    ['hash fragment', '#key-2', `${did}#key-2`],
    ['bare fragment', 'key-2', `${did}#key-2`],
  ])('accepts %s kid form', (_label, kid, want) => {
    const vm = selectVMForPurpose(doc, 'authentication', kid);
    expect(vm.id).toBe(want);
  });

  it('throws when kid is not found', () => {
    expect(() => selectVMForPurpose(doc, 'authentication', '#key-9')).toThrow();
  });

  it('falls back to latest active VM when kid empty', () => {
    const vm = selectVMForPurpose(doc, 'authentication', '');
    expect(vm.id).toBe(`${did}#key-2`);
  });
});

describe('selectLatestActiveVMForPurpose', () => {
  it('skips revoked VM with hard reason', () => {
    const revokedAt = new Date(Date.UTC(2026, 0, 1));
    const doc: DIDDocument = {
      '@context': [],
      id: did,
      verificationMethod: [
        { id: `${did}#key-1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: did },
        {
          id: `${did}#key-2`,
          type: 'EcdsaSecp256k1VerificationKey2019',
          controller: did,
          revoked: revokedAt,
          revocationReason: 'keyCompromise',
        },
      ],
      authentication: [`${did}#key-1`, `${did}#key-2`],
      assertionMethod: [],
    };
    const vm = selectLatestActiveVMForPurpose(doc, 'authentication');
    expect(vm.id).toBe(`${did}#key-1`);
  });
});

describe('resolveVerificationMethodURL', () => {
  const doc: DIDDocument = {
    '@context': [],
    id: did,
    verificationMethod: [
      { id: `${did}#key-1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: did },
      { id: `${did}#key-2`, type: 'EcdsaSecp256k1VerificationKey2019', controller: did },
    ],
    authentication: [`${did}#key-1`, `${did}#key-2`],
    assertionMethod: [`${did}#key-1`],
  };

  it('picks highest key-N for authentication', async () => {
    const got = await resolveVerificationMethodURL(did, 'authentication', new StubResolver(doc));
    expect(got).toBe(`${did}#key-2`);
  });

  it('returns single assertionMethod entry', async () => {
    const got = await resolveVerificationMethodURL(did, 'assertionMethod', new StubResolver(doc));
    expect(got).toBe(`${did}#key-1`);
  });

  it('throws when resolver is null', async () => {
    await expect(resolveVerificationMethodURL(did, 'authentication', null)).rejects.toThrow();
  });

  it('throws when purpose is unsupported', async () => {
    await expect(
      resolveVerificationMethodURL(did, 'keyAgreement', new StubResolver(doc)),
    ).rejects.toThrow(/unsupported purpose/);
  });
});
