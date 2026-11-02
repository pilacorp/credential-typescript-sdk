import { integrity, load, staticResolver, ErrViolated } from '../../src/digitalcredential/typemeta';
import { metadataURL } from '../../src/digitalcredential/issuermeta';

describe('typemeta', () => {
  it('loads a static document and checks a mandatory claim', async () => {
    const doc = Buffer.from(
      JSON.stringify({
        vct: 'https://credentials.example/identity_credential',
        name: 'Identity',
        claims: [{ path: ['given_name'], mandatory: true, sd: 'always' }],
      }),
    );
    const r = staticResolver(doc);
    const m = await load(r, { vct: 'https://credentials.example/identity_credential', integrity: integrity(doc) });
    expect(m.vct).toBe('https://credentials.example/identity_credential');
    expect(m.chain).toEqual(['https://credentials.example/identity_credential']);
    m.validateClaims({ given_name: 'Erika' });
    try {
      m.validateClaims({ family_name: 'Mustermann' });
      throw new Error('expected violation');
    } catch (err) {
      expect((err as { cause?: unknown }).cause).toBe(ErrViolated);
    }
  });

  it('merges extends: nearer display wins', async () => {
    const parent = Buffer.from(
      JSON.stringify({
        vct: 'https://example.com/parent',
        display: [{ locale: 'en', name: 'Parent' }],
        claims: [{ path: ['a'], mandatory: true }],
      }),
    );
    const child = Buffer.from(
      JSON.stringify({
        vct: 'https://example.com/child',
        extends: 'https://example.com/parent',
        display: [{ locale: 'en', name: 'Child' }],
        claims: [{ path: ['b'] }],
      }),
    );
    const m = await load(staticResolver(parent, child), { vct: 'https://example.com/child' });
    expect(m.chain).toEqual(['https://example.com/child', 'https://example.com/parent']);
    expect(m.display[0].name).toBe('Child');
    expect(m.claims.map((c) => c.path[0])).toEqual(['a', 'b']);
  });
});

describe('issuermeta.metadataURL', () => {
  it('inserts /.well-known/jwt-vc-issuer between host and path', () => {
    expect(metadataURL('https://example.com/issuer')).toBe('https://example.com/.well-known/jwt-vc-issuer/issuer');
    expect(metadataURL('https://example.com/')).toBe('https://example.com/.well-known/jwt-vc-issuer');
  });
});
