import { integrity, load, staticResolver, ErrInvalid, ErrViolated } from '../../src/digitalcredential/typemeta';
import type { IssuedNode } from '../../src/common/sdjwt';
import { metadataURL, newResolver, StatusError } from '../../src/digitalcredential/issuermeta';
import { ErrNoUsableKey } from '../../src/digitalcredential/issuerkey';

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
    const disclosed = (fields?: Record<string, IssuedNode>): IssuedNode => ({
      disclosed: true,
      hidden: false,
      hiddenFields: 0,
      fields,
    });
    m.validateClaims(
      { given_name: 'Erika' },
      { issued: { disclosed: false, hidden: false, hiddenFields: 0, fields: { given_name: disclosed() } } },
    );
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

describe('typemeta documents', () => {
  it('refuses a document that is not valid UTF-8', () => {
    const doc = Buffer.concat([Buffer.from('{"vct":"https://t.example/v","name":"A'), Buffer.from([0xff]), Buffer.from('"}')]);
    expect(() => staticResolver(doc)).toThrow(/not valid UTF-8/);
  });
});

describe('issuermeta.metadataURL', () => {
  it('inserts /.well-known/jwt-vc-issuer between host and path', () => {
    expect(metadataURL('https://example.com/issuer')).toBe('https://example.com/.well-known/jwt-vc-issuer/issuer');
    expect(metadataURL('https://example.com/')).toBe('https://example.com/.well-known/jwt-vc-issuer');
  });

  it('refuses an iss path with a dot segment', () => {
    expect(() => metadataURL('https://example.com/a/../b')).toThrow(/"\." or "\.\."/);
  });

  it('accepts a percent-encoded byte that is not UTF-8 and keeps it as written', () => {
    // RFC 3986 §2.1: a percent-encoding names one octet, of any value.
    expect(metadataURL('https://example.com/%ff/x')).toBe('https://example.com/.well-known/jwt-vc-issuer/%ff/x');
    expect(() => metadataURL('https://example.com/%ff/%2e%2e/x')).toThrow(/"\." or "\.\."/);
  });
});

describe('content faults in fetched documents', () => {
  const bad = (prefix: string, suffix: string) => Buffer.concat([Buffer.from(prefix), Buffer.from([0xff]), Buffer.from(suffix)]);
  const serve = (docs: Record<string, Uint8Array>) =>
    newResolver({
      fetch: (async (url: string) => {
        const body = docs[url];
        if (!body) return new Response('', { status: 404 });
        return new Response(body as unknown as BodyInit, { status: 200, headers: { 'content-type': 'application/json' } });
      }) as never,
    });

  it('reports metadata that is not valid UTF-8 as a fault of the issuer', async () => {
    const r = serve({ 'https://issuer.example/.well-known/jwt-vc-issuer': bad('{"issuer":"https://issuer.example","x":"', '"}') });
    const err = await r.keys('https://issuer.example').catch((e: Error) => e);
    expect((err as Error).message).toMatch(/^issuermeta: the issuer metadata is not a JSON object: .*not valid UTF-8/);
    expect((err as Error & { cause?: unknown }).cause).toBe(ErrNoUsableKey);
  });

  it('reports a JWK Set from jwks_uri that is not valid UTF-8 as a fault of the issuer', async () => {
    const r = serve({
      'https://issuer.example/.well-known/jwt-vc-issuer': Buffer.from(
        JSON.stringify({ issuer: 'https://issuer.example', jwks_uri: 'https://issuer.example/jwks' }),
      ),
      'https://issuer.example/jwks': bad('{"keys":[],"x":"', '"}'),
    });
    const err = await r.keys('https://issuer.example').catch((e: Error) => e);
    expect((err as Error).message).toMatch(/^issuermeta: the JWK Set from jwks_uri is not a JSON object: .*not valid UTF-8/);
    expect((err as Error & { cause?: unknown }).cause).toBe(ErrNoUsableKey);
  });

  it('reports metadata naming another issuer as a fault of the issuer', async () => {
    const r = serve({
      'https://issuer.example/.well-known/jwt-vc-issuer': Buffer.from(
        JSON.stringify({ issuer: 'https://other.example', jwks: { keys: [] } }),
      ),
    });
    const err = await r.keys('https://issuer.example').catch((e: Error) => e);
    expect((err as Error & { cause?: unknown }).cause).toBe(ErrNoUsableKey);
  });

  const iss = 'https://issuer.example';
  const jwk = { kty: 'EC', crv: 'P-256', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0' };
  it.each<[string, Record<string, string>]>([
    ['metadata is null', { '': 'null' }],
    ['metadata is an array', { '': '[]' }],
    ['metadata is not JSON', { '': '{' }],
    ['no string issuer', { '': JSON.stringify({ issuer: 1, jwks: { keys: [] } }) }],
    ['both jwks and jwks_uri', { '': JSON.stringify({ issuer: iss, jwks: { keys: [] }, jwks_uri: `${iss}/jwks` }) }],
    ['neither jwks nor jwks_uri', { '': JSON.stringify({ issuer: iss }) }],
    ['jwks_uri is not a URI', { '': JSON.stringify({ issuer: iss, jwks_uri: 'not a uri' }) }],
    ['jwks_uri is not https', { '': JSON.stringify({ issuer: iss, jwks_uri: 'http://issuer.example/jwks' }) }],
    ['jwks_uri has a host the URL parser refuses', { '': JSON.stringify({ issuer: iss, jwks_uri: 'https://a%20b/k' }) }],
    ['JWK Set is null', { '': JSON.stringify({ issuer: iss, jwks_uri: `${iss}/jwks` }), '/jwks': 'null' }],
    ['JWK Set has no keys array', { '': JSON.stringify({ issuer: iss, jwks: {} }) }],
    ['a keys element is an array', { '': JSON.stringify({ issuer: iss, jwks: { keys: [[], jwk] } }) }],
  ])('reports a content fault of the issuer: %s', async (_name, docs) => {
    const served: Record<string, Uint8Array> = {};
    for (const [path, text] of Object.entries(docs)) {
      served[path === '' ? `${iss}/.well-known/jwt-vc-issuer` : `${iss}${path}`] = Buffer.from(text);
    }
    const err = await serve(served).keys(iss).catch((e: Error) => e);
    expect((err as Error).message).toMatch(/^issuermeta: /);
    expect((err as Error & { cause?: unknown }).cause).toBe(ErrNoUsableKey);
  });

  it('names jwks, not its keys, when jwks is an array', async () => {
    const r = serve({ [`${iss}/.well-known/jwt-vc-issuer`]: Buffer.from(JSON.stringify({ issuer: iss, jwks: [] })) });
    await expect(r.keys(iss)).rejects.toThrow('issuermeta: jwks is not a JSON object');
  });

  it('keeps a failure to reach the issuer apart from a content fault', async () => {
    const err = await serve({}).keys(iss).catch((e: Error) => e);
    expect(err).toBeInstanceOf(StatusError);
    expect((err as Error & { cause?: unknown }).cause).not.toBe(ErrNoUsableKey);
  });

  it('reports a resolved Type Metadata document that is not valid UTF-8 as invalid', async () => {
    const r = { metadata: async () => bad('{"vct":"https://t.example/v","name":"', '"}') };
    const err = await load(r, { vct: 'https://t.example/v' }).catch((e: Error) => e);
    expect((err as Error).message).toMatch(/^typemeta: .*not valid UTF-8/);
    expect((err as Error & { cause?: unknown }).cause).toBe(ErrInvalid);
  });
});
