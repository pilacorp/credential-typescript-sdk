import {
  bundledContextUrls,
  canonicalizeDocument,
  canonicalizeRDF,
  expandJSONLD,
  registerContext,
  withDocumentLoader,
} from '../../src/common/processor/processor';

describe('JSON-LD document loader', () => {
  afterEach(() => {
    withDocumentLoader(null);
  });

  it('bundles Go-equivalent well-known contexts', () => {
    expect(bundledContextUrls()).toEqual(
      expect.arrayContaining([
        'https://www.w3.org/2018/credentials/v1',
        'https://www.w3.org/ns/credentials/v2',
        'https://w3id.org/security/v1',
        'https://w3id.org/security/v2',
        'https://w3id.org/security/data-integrity/v2',
        'https://w3id.org/security/suites/secp256k1-2019/v1',
      ]),
    );
  });

  it('serves a registered custom context without network', async () => {
    registerContext('https://example.test/vocab', {
      '@context': { customTerm: 'https://example.test/vocab#customTerm' },
    });
    const nq = await canonicalizeRDF({
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://example.test/vocab'],
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:subject', customTerm: 'hello' },
    });
    expect(Buffer.from(nq).toString('utf8')).toContain('customTerm');
  });

  it('rejects undefined types and relative ids', async () => {
    await expect(
      expandJSONLD({
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['NotADefinedType'],
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' },
      }),
    ).rejects.toThrow(/not defined by @context|Safe mode/);
    await expect(
      expandJSONLD({
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'relative-id',
        type: ['VerifiableCredential'],
        issuer: 'did:example:issuer',
        credentialSubject: { id: 'did:example:subject' },
      }),
    ).rejects.toThrow(/not an absolute IRI|Safe mode/);
  });
});

// Expected bytes come from go-credential-sdk 20a302e (json-gold v0.7.0) on the same documents.
describe('@import', () => {
  const contexts: Record<string, unknown> = {"https://ex.test/inner": {"@context": {"@vocab": "https://ex.test/v#", "n": "https://ex.test/n"}}, "https://ex.test/nested": {"@context": {"@import": "https://ex.test/inner", "m": "https://ex.test/m"}}};
  beforeEach(() => {
    withDocumentLoader((url) => {
      if (!(url in contexts)) throw new Error(`no network in tests: ${url}`);
      return { contextUrl: null, documentUrl: url, document: JSON.parse(JSON.stringify(contexts[url])) };
    });
  });
  afterEach(() => withDocumentLoader(null));
  const text = (b: Uint8Array) => Buffer.from(b).toString('utf8');

  it('signs a @json value holding @context and @import as written', async () => {
    const doc = {"@context": {"@vocab": "https://ex.test/v#", "j": {"@id": "https://ex.test/v#j", "@type": "@json"}}, "@id": "urn:x:2", "j": {"@context": {"@import": "https://ctx.test/imp"}, "k": 1}};
    expect(text(await canonicalizeRDF(JSON.parse(JSON.stringify(doc))))).toBe("<urn:x:2> <https://ex.test/v#j> \"{\\\"@context\\\":{\\\"@import\\\":\\\"https://ctx.test/imp\\\"},\\\"k\\\":1}\"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> .\n");
    expect(text(await canonicalizeDocument(JSON.parse(JSON.stringify(doc))))).toBe("<urn:x:2> <https://ex.test/v#j> \"{\\\"@context\\\":{\\\"@import\\\":\\\"https://ctx.test/imp\\\"},\\\"k\\\":{\\\"@type\\\":\\\"http://www.w3.org/2001/XMLSchema#string\\\",\\\"@value\\\":\\\"1\\\"}}\"^^<http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON> .\n");
  });

  it('merges an @import found inside a remote context', async () => {
    const doc = {"@context": ["https://www.w3.org/ns/credentials/v2", "https://ex.test/nested"], "id": "urn:uuid:1", "type": ["VerifiableCredential"], "issuer": "did:example:issuer", "credentialSubject": {"id": "did:example:s", "n": "x", "m": "y"}};
    expect(text(await canonicalizeRDF(doc))).toBe("<did:example:s> <https://ex.test/m> \"y\" .\n<did:example:s> <https://ex.test/n> \"x\" .\n<urn:uuid:1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n<urn:uuid:1> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:s> .\n<urn:uuid:1> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer> .\n");
  });

  it('lets local definitions win over imported ones', async () => {
    const doc = {"@context": ["https://www.w3.org/ns/credentials/v2", {"@version": 1.1, "@import": "https://ex.test/inner", "n": "https://ex.test/local-n", "@vocab": "https://ex.test/local#"}], "id": "urn:uuid:1", "type": ["VerifiableCredential"], "issuer": "did:example:issuer", "credentialSubject": {"id": "did:example:s", "n": "x", "free": "y"}};
    expect(text(await canonicalizeRDF(doc))).toBe("<did:example:s> <https://ex.test/local#free> \"y\" .\n<did:example:s> <https://ex.test/local-n> \"x\" .\n<urn:uuid:1> <http://www.w3.org/1999/02/22-rdf-syntax-ns#type> <https://www.w3.org/2018/credentials#VerifiableCredential> .\n<urn:uuid:1> <https://www.w3.org/2018/credentials#credentialSubject> <did:example:s> .\n<urn:uuid:1> <https://www.w3.org/2018/credentials#issuer> <did:example:issuer> .\n");
  });

  it('loads a scoped @import once per operation, however often the term is used', async () => {
    const loads: string[] = [];
    withDocumentLoader((url) => {
      loads.push(url);
      return { contextUrl: null, documentUrl: url, document: JSON.parse(JSON.stringify(contexts[url])) };
    });
    const doc = {
      '@context': { '@version': 1.1, p: { '@id': 'https://ex.test/p', '@context': { '@import': 'https://ex.test/inner' } } },
      '@id': 'urn:x:1',
      p: Array.from({ length: 50 }, (_, i) => ({ '@id': `urn:y:${i}`, n: 'x' })),
    };
    await canonicalizeRDF(doc);
    expect(loads.filter((u) => u === 'https://ex.test/inner')).toHaveLength(1);
  });

  it('refuses an @import target that has an @import of its own', async () => {
    const doc = {"@context": ["https://www.w3.org/ns/credentials/v2", {"@version": 1.1, "@import": "https://ex.test/nested"}], "id": "urn:uuid:1", "type": ["VerifiableCredential"], "issuer": "did:example:issuer", "credentialSubject": {"id": "did:example:s", "n": "x", "m": "y"}};
    await expect(canonicalizeRDF(doc)).rejects.toThrow(/@import/);
  });
});
