import {
  bundledContextUrls,
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
