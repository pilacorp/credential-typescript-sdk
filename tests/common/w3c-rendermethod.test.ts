import { readFileSync } from 'fs';
import { join } from 'path';
import { JSONCredential } from '../../src/vc/json-credential';
import { canonicalizeDocument } from '../../src/common/processor/processor';
import w3cV2 from '../../src/common/processor/w3c.credential.v2.json';

const RENDER_IRI = 'https://www.w3.org/2018/credentials#renderMethod';

const withExamplesContext = {
  '@context': [
    'https://www.w3.org/ns/credentials/v2',
    'https://www.w3.org/ns/credentials/examples/v2',
  ],
  id: 'urn:uuid:3978344f-8596-4c3a-a978-8fcaba3903c5',
  type: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  credentialSubject: { id: 'did:example:subject', name: 'Alice' },
  renderMethod: {
    id: 'https://example.com/render-method',
    type: 'SuiteRenderMethod',
    renderSuite: 'html',
    renderProperty: ['/credentialSubject/name'],
    template: {
      id: 'https://example.com/templates/name.html',
      mediaType: 'text/html',
    },
  },
};

const v2OnlyContext = {
  ...withExamplesContext,
  '@context': ['https://www.w3.org/ns/credentials/v2'],
};

describe('W3C v2 renderMethod context', () => {
  it('defines renderMethod in the bundled credentials/v2 document', () => {
    const vc = (w3cV2 as { '@context': { VerifiableCredential: { '@context': Record<string, unknown> } } })
      ['@context'].VerifiableCredential['@context'];
    expect(vc.renderMethod).toEqual({
      '@id': RENDER_IRI,
      '@type': '@id',
    });
  });

  it('keeps the on-disk context term in sync with the import', () => {
    const onDisk = JSON.parse(
      readFileSync(
        join(__dirname, '../../src/common/processor/w3c.credential.v2.json'),
        'utf8',
      ),
    );
    expect(onDisk['@context'].VerifiableCredential['@context'].renderMethod['@id']).toBe(
      RENDER_IRI,
    );
  });

  it('canonicalizes a credential that uses renderMethod with v2 + examples/v2', async () => {
    const nquads = Buffer.from(await canonicalizeDocument(withExamplesContext)).toString('utf8');
    expect(nquads).toContain(`<${RENDER_IRI}>`);
    expect(nquads).toContain('https://www.w3.org/ns/credentials/examples#SuiteRenderMethod');
    expect(nquads).toContain('https://www.w3.org/ns/credentials/examples#renderSuite');

    const cred = await JSONCredential.parse(JSON.stringify(withExamplesContext));
    const digest = await cred.getSigningInput();
    expect(digest.byteLength).toBe(32);
  });

  it('still canonicalizes when examples/v2 is omitted (terms may drop)', async () => {
    const nquads = Buffer.from(await canonicalizeDocument(v2OnlyContext)).toString('utf8');
    expect(nquads).toContain(`<${RENDER_IRI}>`);
    expect(nquads).not.toContain('SuiteRenderMethod');

    // getSigningInput now uses the native, safe-mode canonicalizer (Go's
    // DocumentDigest), so a credential whose example-specific terms
    // (SuiteRenderMethod, renderSuite, ...) are undefined without examples/v2
    // cannot produce a signing input — those terms would be dropped unsigned.
    const cred = await JSONCredential.parse(JSON.stringify(v2OnlyContext));
    await expect(cred.getSigningInput()).rejects.toThrow();
  });
});
