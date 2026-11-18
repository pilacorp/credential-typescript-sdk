/**
 * termsOfUse and renderMethod (VC 2.0) — preserved through create/serialize and
 * covered by the Data Integrity signature. Reference: Go CredentialContents
 * TermsOfUse + serializeTermsOfUse; renderMethod rides the v2 @context into
 * canonicalization just like any other defined term.
 */
import { p256 } from '@noble/curves/nist';
import { hexToBytes } from '../../src/common/crypto/hex';
import { P256Provider } from '../../src/common/signer/p256-provider';
import { encodeP256PublicMultibase } from '../../src/common/verification-method/multikey';
import { DIDDocument, ResolverProvider } from '../../src/common/verification-method';
import { JSONCredential } from '../../src/vc/json-credential';
import { parseCredential } from '../../src/vc/credential';
import type { CredentialData } from '../../src/vc/types';

const ISSUER = 'did:example:p256-issuer';
const SUBJECT = 'did:example:subject';
const P256_PRIV = '1111111111111111111111111111111111111111111111111111111111111111';
const V2 = 'https://www.w3.org/ns/credentials/v2';

class StaticResolver implements ResolverProvider {
  constructor(private readonly doc: DIDDocument) {}
  async resolveDocument(): Promise<DIDDocument> {
    return this.doc;
  }
}

function p256Did(): DIDDocument {
  const pub = p256.getPublicKey(hexToBytes(P256_PRIV), false);
  return {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/v1', 'https://www.w3.org/ns/cid/v1'],
    id: ISSUER,
    verificationMethod: [
      { id: `${ISSUER}#key-2`, type: 'Multikey', controller: ISSUER, publicKeyMultibase: encodeP256PublicMultibase(pub) },
    ],
    authentication: [`${ISSUER}#key-2`],
    assertionMethod: [`${ISSUER}#key-2`],
  };
}

describe('termsOfUse and renderMethod', () => {
  const resolver = new StaticResolver(p256Did());

  it('requires a type on each termsOfUse entry', async () => {
    await expect(
      JSONCredential.create(
        {
          context: [V2],
          types: ['VerifiableCredential'],
          issuer: ISSUER,
          subject: [{ id: SUBJECT }],
          termsOfUse: [{ type: '' }],
        },
        { resolver },
      ),
    ).rejects.toThrow(/termsOfUse\[0\]\.type is required/);
  });

  it('carries termsOfUse into the signed document and covers it', async () => {
    const cred = await JSONCredential.create(
      {
        // @vocab makes the undeclared policy type canonicalize to an absolute
        // IRI (see Go TestTermsOfUse_CanonicalizationProducesAbsoluteIRIs).
        context: [V2, { '@vocab': 'https://example.com/vocab#' }],
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        subject: [{ id: SUBJECT }],
        termsOfUse: [{ id: 'https://example.com/policy/1', type: 'IssuerPolicy' }],
      },
      { verificationMethodKey: 'key-2', resolver },
    );
    await cred.addProofByProvider(new P256Provider(P256_PRIV), { resolver });
    const doc = (await cred.serialize()) as CredentialData;

    const terms = doc.termsOfUse as Array<Record<string, unknown>>;
    expect(terms[0]).toEqual({ id: 'https://example.com/policy/1', type: 'IssuerPolicy' });

    const serialized = JSON.stringify(doc);
    await expect(parseCredential(serialized, { resolver }).then((c) => c.verify({ resolver }))).resolves.toBeUndefined();

    // Tampering termsOfUse breaks the signature → it is covered.
    const tampered = JSON.parse(serialized) as CredentialData;
    (tampered.termsOfUse as Array<Record<string, unknown>>)[0].type = 'ForgedPolicy';
    await expect(parseCredential(JSON.stringify(tampered), { resolver }).then((c) => c.verify({ resolver }))).rejects.toThrow();
  });

  it('preserves renderMethod through sign/serialize/verify and covers it', async () => {
    // renderMethod has no struct field (neither does Go); it rides in the raw
    // document map and is defined in the v2 @context, so canonicalization keeps it.
    const document: CredentialData = {
      '@context': [V2],
      type: ['VerifiableCredential'],
      issuer: ISSUER,
      credentialSubject: { id: SUBJECT },
      renderMethod: 'https://example.com/render/template.svg',
    };
    const cred = new JSONCredential(document, 'key-2');
    await cred.addProofByProvider(new P256Provider(P256_PRIV), { resolver });
    const serialized = JSON.stringify(await cred.serialize());

    expect(JSON.parse(serialized).renderMethod).toBe('https://example.com/render/template.svg');
    await expect(parseCredential(serialized, { resolver }).then((c) => c.verify({ resolver }))).resolves.toBeUndefined();

    const tampered = JSON.parse(serialized) as CredentialData;
    tampered.renderMethod = 'https://attacker.example/evil.svg';
    await expect(parseCredential(JSON.stringify(tampered), { resolver }).then((c) => c.verify({ resolver }))).rejects.toThrow();
  });
});
