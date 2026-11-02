import { readFileSync } from 'fs';
import { join } from 'path';
import { p256 } from '@noble/curves/nist';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import { P256Provider } from '../../src/common/signer/p256-provider';
import {
  DIDDocument,
  ResolverProvider,
} from '../../src/common/verification-method';
import { decodeP256SecretMultibase, encodeP256PublicMultibase } from '../../src/common/verification-method/multikey';
import { ECDSASDCredential } from '../../src/vc/ecdsasd-credential';
import { Cryptosuite } from '../../src/common/ecdsasd';

const ISSUER = 'did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP';

class StaticResolver implements ResolverProvider {
  constructor(private readonly doc: DIDDocument) {}
  async resolveDocument(): Promise<DIDDocument> {
    return this.doc;
  }
}

describe('ecdsa-sd-2023', () => {
  const keys = JSON.parse(
    readFileSync(join(__dirname, '../fixtures/w3c-ecdsa-sd-2023/keys.json'), 'utf8'),
  );
  const priv = decodeP256SecretMultibase(keys.baseKeyPair.secretKeyMultibase);
  const pub = p256.getPublicKey(priv, false);

  function did(): DIDDocument {
    return {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://www.w3.org/ns/cid/v1'],
      id: ISSUER,
      verificationMethod: [
        {
          id: `${ISSUER}#key-2`,
          type: 'Multikey',
          controller: ISSUER,
          publicKeyMultibase: encodeP256PublicMultibase(pub),
        },
      ],
      authentication: [`${ISSUER}#key-2`],
      assertionMethod: [`${ISSUER}#key-2`],
    };
  }

  it('issues a base proof, verifies, and derives a disclosure', async () => {
    const resolver = new StaticResolver(did());
    const cred = await ECDSASDCredential.create(
      {
        context: [
          'https://www.w3.org/ns/credentials/v2',
          'https://www.w3.org/ns/credentials/examples/v2',
        ],
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        subject: [{ id: 'did:example:subject', customFields: { name: 'Alice', salary: 'secret' } }],
      },
      { verificationMethodKey: 'key-2', resolver },
    );
    await cred.addProofByProvider(new P256Provider(bytesToHex(priv)), ['/issuer', '/credentialSubject/id'], {
      verificationMethodKey: 'key-2',
      resolver,
    });
    const issued = await cred.serialize();
    expect((issued as { proof: { cryptosuite: string } }).proof.cryptosuite).toBe(Cryptosuite);
    await ECDSASDCredential.parse(JSON.stringify(issued), { resolver, verifyProof: true });

    const derived = await cred.derive(['/credentialSubject/name']);
    const derivedDoc = await derived.serialize();
    expect(JSON.stringify(derivedDoc)).toContain('Alice');
    expect(JSON.stringify(derivedDoc)).not.toContain('secret');
    await derived.verify({ resolver, verifyProof: true });
  });
});
