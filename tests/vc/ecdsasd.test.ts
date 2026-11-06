import { readFileSync } from 'fs';
import { join } from 'path';
import { p256 } from '@noble/curves/nist';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import { P256Provider } from '../../src/common/signer/p256-provider';
import {
  DIDDocument,
  ResolverProvider,
  StaticResolver
} from '../../src/common/verification-method';
import { decodeP256SecretMultibase, encodeP256PublicMultibase } from '../../src/common/verification-method/multikey';
import { ECDSASDCredential } from '../../src/vc/ecdsasd-credential';
import { Cryptosuite } from '../../src/common/ecdsasd';

const ISSUER = 'did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP';

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
    expect(cred.getType()).toBe('JSON');
    expect(cred.extractField('issuer')).toBe(ISSUER);
    expect(cred.getContents().length).toBeGreaterThan(0);
    expect(await cred.hash()).toMatch(/^[0-9a-f]{64}$/);
  });

  it('defaults to the issuer active assertion method when no kid is given', async () => {
    const doc: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1', 'https://www.w3.org/ns/cid/v1'],
      id: ISSUER,
      verificationMethod: [
        {
          id: `${ISSUER}#key-1`,
          type: 'Multikey',
          controller: ISSUER,
          publicKeyMultibase: encodeP256PublicMultibase(pub),
        },
      ],
      authentication: [`${ISSUER}#key-1`],
      assertionMethod: [`${ISSUER}#key-1`],
    };
    const resolver = new StaticResolver(doc);
    const cred = await ECDSASDCredential.create(
      {
        context: [
          'https://www.w3.org/ns/credentials/v2',
          'https://www.w3.org/ns/credentials/examples/v2',
        ],
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        subject: [{ id: 'did:example:subject' }],
      },
      { resolver },
    );
    await cred.addProofByProvider(new P256Provider(bytesToHex(priv)), ['/issuer'], { resolver });
    const issued = (await cred.serialize()) as { proof: { verificationMethod: string } };
    expect(issued.proof.verificationMethod).toBe(`${ISSUER}#key-1`);
    await ECDSASDCredential.parse(JSON.stringify(issued), { resolver, verifyProof: true });
  });
});
