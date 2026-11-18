/**
 * A VM carrying both publicKeyHex and publicKeyMultibase: like Go's VMKeyKind and
 * ECPubFromVM, publicKeyHex wins, so signing and verifying agree on secp256k1/ES256K.
 */
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import { DefaultProvider } from '../../src/common/signer/default-provider';
import { P256Provider } from '../../src/common/signer/p256-provider';
import { DIDDocument, ResolverProvider } from '../../src/common/verification-method';
import { encodeP256PublicMultibase } from '../../src/common/verification-method/multikey';
import { JWTCredential } from '../../src/vc/jwt-credential';

const A = 'did:example:a';
const SECP = '4646464646464646464646464646464646464646464646464646464646464646';
const P256 = '1111111111111111111111111111111111111111111111111111111111111111';
const doc: DIDDocument = {
  '@context': [],
  id: A,
  verificationMethod: [{
    id: `${A}#key-1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: A,
    publicKeyHex: bytesToHex(secp256k1.getPublicKey(hexToBytes(SECP), false)),
    publicKeyMultibase: encodeP256PublicMultibase(p256.getPublicKey(hexToBytes(P256), false)),
  }],
  authentication: [`${A}#key-1`],
  assertionMethod: [`${A}#key-1`],
};
const resolver: ResolverProvider = { resolveDocument: async () => doc };
const contents = {
  context: ['https://www.w3.org/ns/credentials/v2'],
  id: 'urn:uuid:x',
  types: ['VerifiableCredential'],
  issuer: A,
  subject: [{ id: 'did:example:s', customFields: { name: 'n' } }],
};

describe('VM with both publicKeyHex and publicKeyMultibase (E27)', () => {
  it('signs a JWT VC with the secp256k1 key and verifies it', async () => {
    const cred = await JWTCredential.create(contents, { resolver });
    await cred.addProofByProvider(new DefaultProvider(SECP), { resolver });
    await expect(cred.verify({ resolver })).resolves.toBeUndefined();
  });

  it('refuses the P-256 key, as Go does', async () => {
    const cred = await JWTCredential.create(contents, { resolver });
    await expect(cred.addProofByProvider(new P256Provider(P256), { resolver })).rejects.toThrow();
  });
});
