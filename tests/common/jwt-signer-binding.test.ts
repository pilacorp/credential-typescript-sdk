/**
 * Blocking review finding A1: the JWT verifier must take the signer DID from the
 * payload's issuer (VC) / holder (VP), cross-check it against `iss`, and require
 * the header kid to belong to that signer's DID document. A forged token whose
 * kid names a different DID than its issuer/holder must be rejected.
 */
import { secp256k1 } from '@noble/curves/secp256k1';
import { DefaultProvider } from '../../src/common/signer/default-provider';
import { JWTSigner } from '../../src/common/jwt/signer';
import { JWTVerifier } from '../../src/common/jwt/verifier';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import { DIDDocument, ResolverProvider } from '../../src/common/verification-method';

const ATTACKER_PRIV = '4646464646464646464646464646464646464646464646464646464646464646';
const VICTIM_PRIV = '7777777777777777777777777777777777777777777777777777777777777777';
const ATTACKER = 'did:example:attacker';
const VICTIM = 'did:example:victim';

class MapResolver implements ResolverProvider {
  constructor(private readonly docs: Record<string, DIDDocument>) {}
  async resolveDocument(did: string): Promise<DIDDocument> {
    const doc = this.docs[did];
    if (!doc) throw new Error(`DID ${did} not found`);
    return doc;
  }
}

function secpDoc(did: string, priv: string): DIDDocument {
  const pubHex = bytesToHex(secp256k1.getPublicKey(hexToBytes(priv), false));
  return {
    '@context': [],
    id: did,
    verificationMethod: [
      { id: `${did}#key-1`, type: 'EcdsaSecp256k1VerificationKey2019', controller: did, publicKeyHex: pubHex },
    ],
    authentication: [`${did}#key-1`],
    assertionMethod: [`${did}#key-1`],
  };
}

async function sign(priv: string, header: object, payload: object): Promise<string> {
  const h = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
  const p = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const sig = await new JWTSigner(new DefaultProvider(priv)).signString(`${h}.${p}`);
  return `${h}.${p}.${sig}`;
}

describe('JWT signer binding (A1)', () => {
  const resolver = new MapResolver({ [ATTACKER]: secpDoc(ATTACKER, ATTACKER_PRIV), [VICTIM]: secpDoc(VICTIM, VICTIM_PRIV) });
  const verifier = new JWTVerifier(resolver);

  it('rejects a VC whose iss disagrees with issuer', async () => {
    const token = await sign(ATTACKER_PRIV,
      { typ: 'vc+jwt', alg: 'ES256K', kid: `${ATTACKER}#key-1` },
      { issuer: VICTIM, iss: ATTACKER, type: ['VerifiableCredential'], credentialSubject: { id: 'did:example:s' } });
    await expect(verifier.verifyJWT(token)).rejects.toThrow();
  });

  it('rejects a VC whose kid names a different DID than its issuer', async () => {
    const token = await sign(ATTACKER_PRIV,
      { typ: 'vc+jwt', alg: 'ES256K', kid: `${ATTACKER}#key-1` },
      { issuer: VICTIM, type: ['VerifiableCredential'], credentialSubject: { id: 'did:example:s' } });
    await expect(verifier.verifyJWT(token)).rejects.toThrow();
  });

  it('rejects a VP whose kid is not the holder key', async () => {
    const token = await sign(ATTACKER_PRIV,
      { typ: 'vp+jwt', alg: 'ES256K', kid: `${ATTACKER}#key-1` },
      { holder: VICTIM, type: ['VerifiablePresentation'] });
    await expect(verifier.verifyJWT(token)).rejects.toThrow();
  });

  it('accepts a VC legitimately signed by its issuer', async () => {
    const token = await sign(VICTIM_PRIV,
      { typ: 'vc+jwt', alg: 'ES256K', kid: `${VICTIM}#key-1` },
      { issuer: VICTIM, type: ['VerifiableCredential'], credentialSubject: { id: 'did:example:s' } });
    await expect(verifier.verifyJWT(token)).resolves.toBeUndefined();
  });
});
