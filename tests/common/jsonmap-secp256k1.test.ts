/**
 * A2 — JSON-LD signing suite selection (ecdsa-rdfc-2019 vs
 * EcdsaSecp256k1Signature2019) and EcdsaSecp256k1Signature2019 strictness.
 * Port-parity with go credential/common/jsonmap/jsonmap_secp256k1.go.
 */
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import {
  addEcdsaSecp256k1Proof,
  verifyProof,
  EcdsaSecp256k1Signature2019,
} from '../../src/common/jsonmap/jsonmap';
import { DefaultProvider } from '../../src/common/signer/default-provider';
import { P256Provider } from '../../src/common/signer/p256-provider';
import { JSONCredential } from '../../src/vc/json-credential';
import {
  DIDDocument,
  ResolverProvider,
} from '../../src/common/verification-method';

const SECP_PRIV = '4646464646464646464646464646464646464646464646464646464646464646';
const P256_PRIV = '1a2b3c4d5e6f70818243a4b5c6d7e8f9000102030405060708090a0b0c0d0e0f';
const ISSUER = 'did:example:issuer';
const SUBJECT = 'did:example:subject';

class StaticResolver implements ResolverProvider {
  constructor(private readonly doc: DIDDocument) {}
  async resolveDocument(): Promise<DIDDocument> {
    return this.doc;
  }
}

function secpDID(): DIDDocument {
  const pubHex = bytesToHex(secp256k1.getPublicKey(hexToBytes(SECP_PRIV), false));
  return {
    '@context': [],
    id: ISSUER,
    verificationMethod: [
      {
        id: `${ISSUER}#key-1`,
        type: 'EcdsaSecp256k1VerificationKey2019',
        controller: ISSUER,
        publicKeyHex: pubHex,
      },
    ],
    authentication: [`${ISSUER}#key-1`],
    assertionMethod: [`${ISSUER}#key-1`],
  };
}

function p256DID(): DIDDocument {
  const pub = p256.getPublicKey(hexToBytes(P256_PRIV), false); // 0x04 || X || Y
  const x = Buffer.from(pub.slice(1, 33)).toString('base64url');
  const y = Buffer.from(pub.slice(33, 65)).toString('base64url');
  return {
    '@context': [],
    id: ISSUER,
    verificationMethod: [
      {
        id: `${ISSUER}#key-1`,
        type: 'JsonWebKey2020',
        controller: ISSUER,
        publicKeyJwk: { kty: 'EC', crv: 'P-256', x, y },
      },
    ],
    authentication: [`${ISSUER}#key-1`],
    assertionMethod: [`${ISSUER}#key-1`],
  };
}

async function newUnsignedVC(): Promise<Record<string, unknown>> {
  const cred = await JSONCredential.create({
    context: ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:secp',
    types: ['VerifiableCredential'],
    issuer: ISSUER,
    subject: [{ id: SUBJECT, customFields: { name: 'Alice' } }],
  });
  return cred.getInternalData() as Record<string, unknown>;
}

describe('A2: JSON-LD signing suite selection', () => {
  it('a secp256k1 key issues EcdsaSecp256k1Signature2019 with a jws (no hex proofValue) and round-trips', async () => {
    const resolver = new StaticResolver(secpDID());
    const cred = await JSONCredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:secp',
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        subject: [{ id: SUBJECT, customFields: { name: 'Alice' } }],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await cred.addProofByProvider(new DefaultProvider(SECP_PRIV), { verificationMethodKey: 'key-1', resolver });

    const out = (await cred.serialize()) as Record<string, unknown>;
    const proof = out.proof as Record<string, unknown>;
    expect(proof.type).toBe(EcdsaSecp256k1Signature2019);
    expect(typeof proof.jws).toBe('string');
    expect(proof.proofValue).toBeUndefined();
    // Detached JWS, b64:false (RFC 7797): header '..' signature.
    expect((proof.jws as string).includes('..')).toBe(true);

    const parsed = await JSONCredential.parse(JSON.stringify(out));
    await parsed.verify({ resolver });
  });

  it('a P-256 key issues ecdsa-rdfc-2019 (base58btc proofValue) and round-trips', async () => {
    const resolver = new StaticResolver(p256DID());
    const cred = await JSONCredential.create(
      {
        context: ['https://www.w3.org/ns/credentials/v2'],
        id: 'urn:uuid:p256',
        types: ['VerifiableCredential'],
        issuer: ISSUER,
        subject: [{ id: SUBJECT, customFields: { name: 'Alice' } }],
      },
      { verificationMethodKey: 'key-1', resolver },
    );
    await cred.addProofByProvider(new P256Provider(P256_PRIV), {
      verificationMethodKey: 'key-1',
      resolver,
    });

    const out = (await cred.serialize()) as Record<string, unknown>;
    const proof = out.proof as Record<string, unknown>;
    expect(proof.type).toBe('DataIntegrityProof');
    expect(proof.cryptosuite).toBe('ecdsa-rdfc-2019');
    expect((proof.proofValue as string).startsWith('z')).toBe(true);
    expect(proof.jws).toBeUndefined();

    const parsed = await JSONCredential.parse(JSON.stringify(out));
    await parsed.verify({ resolver });
  });
});

describe('A2: EcdsaSecp256k1Signature2019 verification strictness', () => {
  async function signedSecp(): Promise<Record<string, unknown>> {
    const m = await newUnsignedVC();
    await addEcdsaSecp256k1Proof(m, new DefaultProvider(SECP_PRIV), `${ISSUER}#key-1`, 'assertionMethod');
    return m;
  }

  function splitJWS(jws: string): { header: string; sig: Uint8Array } {
    const i = jws.indexOf('..');
    return { header: jws.slice(0, i), sig: new Uint8Array(Buffer.from(jws.slice(i + 2), 'base64url')) };
  }

  it('verifies an untampered proof', async () => {
    const m = await signedSecp();
    await expect(verifyProof(m, new StaticResolver(secpDID()))).resolves.toBe(true);
  });

  it('rejects a high-S signature', async () => {
    const m = await signedSecp();
    const proof = m.proof as Record<string, unknown>;
    const { header, sig } = splitJWS(proof.jws as string);
    const n = secp256k1.CURVE.n;
    const s = BigInt('0x' + bytesToHex(sig.subarray(32)));
    const highS = n - s; // the other valid numeric form
    const tampered = new Uint8Array(64);
    tampered.set(sig.subarray(0, 32), 0);
    tampered.set(hexToBytes(highS.toString(16).padStart(64, '0')), 32);
    proof.jws = `${header}..${Buffer.from(tampered).toString('base64url')}`;
    await expect(verifyProof(m, new StaticResolver(secpDID()))).rejects.toThrow(/low-S/);
  });

  it('rejects a 65-byte signature', async () => {
    const m = await signedSecp();
    const proof = m.proof as Record<string, unknown>;
    const { header, sig } = splitJWS(proof.jws as string);
    const sig65 = new Uint8Array(65);
    sig65.set(sig, 0); // append a recovery byte nobody signed
    proof.jws = `${header}..${Buffer.from(sig65).toString('base64url')}`;
    await expect(verifyProof(m, new StaticResolver(secpDID()))).rejects.toThrow(/64 \(r\|\|s\)/);
  });

  it('rejects a non-canonical base64url signature', async () => {
    const m = await signedSecp();
    const proof = m.proof as Record<string, unknown>;
    const { header, sig } = splitJWS(proof.jws as string);
    // Re-encode then set the trailing unused bits of the last base64url char so
    // the string decodes to the same bytes but is not the canonical encoding.
    const enc = Buffer.from(sig).toString('base64url');
    const last = enc[enc.length - 1];
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    // 64 bytes -> 86 chars, final char carries 2 significant bits; bump it to a
    // char that decodes to the same 2 bits but with the low 4 bits set.
    const idx = alphabet.indexOf(last);
    const nonCanonical = alphabet[(idx & 0x30) | 0x0f];
    proof.jws = `${header}..${enc.slice(0, -1)}${nonCanonical}`;
    await expect(verifyProof(m, new StaticResolver(secpDID()))).rejects.toThrow(/non-canonical/);
  });

  it('rejects a P-256 VM under the secp256k1 suite (mixed suites)', async () => {
    const m = await signedSecp();
    await expect(verifyProof(m, new StaticResolver(p256DID()))).rejects.toThrow(/secp256k1 key/);
  });
});
