/**
 * PR #11 differential review of 13 Nov (items C13-C16, D17-D26): TS takes the
 * same accept/refuse decisions as go-credential-sdk.
 */
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, ecdsaVerifySignature } from '../../src/common/crypto/crypto';
import { parseRawToProof } from '../../src/common/jsonmap/jsonmap';
import { checkJwtTimeClaims } from '../../src/common/util/vc';
import { formatRFC3339 } from '../../src/common/util/time';
import { jwkToHex, parseDIDDocument, parseRFC3339Strict } from '../../src/common/verification-method';
import { getSharedSecret } from '../../src/didcomm/didcomm';
import { checkExpiration as checkVCExpiration, serializeCredentialContents } from '../../src/vc/credential-helper';
import { newJSONCredential, newJWTCredential, parseCredential } from '../../src/vc/credential';
import type { CredentialContents } from '../../src/vc/types';
import { checkExpiration as checkVPExpiration } from '../../src/vp/presentation-helper';

const base: CredentialContents = {
  context: ['https://www.w3.org/ns/credentials/v2'],
  types: ['VerifiableCredential'],
  issuer: 'did:example:issuer',
  subject: [{ id: 'did:example:subject', customFields: { name: 'x' } }],
};

const year = (y: number): Date => {
  const d = new Date(0);
  d.setUTCFullYear(y, 0, 1);
  return d;
};

describe('C13: required properties on creation from contents', () => {
  it.each([
    ['@context', { context: [] }],
    ['type', { types: [] }],
    ['issuer', { issuer: '' }],
    ['credentialSubject', { subject: [] }],
  ])('refuses a credential without %s (JSON and JWT)', async (prop, patch) => {
    const vcc = { ...base, ...patch } as CredentialContents;
    await expect(newJSONCredential(vcc)).rejects.toThrow(`credential is missing ${prop}`);
    await expect(newJWTCredential(vcc)).rejects.toThrow(`credential is missing ${prop}`);
  });
});

describe('C14: credentialSchema fields', () => {
  it('writes an absent schema id or type as ""', () => {
    const m = serializeCredentialContents({ ...base, schemas: [{ id: 'https://s.example/1' } as never] });
    expect(m.credentialSchema).toEqual({ id: 'https://s.example/1', type: '' });
  });
});

describe('C15: null validity dates', () => {
  it.each(['validFrom', 'validUntil'])('refuses %s: null for VC and VP', (field) => {
    expect(() => checkVCExpiration({ [field]: null })).toThrow(`field "${field}" must be a string`);
    expect(() => checkVPExpiration({ [field]: null })).toThrow(`field "${field}" must be a string`);
  });

  it('still treats an absent field as unset', () => {
    expect(() => checkVCExpiration({})).not.toThrow();
  });
});

describe('C16: dates written from contents', () => {
  it('zero-pads years below 1000', () => {
    expect(formatRFC3339(year(5))).toBe('0005-01-01T00:00:00Z');
  });

  it("omits Go's zero time, as Go's IsZero does", () => {
    const m = serializeCredentialContents({ ...base, validFrom: year(1), validUntil: year(1) });
    expect(m).not.toHaveProperty('validFrom');
    expect(m).not.toHaveProperty('validUntil');
  });
});

describe('D17: DID document field types', () => {
  const doc = { id: 'did:example:a', '@context': ['https://www.w3.org/ns/did/v1'] };

  it.each([
    ['@context', { '@context': 'https://www.w3.org/ns/did/v1' }],
    ['@context', { '@context': [{ '@vocab': 'x' }] }],
    ['authentication', { authentication: 1 }],
    ['didDocumentMetadata', { didDocumentMetadata: 'x' }],
    ['revocationReason', { verificationMethod: [{ id: 'k', revocationReason: 1 }] }],
    ['publicKeyJwk.x', { verificationMethod: [{ id: 'k', publicKeyJwk: { kty: 'EC', x: 1 } }] }],
  ])('refuses a wrong JSON type in %s', (field, patch) => {
    expect(() => parseDIDDocument({ ...doc, ...patch })).toThrow(`"${field}" has the wrong type`);
  });

  it('reads null as unset, like Go', () => {
    const d = parseDIDDocument({ ...doc, authentication: null, didDocumentMetadata: null });
    expect(d.authentication).toEqual([]);
    expect(d.didDocumentMetadata).toBeUndefined();
  });
});

describe('D18: JWK coordinates are unpadded base64url', () => {
  const pub = p256.getPublicKey(p256.utils.randomPrivateKey(), false);
  const x = Buffer.from(pub.subarray(1, 33)).toString('base64url');
  const y = Buffer.from(pub.subarray(33)).toString('base64url');

  it('accepts the raw URL alphabet', () => {
    expect(jwkToHex({ kty: 'EC', crv: 'P-256', x, y })).toBe(bytesToHex(pub));
  });

  it.each([
    ['padding', `${x}=`],
    ['standard alphabet', Buffer.from(pub.subarray(1, 33)).toString('base64').replace(/=+$/, '').replace(/-/g, '+').replace(/_/g, '/') + '+'],
  ])('refuses %s', (_, bad) => {
    expect(() => jwkToHex({ kty: 'EC', crv: 'P-256', x: bad, y })).toThrow('unpadded base64url');
  });
});

describe('D19/D23: legacy hex proofValue', () => {
  const digest = sha256(new TextEncoder().encode('legacy'));

  it('refuses a 0x-prefixed signature', () => {
    const priv = secp256k1.utils.randomPrivateKey();
    const sig = bytesToHex(secp256k1.sign(digest, priv).toCompactRawBytes());
    const pub = bytesToHex(secp256k1.getPublicKey(priv, false));
    expect(ecdsaVerifySignature(pub, sig, digest)).toBe(true);
    expect(() => ecdsaVerifySignature(pub, `0x${sig}`, digest)).toThrow('0x prefix');
  });

  it('verifies a signature by a P-256 key on the P-256 curve', () => {
    const priv = p256.utils.randomPrivateKey();
    const sig = bytesToHex(p256.sign(digest, priv).toCompactRawBytes());
    const pub = bytesToHex(p256.getPublicKey(priv, false));
    expect(ecdsaVerifySignature(pub, sig, digest, p256)).toBe(true);
  });
});

describe('D21: JWT numeric dates beyond int64', () => {
  it.each([['exp', 1e30], ['nbf', 1e25]])('refuses %s = %d', (claim, value) => {
    expect(() => checkJwtTimeClaims({ [claim]: value })).toThrow(`invalid JWT ${claim} claim`);
  });
});

describe('D22: DIDComm public key encoding', () => {
  const priv = bytesToHex(secp256k1.utils.randomPrivateKey());
  const pub = secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey(), false);

  it('refuses a 0x prefix and a raw 64-byte key', () => {
    expect(() => getSharedSecret(bytesToHex(pub), priv)).not.toThrow();
    expect(() => getSharedSecret(`0x${bytesToHex(pub)}`, priv)).toThrow('0x prefix');
    expect(() => getSharedSecret(bytesToHex(pub.subarray(1)), priv)).toThrow('33 or 65 bytes');
  });
});

describe('D24: revoked with a comma fraction', () => {
  it('parses like Go time.Parse(RFC3339)', () => {
    expect(parseRFC3339Strict('2024-01-01T00:00:00,5Z').date.toISOString()).toBe('2024-01-01T00:00:00.500Z');
  });
});

describe('D25: non-string proof.created', () => {
  it('stays in the proof, so the proof configuration hashes it as Go does', () => {
    expect(parseRawToProof({ type: 'DataIntegrityProof', created: 1700000000 }).created).toBe(1700000000);
    expect(parseRawToProof({ type: 'DataIntegrityProof' }).created).toBe('');
  });
});

describe('D26: parseCredential trims a JWT', () => {
  it('reads a JWT with surrounding whitespace and quotes', async () => {
    const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const vc = { '@context': ['https://www.w3.org/2018/credentials/v1'], type: ['VerifiableCredential'], issuer: 'did:example:i', credentialSubject: { id: 'did:example:s' } };
    const jwt = `${enc({ alg: 'ES256K', typ: 'JWT' })}.${enc({ vc, iss: 'did:example:i' })}.${'A'.repeat(86)}`;
    expect((await parseCredential(`  ${jwt}\n`)).getType()).toBe('JWT');
    expect((await parseCredential(`"${jwt}"`)).getType()).toBe('JWT');
  });
});
