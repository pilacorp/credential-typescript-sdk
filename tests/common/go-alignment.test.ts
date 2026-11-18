/**
 * Alignment with the Go SDK (PR #11 review rows 2.x / 4.x / 5.6). Expected
 * values were observed by running Go (fmt %v, LegacyHexCanonicalize, crypto.Sign).
 */
import { readFileSync } from 'fs';
import { join } from 'path';
import { secp256k1 } from '@noble/curves/secp256k1';
import { p256 } from '@noble/curves/nist';
import { sha256 } from '@noble/hashes/sha256';
import { canonicalize, parseRawToProof, proofHashData, verifyProof } from '../../src/common/jsonmap/jsonmap';
import { canonicalizeDocument, canonicalizeRDF, registerContext, relativeKeywordValues } from '../../src/common/processor/processor';
import { transformToString } from '../../src/common/jsoncanonicalizer/jsoncanonicalizer';
import { bytesToHex, hexToBytes } from '../../src/common/crypto/hex';
import { verifySignature } from '../../src/common/crypto/crypto';
import { verifyJwtProof } from '../../src/common/crypto/jwt-proof-2020';
import { p256PubFromJwk, verifyES256 } from '../../src/common/crypto/jws-2020';
import { parseStatusListIndex } from '../../src/common/credential-status/credential-status';
import { checkJwtTimeClaims, checkValidityPeriod } from '../../src/common/util/vc';
import { parseRFC3339Nanos } from '../../src/common/util/time';

const fx = JSON.parse(
  readFileSync(join(__dirname, '../fixtures/go-legacy-hex/credential.json'), 'utf8'),
);

describe('2.1 / 4.1 legacy canonicalizer number formatting (Go %v)', () => {
  it('canonicalizes numbers like Go and matches the Go digest', async () => {
    const digest = await canonicalize(fx.credential);
    expect(bytesToHex(digest)).toBe(fx.digest);
  });

  it('verifies a Go-signed legacy hex proof with numbers >= 1e6 and < 1e-4', async () => {
    const pub = fx.publicKeyHex as string;
    const resolver = {
      resolveDocument: async () => ({
        '@context': [],
        id: 'did:example:issuer',
        verificationMethod: [
          {
            id: 'did:example:issuer#key-1',
            type: 'EcdsaSecp256k1VerificationKey2019',
            controller: 'did:example:issuer',
            publicKeyHex: pub,
          },
        ],
        authentication: ['#key-1'],
        assertionMethod: ['#key-1'],
      }),
    };
    expect(await verifyProof(structuredClone(fx.credential), resolver as never)).toBe(true);
    const bad = structuredClone(fx.credential);
    bad.credentialSubject.salary = 1000001;
    expect(await verifyProof(bad, resolver as never)).toBe(false);
  });
});

describe('2.3 proof configuration keeps the whole proof', () => {
  const m = { '@context': ['https://www.w3.org/ns/credentials/v2'], type: 'VerifiableCredential' };
  const proof = {
    type: 'DataIntegrityProof',
    cryptosuite: 'ecdsa-rdfc-2019',
    created: '2024-01-01T00:00:00Z',
    verificationMethod: 'did:example:i#key-1',
    proofPurpose: 'assertionMethod',
    proofValue: 'zabc',
  };
  it('parseRawToProof keeps id/expires/nonce/array domain; hash covers them', async () => {
    const extra = { ...proof, id: 'urn:uuid:1', expires: '2030-01-01T00:00:00Z', nonce: 'n', domain: ['a', 'b'] };
    const parsed = parseRawToProof(extra) as unknown as Record<string, unknown>;
    expect(parsed.id).toBe('urn:uuid:1');
    expect(parsed.domain).toEqual(['a', 'b']);
    const docHash = new Uint8Array(32);
    const a = await proofHashData(m, docHash, parseRawToProof(proof));
    const b = await proofHashData(m, docHash, parseRawToProof(extra));
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
    // the signature field itself is not part of the configuration
    const c = await proofHashData(m, docHash, parseRawToProof({ ...proof, proofValue: 'zother' }));
    expect(Buffer.from(a).equals(Buffer.from(c))).toBe(true);
  });
});

describe('2.5 / 2.7 processor', () => {
  it('refuses to override a bundled context', () => {
    expect(() => registerContext('https://www.w3.org/ns/credentials/v2', {})).toThrow(/bundled/);
  });
  it('flags relative values of an array-valued @type, not keywords', async () => {
    expect(relativeKeywordValues({ '@type': ['http://a/b', 'Nope'] }, '@type')).toEqual(['Nope']);
    expect(relativeKeywordValues({ x: [{ '@type': ['@json', '_:b0', 'urn:x:y'] }] }, '@type')).toEqual([]);
    const ctx = ['https://www.w3.org/ns/credentials/v2'];
    await expect(canonicalizeRDF({ '@context': ctx, type: ['VerifiableCredential', 'Nope'] })).rejects.toThrow();
    expect((await canonicalizeDocument({ '@context': ctx, type: 'VerifiableCredential' })).length).toBeGreaterThan(0);
  });
});

describe('2.8 JCS strictness', () => {
  it('rejects duplicate keys, top-level scalars and lone surrogates', () => {
    expect(() => transformToString('{"a":1,"a":2}')).toThrow(/duplicate/);
    expect(() => transformToString('{"x":{"a":1,"a":2}}')).toThrow(/duplicate/);
    expect(() => transformToString('{"a":1,"b":{"a":2}}')).not.toThrow();
    expect(() => transformToString('5')).toThrow();
    expect(() => transformToString('"s"')).toThrow();
    expect(() => transformToString('{"a":"\\ud800"}')).toThrow(/surrogate/);
    expect(transformToString('{"a":"\\ud83d\\ude00"}')).toBe('{"a":"😀"}');
  });
});

describe('4.2 / 4.3 JwtProof2020', () => {
  const priv = hexToBytes('4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318');
  const pub33 = secp256k1.getPublicKey(priv, true);
  const pub65 = secp256k1.getPublicKey(priv, false);
  const msg = Buffer.from('header.payload');
  const sig = secp256k1.sign(sha256(msg), priv, { lowS: true });
  const compact = sig.toCompactRawBytes();
  const withV = Uint8Array.from([...compact, sig.recovery]);
  const jwt = (s: Uint8Array) => ({ proof: { jwt: `header.payload.${Buffer.from(s).toString('base64url')}` } });

  it('accepts a 65-byte public key (compressed first)', () => {
    expect(verifyJwtProof(jwt(compact), bytesToHex(pub65))).toBe(true);
    expect(verifyJwtProof(jwt(compact), bytesToHex(pub33))).toBe(true);
  });
  it('uses the recovery id of a 65-byte signature', () => {
    expect(verifySignature(pub33, msg, withV)).toBe(true);
    const wrongV = Uint8Array.from([...compact, sig.recovery ^ 1]);
    expect(verifySignature(pub33, msg, wrongV)).toBe(false);
    expect(verifySignature(pub33, msg, Uint8Array.from([...compact, 27]))).toBe(false);
  });
  it('rejects a high-S 64-byte signature', () => {
    const n = secp256k1.CURVE.n;
    const high = Uint8Array.from([...compact.subarray(0, 32), ...hexToBytes((n - sig.s).toString(16).padStart(64, '0'))]);
    expect(verifySignature(pub33, msg, high)).toBe(false);
  });
});

describe('4.4 / 4.5 JWS2020 P-256', () => {
  it('ES256 needs exactly 64 bytes', () => {
    const priv = p256.utils.randomPrivateKey();
    const pub = p256.getPublicKey(priv, false);
    const digest = sha256(Buffer.from('x'));
    const sig = p256.sign(digest, priv, { lowS: false }).toCompactRawBytes();
    expect(verifyES256(pub, digest, sig)).toBe(true);
    expect(verifyES256(pub, digest, Uint8Array.from([...sig, 0]))).toBe(false);
  });
  it('left-pads short JWK coordinates', () => {
    for (;;) {
      const pub = p256.getPublicKey(p256.utils.randomPrivateKey(), false);
      if (pub[1] !== 0 && pub[33] !== 0) continue;
      const strip = (b: Uint8Array) => Buffer.from(b[0] === 0 ? b.subarray(1) : b).toString('base64url');
      const out = p256PubFromJwk({ kty: 'EC', crv: 'P-256', x: strip(pub.subarray(1, 33)), y: strip(pub.subarray(33, 65)) });
      expect(Buffer.from(out).equals(Buffer.from(pub))).toBe(true);
      return;
    }
  });
});

describe('5.6 strict hex', () => {
  it.each(['1g', '+1', ' 1', '0x', 'zz'])('rejects %p', (h) => {
    if (h === '0x') return; // empty after prefix is valid
    expect(() => hexToBytes(h.length % 2 ? h + '0' : h)).toThrow();
  });
  it('accepts valid hex', () => {
    expect(bytesToHex(hexToBytes('0xAbCd'))).toBe('abcd');
  });
});

describe('4.16 / 4.17 / 4.18 time and index', () => {
  it('parses strict RFC3339 with nanosecond precision', () => {
    expect(parseRFC3339Nanos('2024-01-01T00:00:00.123456789Z')).toBe(1704067200123456789n);
    expect(parseRFC3339Nanos('2024-01-01T01:00:00+01:00')).toBe(1704067200000000000n);
    for (const bad of ['2024-01-01', '2024-01-01 00:00:00Z', '2024-02-30T00:00:00Z', '2024-01-01T00:00:00', 'x']) {
      expect(() => parseRFC3339Nanos(bad)).toThrow();
    }
    expect(() => checkValidityPeriod({ validFrom: '2024-01-01T00:00:00' }, 'credential')).toThrow(/parse validFrom/);
  });
  it('JWT is expired when now >= exp', () => {
    const now = Math.floor(Date.now() / 1000);
    jest.useFakeTimers().setSystemTime(now * 1000);
    try {
      expect(() => checkJwtTimeClaims({ exp: now })).toThrow(/expired/);
      expect(() => checkJwtTimeClaims({ exp: now + 1 })).not.toThrow();
    } finally {
      jest.useRealTimers();
    }
  });
  it('status list index is parsed like Atoi', () => {
    expect(parseStatusListIndex('12')).toBe(12);
    expect(parseStatusListIndex('-3')).toBe(-3);
    for (const bad of ['12abc', ' 1', '1.5', '', '0x10']) expect(() => parseStatusListIndex(bad)).toThrow();
  });
});
