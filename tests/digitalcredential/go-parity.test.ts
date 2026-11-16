import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { P256Provider } from '../../src/common/signer/p256-provider';
import { bytesToHex } from '../../src/common/crypto/hex';
import { hashDisclosure, reconstruct } from '../../src/common/sdjwt';
import { issue, Credential, StaticResolver, Code } from '../../src/digitalcredential';
import { signCompactJWS } from '../../src/digitalcredential/jws-compact';
import { List } from '../../src/digitalcredential/statuslist';

const iss = 'https://issuer.example';
const vct = 'https://a.example/t';
const uri = 'https://a.example/s';

function issuer() {
  const priv = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(priv, false);
  return {
    key: { signer: new P256Provider(bytesToHex(priv)), publicKey: pub, kid: 'key-1' },
    resolver: new StaticResolver(iss, [{ kid: 'key-1', publicKey: pub }]),
  };
}

const disclosure = (...items: unknown[]): string => Buffer.from(JSON.stringify(items)).toString('base64url');
const digest = (d: string): string => hashDisclosure('sha-256', d);
const decoy = digest(disclosure('salt', 'no', 'claim'));

/** A credential with exactly this payload, as an Issuer other than this SDK could sign it. */
async function signed(ctx: ReturnType<typeof issuer>, payload: Record<string, unknown>, ...disclosures: string[]) {
  const jwt = await signCompactJWS({ alg: 'ES256', typ: 'dc+sd-jwt', kid: 'key-1' }, { iss, vct, ...payload }, ctx.key.signer);
  return new Credential([jwt, ...disclosures, ''].join('~'));
}

describe('sdjwt reconstruct: reserved names out of place', () => {
  it.each([
    ['"..." beside another member', { a: { '...': 'x', b: 1 } }],
    ['"..." beside another member, in an array', { arr: [{ '...': 'x', b: 1 }] }],
    ['"..." that is not a string', { arr: [{ '...': 5 }, 1] }],
    ['_sd_alg below the top level', { a: { _sd_alg: 'sha-256' } }],
  ])('refuses %s', (_name, payload) => {
    expect(() => reconstruct(payload, [], true, true)).toThrow();
  });

  it('leaves those names alone when not strict, as the vc module reads', () => {
    const payload = { ref: { '...': 'x', b: 1 }, a: { _sd_alg: 'sha-256' } };
    expect(reconstruct(payload, [], true)).toEqual(payload);
  });

  it('refuses nesting deeper than 32 when strict', () => {
    const nested = (levels: number): Record<string, unknown> => (levels === 1 ? {} : { a: nested(levels - 1) });
    expect(() => reconstruct(nested(32), [], true, true)).not.toThrow();
    expect(() => reconstruct(nested(33), [], true, true)).toThrow('nesting deeper than 32');
  });

  it('keeps a placeholder nothing opens and a top-level _sd_alg', () => {
    expect(reconstruct({ _sd_alg: 'sha-256', arr: [{ '...': decoy }, 1] }, [], true, true)).toEqual({
      arr: [{ '...': decoy }, 1],
    });
  });
});

describe('dc verify: claims that are never selectively disclosable', () => {
  const status = { status_list: { idx: 0, uri } };

  it('accepts decoy digests inside status', async () => {
    const ctx = issuer();
    const cred = await signed(ctx, { _sd_alg: 'sha-256', status: { ...status, _sd: [decoy] } });
    const res = await cred.verify(ctx.resolver, { skipStatus: true });
    expect(res.claims.status).toEqual(status);
  });

  it('refuses a sub-claim of status that came in a Disclosure', async () => {
    const ctx = issuer();
    const d = disclosure('salt', 'extra', 1);
    const cred = await signed(ctx, { _sd_alg: 'sha-256', status: { ...status, _sd: [digest(d)] } }, d);
    await expect(cred.verify(ctx.resolver, { skipStatus: true })).rejects.toMatchObject({ code: Code.DisclosureInvalid });
  });
});

describe('dc: cnf is read the same way at issue and at verify', () => {
  const rsa = { kty: 'RSA', n: 'AQAB', e: 'AQAB' };

  it('signs a cnf this SDK does not bind to, and verify names it unsupported', async () => {
    const ctx = issuer();
    for (const cnf of [{ jwk: rsa }, { jwk: { kty: 'EC', crv: 'P-384', x: 'AQAB', y: 'AQAB' } }, { jku: 'https://a.example/k' }]) {
      const cred = await issue({ issuer: iss, vct, claims: { cnf } }, ctx.key);
      await expect(cred.verify(ctx.resolver)).rejects.toMatchObject({ code: Code.KBUnsupported });
    }
  });

  it.each([
    ['a symmetric key', { jwk: { kty: 'oct', k: 'AQAB' } }],
    ['a private key', { jwk: { ...rsa, d: 'AQAB' } }],
    ['no kty', { jwk: { crv: 'P-256' } }],
    ['an EC key without crv', { jwk: { kty: 'EC' } }],
  ])('refuses to sign a cnf.jwk with %s', async (_name, cnf) => {
    await expect(issue({ issuer: iss, vct, claims: { cnf } }, issuer().key)).rejects.toThrow(/cnf/);
  });

  it('reads a cnf that is not an object as malformed, not as absent', async () => {
    const ctx = issuer();
    for (const cnf of [null, '', 0]) {
      const cred = await signed(ctx, { cnf });
      await expect(cred.verify(ctx.resolver)).rejects.toMatchObject({ code: Code.Malformed });
    }
  });

  it('needs a cnf when Key Binding is required', async () => {
    const ctx = issuer();
    const cred = await issue({ issuer: iss, vct }, ctx.key);
    await expect(cred.verify(ctx.resolver, { requireKeyBinding: true })).rejects.toMatchObject({
      code: Code.KBUnsupported,
    });
  });
});

describe('dc issue: a status index past the safe integers', () => {
  it('is signed while it fits a status list', async () => {
    const claims = { status: { status_list: { idx: 2 ** 53 + 2, uri } } };
    await issue({ issuer: iss, vct, claims }, issuer().key);
  });
});

describe('dc present: an array element that only looks like a placeholder', () => {
  it('counts as an element', async () => {
    const ctx = issuer();
    const d = disclosure('salt', 'a', 1);
    const cred = await signed(ctx, { _sd_alg: 'sha-256', _sd: [digest(d)], arr: [{ '...': 'zz', b: 1 }, 'y'] }, d);
    // Not reachable through verify, which refuses the payload; present reads it before any check.
    const shown = await cred.present({ reveal: [['arr', 0, 'b'], ['a']] });
    expect(shown.compact.split('~')).toHaveLength(3);
  });
});

describe('dc: _sd_alg is never a disclosed claim', () => {
  it('issue refuses a Disclose path that names it', async () => {
    const ctx = issuer();
    await expect(issue({ issuer: iss, vct, claims: { a: 1 }, disclose: [['_sd_alg'], ['a']] }, ctx.key)).rejects.toThrow(
      'path ["_sd_alg"] does not exist in the claims',
    );
  });

  it('verify refuses a Disclosure with that claim name', async () => {
    const ctx = issuer();
    const d = disclosure('salt', '_sd_alg', 'x');
    const cred = await signed(ctx, { _sd_alg: 'sha-256', a: { _sd: [digest(d)] } }, d);
    await expect(cred.verify(ctx.resolver, { skipStatus: true })).rejects.toMatchObject({ code: Code.DisclosureInvalid });
  });
});

describe('dc: cnf.jwk on secp256k1 that says it is for something else (RFC 8812 §3.2)', () => {
  const pub = secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey(), false);
  const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
  const jwk = { kty: 'EC', crv: 'secp256k1', x: b64(pub.subarray(1, 33)), y: b64(pub.subarray(33)) };

  it.each([
    ['alg ES256', { alg: 'ES256' }],
    ['use enc', { use: 'enc' }],
    ['key_ops without verify', { key_ops: ['sign'] }],
  ])('is malformed with %s', async (_name, extra) => {
    const ctx = issuer();
    const cnf = { jwk: { ...jwk, ...extra } };
    await expect(issue({ issuer: iss, vct, claims: { cnf } }, ctx.key)).rejects.toThrow();
    const cred = await signed(ctx, { cnf });
    await expect(cred.verify(ctx.resolver, { skipStatus: true })).rejects.toMatchObject({ code: Code.Malformed });
  });

  it('is a Holder key with alg ES256K, use sig and key_ops verify', async () => {
    const ctx = issuer();
    const cnf = { jwk: { ...jwk, alg: 'ES256K', use: 'sig', key_ops: ['verify'] } };
    const cred = await issue({ issuer: iss, vct, claims: { cnf } }, ctx.key);
    await expect(cred.verify(ctx.resolver, { skipStatus: true })).rejects.toMatchObject({ code: Code.KBMissing });
  });
});

describe('dc issue: more Disclose paths than a Verifier reads disclosures', () => {
  it('refuses 1001 paths', async () => {
    const ctx = issuer();
    const claims = Object.fromEntries(Array.from({ length: 1001 }, (_, i) => [`c${i}`, i]));
    const disclose = Object.keys(claims).map((k) => [k]);
    await expect(issue({ issuer: iss, vct, claims, disclose }, ctx.key)).rejects.toThrow('1001 Disclose paths, at most 1000');
    await expect(issue({ issuer: iss, vct, claims, disclose: disclose.slice(1) }, ctx.key)).resolves.toBeDefined();
  });
});

describe('dc verify: iat, nbf and exp are NumericDates (RFC 7519 §2)', () => {
  it.each([
    ['exp past the range', { exp: 1e300 }],
    ['nbf before the range', { nbf: -1e300 }],
    ['iat past the range', { iat: 1e300 }],
    ['exp at the first value past the range', { exp: 9223371974719179007 }],
  ])('refuses %s', async (_name, extra) => {
    const ctx = issuer();
    const cred = await signed(ctx, extra);
    await expect(cred.verify(ctx.resolver, { skipStatus: true })).rejects.toMatchObject({ code: Code.Malformed });
  });

  it.each([
    ['a string', 'abc'],
    ['null', null],
    ['a number past the range', 1e300],
  ])('refuses a disclosed iat that is %s, and does not show the iat check an absent iat', async (_name, iat) => {
    const ctx = issuer();
    const d = disclosure('salt', 'iat', iat);
    const cred = await signed(ctx, { _sd_alg: 'sha-256', _sd: [digest(d)] }, d);
    const iatCheck = jest.fn();
    await expect(cred.verify(ctx.resolver, { skipStatus: true, iatCheck })).rejects.toMatchObject({ code: Code.Malformed });
    expect(iatCheck).not.toHaveBeenCalled();
  });

  it('reads a fraction and a disclosed iat', async () => {
    const ctx = issuer();
    const d = disclosure('salt', 'iat', 1700000000);
    const cred = await signed(ctx, { exp: 4102444800.5, _sd_alg: 'sha-256', _sd: [digest(d)] }, d);
    const res = await cred.verify(ctx.resolver, { skipStatus: true });
    expect(res.claims.iat).toBe(1700000000);
  });
});

describe('dc verify: nesting of the payload JSON', () => {
  const nested = (containers: number): unknown => (containers === 1 ? {} : { a: nested(containers - 1) });

  it('reads 65 levels as malformed, before the SD-JWT rules', async () => {
    const ctx = issuer();
    // The payload is one level; a holds 64 more.
    const cred = await signed(ctx, { a: nested(64) });
    await expect(cred.verify(ctx.resolver, { skipStatus: true })).rejects.toMatchObject({ code: Code.Malformed });
  });

  it('reads 64 levels as too deep for an SD-JWT', async () => {
    const ctx = issuer();
    const cred = await signed(ctx, { a: nested(63) });
    await expect(cred.verify(ctx.resolver, { skipStatus: true })).rejects.toMatchObject({ code: Code.DisclosureInvalid });
  });
});

describe('dc present: cnf with a sub-claim in a Disclosure', () => {
  it('is refused before a Key Binding JWT is signed', async () => {
    const ctx = issuer();
    const holder = p256.utils.randomPrivateKey();
    const pub = p256.getPublicKey(holder, false);
    const b64 = (b: Uint8Array): string => Buffer.from(b).toString('base64url');
    const d = disclosure('salt', 'kid', 'k');
    const cnf = { jwk: { kty: 'EC', crv: 'P-256', x: b64(pub.subarray(1, 33)), y: b64(pub.subarray(33)) }, _sd: [digest(d)] };
    const cred = await signed(ctx, { _sd_alg: 'sha-256', cnf }, d);
    const keyBinding = { signer: new P256Provider(bytesToHex(holder)), audience: 'https://v.example', nonce: 'n', issuedAt: new Date() };
    await expect(cred.present({ keyBinding })).rejects.toThrow('is in a disclosure');
  });
});

describe('dc verify: time is not rounded and iatCheck gets a real Date', () => {
  it('expires a credential at its fractional exp', async () => {
    const ctx = issuer();
    const cred = await signed(ctx, { exp: 1700000000.5 });
    const at = (ms: number) => cred.verify(ctx.resolver, { skipStatus: true, clockSkewSeconds: 0, now: new Date(ms) });
    await expect(at(1700000000400)).resolves.toBeDefined();
    await expect(at(1700000000700)).rejects.toMatchObject({ code: Code.Expired });
  });

  it('does not hand iatCheck a date it cannot hold', async () => {
    const ctx = issuer();
    const cred = await signed(ctx, { iat: 9e12 });
    const iatCheck = jest.fn();
    await expect(cred.verify(ctx.resolver, { skipStatus: true, iatCheck })).rejects.toMatchObject({ code: Code.IATCheckFailed });
    expect(iatCheck).not.toHaveBeenCalled();
    await expect(cred.verify(ctx.resolver, { skipStatus: true })).resolves.toBeDefined();
  });
});

describe('dc: the depth limit of 64 is told to whoever can act on it', () => {
  const nested = (containers: number): unknown => (containers === 1 ? {} : { a: nested(containers - 1) });

  it('verify reads a deep payload with a bad signature as a bad signature', async () => {
    const ctx = issuer();
    const cred = await signed(ctx, { a: nested(64) });
    const [jwt] = cred.serialize().split('~');
    const forged = new Credential(jwt.slice(0, -2) + (jwt.endsWith('AA') ? 'BB' : 'AA') + '~');
    await expect(forged.verify(ctx.resolver, { skipStatus: true })).rejects.toMatchObject({ code: Code.SignatureInvalid });
  });

  it('issue refuses claims 65 levels deep before the signer is asked', async () => {
    const ctx = issuer();
    const sign = jest.spyOn(ctx.key.signer, 'sign');
    await expect(issue({ issuer: iss, vct, claims: { a: nested(64) } }, ctx.key)).rejects.toThrow('claims: nesting deeper than 64');
    expect(sign).not.toHaveBeenCalled();
  });

  const wrap = (objects: number, leaf: unknown): unknown => (objects === 0 ? leaf : { a: wrap(objects - 1, leaf) });

  it('issue refuses, before the signer is asked, claims that concealing takes to 65 levels', async () => {
    const ctx = issuer();
    const sign = jest.spyOn(ctx.key.signer, 'sign');
    const claims = wrap(63, [1]) as Record<string, unknown>;
    const disclose = [[...Array(63).fill('a'), 0]];
    await expect(issue({ issuer: iss, vct, claims, disclose }, ctx.key)).rejects.toThrow('nesting deeper than 64');
    expect(sign).not.toHaveBeenCalled();
  });

  it('issue counts a Date as the string it serializes to', async () => {
    const ctx = issuer();
    const claims = wrap(63, { at: new Date(0) }) as Record<string, unknown>;
    await expect(issue({ issuer: iss, vct, claims }, ctx.key)).resolves.toBeInstanceOf(Credential);
  });

  it('present refuses Key Binding claims 65 levels deep before the signer is asked', async () => {
    const ctx = issuer();
    const holder = p256.utils.randomPrivateKey();
    const cred = await issue({ issuer: iss, vct, claims: {}, holderKey: p256.getPublicKey(holder, false) }, ctx.key);
    const signer = new P256Provider(bytesToHex(holder));
    const sign = jest.spyOn(signer, 'sign');
    const keyBinding = { signer, audience: 'https://v.example', nonce: 'n', issuedAt: new Date(), claims: { a: nested(64) } };
    await expect(cred.present({ keyBinding })).rejects.toThrow('KeyBinding claims: nesting deeper than 64');
    expect(sign).not.toHaveBeenCalled();
  });
});

describe('dc: claims are read as the JSON that is signed', () => {
  it('issue checks what a toJSON on the claims returns, not the object around it', async () => {
    const ctx = issuer();
    const claims = { a: 1, toJSON: () => ({ iss: 'https://other.example' }) };
    await expect(issue({ issuer: iss, vct, claims }, ctx.key)).rejects.toThrow('claims holds iss');
  });

  it('issue signs a value with toJSON as what it returns, however deep the object behind it', async () => {
    const ctx = issuer();
    let deep: Record<string, unknown> = {};
    for (let i = 0; i < 200_000; i++) deep = { a: deep };
    const cred = await issue({ issuer: iss, vct, claims: { a: { ...deep, toJSON: () => 's' } } }, ctx.key);
    const payload = JSON.parse(Buffer.from(cred.serialize().split('.')[1], 'base64url').toString());
    expect(payload.a).toBe('s');
  });

  it('present keeps aud, nonce and sd_hash when the Key Binding claims have a toJSON', async () => {
    const ctx = issuer();
    const holder = p256.utils.randomPrivateKey();
    const cred = await issue({ issuer: iss, vct, claims: {}, holderKey: p256.getPublicKey(holder, false) }, ctx.key);
    const keyBinding = {
      signer: new P256Provider(bytesToHex(holder)),
      audience: 'https://v.example',
      nonce: 'n',
      issuedAt: new Date(),
      claims: { toJSON: () => ({}) },
    };
    const kbJWT = (await cred.present({ keyBinding })).serialize().split('~').pop()!;
    const kb = JSON.parse(Buffer.from(kbJWT.split('.')[1], 'base64url').toString());
    expect(kb).toMatchObject({ aud: 'https://v.example', nonce: 'n', sd_hash: expect.any(String) });
  });

  it('a status list token refuses Other 65 levels deep before the signer is asked', async () => {
    const ctx = issuer();
    const sign = jest.spyOn(ctx.key.signer, 'sign');
    let other: Record<string, unknown> = {};
    for (let i = 0; i < 64; i++) other = { a: other };
    const token = List.new(16, 1).issueToken({ sub: uri, issuedAt: new Date(), other }, ctx.key);
    await expect(token).rejects.toThrow('statuslist: Other: nesting deeper than 64');
    expect(sign).not.toHaveBeenCalled();
  });

  it('present refuses, before the signer is asked, a toJSON that is deep only when the serializer asks', async () => {
    const ctx = issuer();
    const holder = p256.utils.randomPrivateKey();
    const cred = await issue({ issuer: iss, vct, claims: {}, holderKey: p256.getPublicKey(holder, false) }, ctx.key);
    const signer = new P256Provider(bytesToHex(holder));
    const sign = jest.spyOn(signer, 'sign');
    let deep: unknown = {};
    for (let i = 0; i < 64; i++) deep = { a: deep };
    const claims = { a: { toJSON: (key?: string) => (key === undefined ? 's' : deep) } };
    const keyBinding = { signer, audience: 'https://v.example', nonce: 'n', issuedAt: new Date(), claims };
    await expect(cred.present({ keyBinding })).rejects.toThrow('KeyBinding claims: nesting deeper than 64');
    expect(sign).not.toHaveBeenCalled();
  });

  it('issue reads a request whose fields are getters of its class', async () => {
    const ctx = issuer();
    class Request {
      claims = { a: 1 };
      get issuer() {
        return iss;
      }
      get vct() {
        return vct;
      }
    }
    await expect(issue(new Request(), ctx.key)).resolves.toBeInstanceOf(Credential);
  });
});

describe('dc: a Date that is not a date is not signed as null', () => {
  const bad = new Date(NaN);

  it('present refuses it as the time of the Key Binding', async () => {
    const ctx = issuer();
    const holder = p256.utils.randomPrivateKey();
    const cred = await issue({ issuer: iss, vct, claims: {}, holderKey: p256.getPublicKey(holder, false) }, ctx.key);
    const keyBinding = { signer: new P256Provider(bytesToHex(holder)), audience: 'https://v.example', nonce: 'n', issuedAt: bad };
    await expect(cred.present({ keyBinding })).rejects.toThrow('KeyBinding issuedAt is not a valid Date');
  });

  it.each([
    ['issuedAt', { issuedAt: bad }, 'IssuedAt is not a valid Date'],
    ['expiry', { issuedAt: new Date(), expiry: bad }, 'Expiry is not a valid Date'],
    ['a ttl of Infinity', { issuedAt: new Date(), ttlSeconds: Infinity }, 'TTL is not a finite number'],
    ['a ttl of NaN', { issuedAt: new Date(), ttlSeconds: NaN }, 'TTL is not a finite number'],
  ])('a status list token refuses %s', async (_name, claims, message) => {
    const ctx = issuer();
    await expect(List.new(16, 1).issueToken({ sub: uri, ...claims }, ctx.key)).rejects.toThrow(message);
  });
});
