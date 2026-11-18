import { p256 } from '@noble/curves/nist';
import { P256Provider } from '../../src/common/signer/p256-provider';
import { bytesToHex } from '../../src/common/crypto/hex';
import { buildDisclosures } from '../../src/common/sdjwt';
import { hasOwn } from '../../src/common/util/json';
import { issue, StaticResolver, Code, type IssueRequest } from '../../src/digitalcredential';
import { staticResolver } from '../../src/digitalcredential/typemeta';

const iss = 'https://issuer.example';
const vct = 'https://a.example/t';

function issuer() {
  const priv = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(priv, false);
  return {
    key: { signer: new P256Provider(bytesToHex(priv)), publicKey: pub, kid: 'key-1' },
    resolver: new StaticResolver(iss, [{ kid: 'key-1', publicKey: pub }]),
  };
}

const jwk = { kty: 'EC', crv: 'P-256', x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU', y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0' };

describe('dc issue: claims a Verifier reads as malformed are refused', () => {
  const bad: Array<[string, Partial<IssueRequest>, RegExp]> = [
    ['cnf null', { claims: { cnf: null } }, /cnf is not a JSON object/],
    ['cnf a string', { claims: { cnf: 'x' } }, /cnf is not a JSON object/],
    ['cnf with jwk and jku', { claims: { cnf: { jwk, jku: 'https://a.example/k' } } }, /more than one of jwk, jwe and jku/],
    ['cnf.jwk a string', { claims: { cnf: { jwk: 'x' } } }, /cnf\.jwk is not a JSON object/],
    ['iat past the dates a NumericDate holds', { claims: { iat: 1e300 } }, /iat is not a NumericDate/],
    ['exp before them', { claims: { exp: -1e300 } }, /exp is not a NumericDate/],
    ['aud a number', { claims: { aud: 5 } }, /aud is not a string or an array of strings/],
    ['aud an array with a number', { claims: { aud: ['a', 1] } }, /aud is not a string or an array of strings/],
    ['status idx a fraction', { status: { idx: 1.5, uri: 'https://a.example/s' } }, /status ref is invalid/],
    ['status idx NaN', { status: { idx: NaN, uri: 'https://a.example/s' } }, /status ref is invalid/],
    ['status idx negative', { status: { idx: -1, uri: 'https://a.example/s' } }, /negative/],
    ['claims status idx past every list', { claims: { status: { status_list: { idx: 1e30, uri: 'https://a.example/s' } } } }, /past every status list/],
    ['issuedAt an invalid Date', { issuedAt: new Date(NaN) }, /issuedAt is not a valid Date/],
    ['expiry an invalid Date', { expiry: new Date('x') }, /expiry is not a valid Date/],
  ];
  it.each(bad)('%s', async (_name, part, message) => {
    await expect(issue({ issuer: iss, vct, ...part }, issuer().key)).rejects.toThrow(message);
  });

  it('signs the forms a Verifier reads', async () => {
    const ctx = issuer();
    const cred = await issue(
      {
        issuer: iss,
        vct,
        claims: { aud: ['a', 'b'], iat: 1700000000.5 },
        status: { idx: 0, uri: 'https://a.example/s' },
      },
      ctx.key,
    );
    const res = await cred.verify(ctx.resolver, { credentialAudience: 'a', skipStatus: true });
    expect(res.claims.aud).toEqual(['a', 'b']);
  });
});

describe('dc issue: disclose paths are read on the claims as given', () => {
  it('refuses a path naming what an earlier path wrote', async () => {
    await expect(
      issue({ issuer: iss, vct, claims: { a: { b: 1 } }, disclose: [['a', 'b'], ['a', '_sd']] }, issuer().key),
    ).rejects.toThrow(/does not exist in the claims/);
  });

  it('refuses a path given twice', async () => {
    await expect(
      issue({ issuer: iss, vct, claims: { a: 1 }, disclose: [['a'], ['a']] }, issuer().key),
    ).rejects.toThrow(/given twice/);
  });

  it('does not conceal a value the claims only inherit', () => {
    expect(() => buildDisclosures({ vc: { a: 1 }, selectivePaths: ['toString'] })).toThrow();
    expect(() => buildDisclosures({ vc: { a: 1 }, selectivePaths: ['constructor[0]'] })).toThrow();
  });
});

describe('dc verify: a claim named __proto__', () => {
  const claims = JSON.parse('{"a":1,"__proto__":{"exp":1}}') as Record<string, unknown>;

  it('stays a claim and gives the credential no exp', async () => {
    const ctx = issuer();
    const cred = await issue({ issuer: iss, vct, claims, disclose: [['__proto__']] }, ctx.key);
    const res = await cred.verify(ctx.resolver);
    expect(Object.getPrototypeOf(res.claims)).toBe(Object.prototype);
    expect(hasOwn(res.claims, '__proto__')).toBe(true);
    expect(res.claims.exp).toBeUndefined();
  });

  it('is checked against the claim metadata', async () => {
    const ctx = issuer();
    const cred = await issue({ issuer: iss, vct, claims, disclose: [['__proto__']] }, ctx.key);
    const doc = Buffer.from(JSON.stringify({ vct, claims: [{ path: ['__proto__'], sd: 'never' }] }));
    await expect(cred.verify(ctx.resolver, { types: staticResolver(doc) })).rejects.toMatchObject({
      code: Code.TypeMetadataViolated,
    });
  });
});

describe('dc verify: claim metadata over the work limit', () => {
  it('is Type Metadata the SDK cannot process', async () => {
    const ctx = issuer();
    const arr = Array.from({ length: 2000 }, () => ({}));
    const cred = await issue({ issuer: iss, vct, claims: { arr } }, ctx.key);
    const paths = Array.from({ length: 300 }, (_, i) => ({ path: ['arr', null, `k${i}`] }));
    const doc = Buffer.from(JSON.stringify({ vct, claims: paths }));
    await expect(cred.verify(ctx.resolver, { types: staticResolver(doc) })).rejects.toMatchObject({
      code: Code.TypeMetadataInvalid,
    });
    const few = Buffer.from(JSON.stringify({ vct, claims: paths.slice(0, 100) }));
    await cred.verify(ctx.resolver, { types: staticResolver(few) });
  });
});
