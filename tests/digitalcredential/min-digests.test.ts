import { createHash } from 'node:crypto';
import { p256 } from '@noble/curves/nist';
import { P256Provider } from '../../src/common/signer/p256-provider';
import { bytesToHex } from '../../src/common/crypto/hex';
import { issue, StaticResolver, Code, type Credential } from '../../src/digitalcredential';
import { ErrIssuerNotSupported } from '../../src/digitalcredential/issuerkey';
import { load, staticResolver, integrity } from '../../src/digitalcredential/typemeta';

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

type JSONObject = Record<string, unknown>;

function payloadOf(c: Credential): JSONObject {
  return JSON.parse(Buffer.from(c.compact.split('~')[0].split('.')[1], 'base64url').toString());
}

/** Each disclosure as [name, value] for a property and [undefined, value] for an array element. */
function disclosuresOf(c: Credential): Array<{ raw: string; name?: string; value: unknown }> {
  return c.compact
    .split('~')
    .slice(1)
    .filter(Boolean)
    .map((raw) => {
      const arr = JSON.parse(Buffer.from(raw, 'base64url').toString()) as unknown[];
      return arr.length === 3 ? { raw, name: arr[1] as string, value: arr[2] } : { raw, value: arr[1] };
    });
}

const isPlaceholder = (el: unknown): boolean =>
  !!el && typeof el === 'object' && !Array.isArray(el) && Object.keys(el).length === 1 && '...' in el;
const placeholders = (arr: unknown): number => (arr as unknown[]).filter(isPlaceholder).length;
const readable = (arr: unknown): unknown[] => (arr as unknown[]).filter((el) => !isPlaceholder(el));

function metadataDoc(claims: object[]): Buffer {
  return Buffer.from(JSON.stringify({ vct, claims }));
}

describe('dc issue: minDigests', () => {
  it('pads every array of the payload with decoy placeholders', async () => {
    const ctx = issuer();
    const claims = { nat: ['DE', 'FR', 'VN'], plain: [1, 2], a: 1 };
    const cred = await issue({ issuer: iss, vct, claims, disclose: [['nat', 0], ['a']], minDigests: 3 }, ctx.key);
    const payload = payloadOf(cred);
    expect(placeholders(payload.nat)).toBe(3);
    expect(readable(payload.nat)).toEqual(['FR', 'VN']);
    expect(placeholders(payload.plain)).toBe(3);
    expect(readable(payload.plain)).toEqual([1, 2]);
    const res = await cred.verify(ctx.resolver);
    expect(res.claims.nat).toEqual(['DE', 'FR', 'VN']);
    expect(res.claims.plain).toEqual([1, 2]);
  });

  it('pads the objects and arrays inside a disclosed value', async () => {
    const ctx = issuer();
    const claims = { address: { city: 'c', geo: { lat: 1 }, tags: ['x'] }, objs: [{ a: 1 }] };
    const cred = await issue(
      { issuer: iss, vct, claims, disclose: [['address'], ['objs', 0]], minDigests: 3 },
      ctx.key,
    );
    const ds = disclosuresOf(cred);
    const address = ds.find((d) => d.name === 'address')!.value as JSONObject;
    expect(address._sd).toHaveLength(3);
    expect((address.geo as JSONObject)._sd).toHaveLength(3);
    expect(placeholders(address.tags)).toBe(3);
    const element = ds.find((d) => d.name === undefined)!.value as JSONObject;
    expect(element._sd).toHaveLength(3);
    const res = await cred.verify(ctx.resolver);
    expect(res.claims.address).toEqual(claims.address);
    expect(res.claims.objs).toEqual(claims.objs);
  });

  it('puts no decoy in a claim that is never selectively disclosable', async () => {
    const ctx = issuer();
    const holder = p256.getPublicKey(p256.utils.randomPrivateKey(), false);
    const jwk = {
      kty: 'EC',
      crv: 'P-256',
      x: Buffer.from(holder.subarray(1, 33)).toString('base64url'),
      y: Buffer.from(holder.subarray(33)).toString('base64url'),
    };
    const protectedClaims = {
      cnf: { jwk },
      status: { status_list: { idx: 1, uri: 'https://s.example/1' } },
      aka_vcts: ['https://b.example/t'],
    };
    const cred = await issue(
      { issuer: iss, vct, claims: { a: 1, sub: 's', ...protectedClaims }, disclose: [['a']], minDigests: 2 },
      ctx.key,
    );
    const payload = payloadOf(cred);
    expect(payload.cnf).toEqual(protectedClaims.cnf);
    expect(payload.status).toEqual(protectedClaims.status);
    expect(payload.aka_vcts).toEqual(protectedClaims.aka_vcts);
    expect(payload._sd).toHaveLength(2);
  });

  it('refuses a minDigests that asks for more than 20000 decoys', async () => {
    const ctx = issuer();
    // 22 objects and arrays: the claims, the array and its 20 objects.
    const claims = { a: 1, list: Array.from({ length: 20 }, (_, i) => ({ i })) };
    await expect(issue({ issuer: iss, vct, claims, disclose: [['a']], minDigests: 1000 }, ctx.key)).rejects.toThrow(
      /20000/,
    );
    await issue({ issuer: iss, vct, claims, disclose: [['a']], minDigests: 900 }, ctx.key);
  });
});

describe('dc issue: _sd order', () => {
  it('hides the order of the digests inside a disclosed parent', async () => {
    const ctx = issuer();
    const digest = (raw: string) => createHash('sha256').update(raw).digest('base64url');
    const orders = new Set<string>();
    for (let i = 0; i < 20; i++) {
      const cred = await issue(
        {
          issuer: iss,
          vct,
          claims: { o: { a: 1, b: 2, c: 3, d: 4 } },
          disclose: [['o'], ['o', 'a'], ['o', 'b'], ['o', 'c'], ['o', 'd']],
        },
        ctx.key,
      );
      const ds = disclosuresOf(cred);
      const parent = ds.find((d) => d.name === 'o')!.value as { _sd: string[] };
      orders.add(parent._sd.map((h) => ds.find((d) => digest(d.raw) === h)!.name).join(''));
    }
    expect(orders.size).toBeGreaterThan(1);
  });
});

describe('dc issue: typeMetadata', () => {
  const ref = { vct };

  it('adds no decoy to an array, so the indexes of the claim metadata hold', async () => {
    const ctx = issuer();
    const doc = metadataDoc([
      { path: ['nat', null], sd: 'never' },
      { path: ['a'], sd: 'always' },
    ]);
    const typeMetadata = await load(staticResolver(doc), ref);
    const req = { issuer: iss, vct, claims: { nat: ['DE', 'FR'], a: 1 }, disclose: [['a']], minDigests: 3 };

    const cred = await issue({ ...req, typeMetadata }, ctx.key);
    expect(payloadOf(cred).nat).toEqual(['DE', 'FR']);
    expect(payloadOf(cred)._sd).toHaveLength(3);
    await cred.verify(ctx.resolver, { types: staticResolver(doc) });

    const withArrayDecoys = await issue(req, ctx.key);
    await expect(withArrayDecoys.verify(ctx.resolver, { types: staticResolver(doc) })).rejects.toMatchObject({
      code: Code.TypeMetadataViolated,
    });
  });

  it('refuses claims that break the claim metadata', async () => {
    const ctx = issuer();
    const never = await load(staticResolver(metadataDoc([{ path: ['a'], sd: 'never' }])), ref);
    await expect(
      issue({ issuer: iss, vct, claims: { a: 1 }, disclose: [['a']], typeMetadata: never }, ctx.key),
    ).rejects.toThrow(/sd is never/);
    const always = await load(staticResolver(metadataDoc([{ path: ['o', 'x'], sd: 'always' }])), ref);
    await expect(
      issue({ issuer: iss, vct, claims: { o: { x: 1 } }, disclose: [['o']], typeMetadata: always }, ctx.key),
    ).rejects.toThrow(/sd is always/);
    const mandatory = await load(staticResolver(metadataDoc([{ path: ['b'], mandatory: true }])), ref);
    await expect(
      issue({ issuer: iss, vct, claims: { a: 1 }, disclose: [['a']], typeMetadata: mandatory }, ctx.key),
    ).rejects.toThrow(/mandatory/);
    await issue({ issuer: iss, vct, claims: { a: 1, b: 2 }, disclose: [['b']], typeMetadata: mandatory }, ctx.key);
  });

  it('refuses the Type Metadata of another type or of another document', async () => {
    const ctx = issuer();
    const doc = metadataDoc([]);
    const typeMetadata = await load(staticResolver(doc), ref);
    await expect(issue({ issuer: iss, vct: 'https://a.example/other', typeMetadata }, ctx.key)).rejects.toThrow(
      /typeMetadata/,
    );
    const other = integrity(Buffer.from('another document'));
    await expect(
      issue({ issuer: iss, vct, claims: { 'vct#integrity': other }, typeMetadata }, ctx.key),
    ).rejects.toThrow(/vct#integrity/);
    await issue({ issuer: iss, vct, claims: { 'vct#integrity': integrity(doc) }, typeMetadata }, ctx.key);
  });
});

describe('dc verify: issuer key errors', () => {
  it('finds ErrIssuerNotSupported among the errors of an AggregateError', async () => {
    const ctx = issuer();
    const cred = await issue({ issuer: iss, vct }, ctx.key);
    const refused = Object.assign(new Error('this resolver does not serve the issuer'), {
      cause: ErrIssuerNotSupported,
    });
    const AggregateErrorCtor = (globalThis as unknown as { AggregateError: new (errors: unknown[], m: string) => Error })
      .AggregateError;
    const resolver = {
      async keys(): Promise<never> {
        throw new AggregateErrorCtor([new Error('timeout'), refused], 'every resolver failed');
      },
    };
    await expect(cred.verify(resolver)).rejects.toMatchObject({ code: Code.IssuerNotSupported });
  });
});
