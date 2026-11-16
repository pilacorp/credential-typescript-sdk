import { p256 } from '@noble/curves/nist';
import { P256Provider } from '../../src/common/signer/p256-provider';
import { bytesToHex } from '../../src/common/crypto/hex';
import { blockedAddress } from '../../src/digitalcredential/internal/blocked';
import { metadataURL } from '../../src/digitalcredential/issuermeta';
import { issue, parse, StaticResolver, Code, PolicyError, DigitalCredentialError } from '../../src/digitalcredential';
import { ErrIssuerNotSupported } from '../../src/digitalcredential/issuerkey';
import { typIs, p256FromJWK, decodeJSONSegment } from '../../src/digitalcredential/jws-compact';
import { deepCopyMap } from '../../src/common/util/json';
import { hashDisclosure, reconstruct } from '../../src/common/sdjwt';
import { canonicalizeNQuads } from '../../src/common/processor/processor';

function issuer() {
  const priv = p256.utils.randomPrivateKey();
  const pub = p256.getPublicKey(priv, false);
  const holderPriv = p256.utils.randomPrivateKey();
  const holderPub = p256.getPublicKey(holderPriv, false);
  return {
    iss: 'https://issuer.example',
    key: { signer: new P256Provider(bytesToHex(priv)), publicKey: pub, kid: 'key-1' as const },
    resolver: new StaticResolver('https://issuer.example', [{ kid: 'key-1', publicKey: pub }]),
    holderPriv,
    holderPub,
  };
}

describe('PR #11 review: blocked IPv6-mapped IPv4', () => {
  it.each(['::1', '::', '::ffff:7f00:1', '64:ff9b::a9fe:a9fe', '2002:7f00:1::1'])(
    'blocks %s',
    (ip) => {
      expect(blockedAddress(ip)).toBe(true);
    },
  );
});

describe('PR #11 review: issuermeta path', () => {
  it('refuses dot and dot-dot path segments', () => {
    expect(() => metadataURL('https://issuer.example/a/../../files/keys.json')).toThrow(/"\." or "\.\."/);
    expect(() => metadataURL('https://issuer.example/a/%2e%2e/files')).toThrow(/"\." or "\.\."/);
    try {
      metadataURL('https://issuer.example/a/../x');
    } catch (err) {
      expect((err as { cause?: unknown }).cause).toBe(ErrIssuerNotSupported);
    }
  });
});

describe('PR #11 review: dc+sd-jwt verify/issue/present', () => {
  it('requires audience and nonce for a KB-JWT', async () => {
    const ctx = issuer();
    const cred = await issue(
      {
        issuer: ctx.iss,
        vct: 'https://credentials.example/id',
        issuedAt: new Date(),
        holderKey: ctx.holderPub,
        claims: { given_name: 'Erika', child: { name: 'A' } },
        disclose: [['given_name'], ['child', 'name']],
      },
      ctx.key,
    );
    const presented = await cred.present({
      reveal: [['given_name']],
      keyBinding: {
        signer: new P256Provider(bytesToHex(ctx.holderPriv)),
        audience: 'https://verifier.example',
        nonce: 'n1',
        issuedAt: new Date(),
      },
    });
    await expect(presented.verify(ctx.resolver)).rejects.toBeInstanceOf(PolicyError);
    const res = await presented.verify(ctx.resolver, { audience: 'https://verifier.example', nonce: 'n1' });
    expect(res.keyBound).toBe(true);
    expect(res.claims.given_name).toBe('Erika');
    expect(res.claims.child).toEqual({});
  });

  it('does not reveal child.name when reveal is only name', async () => {
    const ctx = issuer();
    const cred = await issue(
      {
        issuer: ctx.iss,
        vct: 'https://credentials.example/id',
        claims: { name: 'Erika', child: { name: 'hidden' } },
        disclose: [['name'], ['child', 'name']],
      },
      ctx.key,
    );
    const presented = await cred.present({ reveal: [['name']] });
    const res = await presented.verify(ctx.resolver);
    expect(res.claims.name).toBe('Erika');
    expect(res.claims.child).toEqual({});
  });

  it('conceals array indexes and nested paths deepest first', async () => {
    const ctx = issuer();
    const cred = await issue(
      {
        issuer: ctx.iss,
        vct: 'https://credentials.example/id',
        claims: { nat: ['DE', 'FR'], address: { street: 'A', city: 'B' } },
        disclose: [['address'], ['address', 'street'], ['nat', 0]],
      },
      ctx.key,
    );
    const hidden = await cred.present({ reveal: [] });
    const hiddenRes = await hidden.verify(ctx.resolver);
    expect(hiddenRes.claims.nat).toEqual(['FR']);
    const presented = await cred.present({ reveal: [['nat', 0], ['address', 'street']] });
    const res = await presented.verify(ctx.resolver);
    expect(res.claims.nat).toEqual(['DE', 'FR']);
    expect((res.claims.address as { street: string }).street).toBe('A');
  });

  it('refuses owned claims at issue time', async () => {
    const ctx = issuer();
    await expect(
      issue({ issuer: ctx.iss, vct: 'https://example/t', claims: { iss: 'https://other' } }, ctx.key),
    ).rejects.toThrow(/claims holds iss/);
  });

  it('refuses empty aka_vcts and aka_vcts equal to vct', async () => {
    const ctx = issuer();
    await expect(
      issue({ issuer: ctx.iss, vct: 'https://example/t', claims: { aka_vcts: [] } }, ctx.key),
    ).rejects.toThrow(/aka_vcts/);
    await expect(
      issue({ issuer: ctx.iss, vct: 'https://example/t', claims: { aka_vcts: ['https://example/t'] } }, ctx.key),
    ).rejects.toThrow(/aka_vcts/);
  });

  it('maps non-JSON payload to MALFORMED', async () => {
    expect(() => decodeJSONSegment(Buffer.from('not-json').toString('base64url'))).toThrow(/JSON object/);
  });

  it('typIs accepts application/ prefix', () => {
    expect(typIs('application/dc+sd-jwt', 'dc+sd-jwt')).toBe(true);
    expect(typIs('DC+SD-JWT', 'dc+sd-jwt')).toBe(true);
  });

  it('refuses a JWK with d or short coordinates', () => {
    expect(() => p256FromJWK({ kty: 'EC', crv: 'P-256', x: 'YQ', y: 'YQ', d: 'YQ' })).toThrow(/private key/);
    const short = Buffer.from([1]).toString('base64url');
    expect(() => p256FromJWK({ kty: 'EC', crv: 'P-256', x: short, y: short })).toThrow(/32 bytes/);
  });

  it('rejectFutureIAT and iatCheck', async () => {
    const ctx = issuer();
    const cred = await issue(
      {
        issuer: ctx.iss,
        vct: 'https://example/t',
        issuedAt: new Date(Date.now() + 3600_000),
        claims: { given_name: 'Erika' },
      },
      ctx.key,
    );
    await expect(parse(cred.serialize()).verify(ctx.resolver, { rejectFutureIAT: true, clockSkewSeconds: 0 })).rejects.toMatchObject({
      code: Code.NotYetValid,
    });
    await expect(
      parse(cred.serialize()).verify(ctx.resolver, {
        iatCheck: () => {
          throw new Error('policy');
        },
      }),
    ).rejects.toMatchObject({ code: Code.IATCheckFailed });
  });
});

describe('PR #11 review: copies and reconstruction', () => {
  it('deep-copies an own constructor property', () => {
    const src = { name: 'Alice', constructor: 'x' };
    const copy = deepCopyMap(src);
    expect(copy.constructor).toBe('x');
    copy.name = 'Bob';
    expect(src.name).toBe('Alice');
  });

  it('allows reconstructing a constructor claim', () => {
    const payload = { _sd_alg: 'sha-256', _sd: [] as string[] };
    const disc = Buffer.from(JSON.stringify(['salt', 'constructor', 'x'])).toString('base64url');
    payload._sd.push(hashDisclosure('sha-256', disc));
    const out = reconstruct(payload, [disc], true);
    expect(out.constructor).toBe('x');
  });
});

describe('PR #11 review: N-Quads TAB', () => {
  it('escapes TAB in literals', async () => {
    const nq = await canonicalizeNQuads({
      '@id': 'http://example/s',
      'http://example/p': { '@value': 'a\tb' },
    });
    expect(nq.join('')).toContain('\\t');
  });
});
