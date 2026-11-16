import { deflateSync } from 'node:zlib';
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { P256Provider } from '../../src/common/signer/p256-provider';
import { DefaultProvider } from '../../src/common/signer/default-provider';
import { bytesToHex } from '../../src/common/crypto/hex';
import { blockedAddress } from '../../src/digitalcredential/internal/blocked';
import { metadataURL } from '../../src/digitalcredential/issuermeta';
import { issue, parse, StaticResolver, Code, PolicyError } from '../../src/digitalcredential';
import { ErrIssuerNotSupported } from '../../src/digitalcredential/issuerkey';
import { typIs, p256FromJWK, decodeJSONSegment, peekHeader, signCompactJWS, verifyCompactJWS } from '../../src/digitalcredential/jws-compact';
import { deepCopyMap } from '../../src/common/util/json';
import { hashDisclosure, reconstruct } from '../../src/common/sdjwt';
import { canonicalizeNQuads } from '../../src/common/processor/processor';
import { verifyProof } from '../../src/common/jsonmap/jsonmap';
import { load, staticResolver, integrity, ErrViolated } from '../../src/digitalcredential/typemeta';
import { decodeList } from '../../src/digitalcredential/statuslist';
import { get, ErrBodyTooLarge } from '../../src/digitalcredential/internal/safehttp';

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

describe('PR #11 review: compact JWS crit/b64 and typ', () => {
  it('refuses crit and b64 in peekHeader and verifyCompactJWS', async () => {
    const ctx = issuer();
    const token = await signCompactJWS({ alg: 'ES256', typ: 'dc+sd-jwt' }, { iss: ctx.iss }, ctx.key.signer);
    const parts = token.split('.');
    const withCrit = `${Buffer.from(JSON.stringify({ alg: 'ES256', crit: ['exp'] })).toString('base64url')}.${parts[1]}.${parts[2]}`;
    const withB64 = `${Buffer.from(JSON.stringify({ alg: 'ES256', b64: false })).toString('base64url')}.${parts[1]}.${parts[2]}`;
    expect(() => peekHeader(withCrit)).toThrow(/crit or b64/);
    expect(() => peekHeader(withB64)).toThrow(/crit or b64/);
    expect(() => verifyCompactJWS(withCrit, ctx.key.publicKey)).toThrow(/crit or b64/);
    await expect(parse(withCrit + '~').verify(ctx.resolver)).rejects.toMatchObject({ code: Code.Malformed });
  });

  it('typIs refuses parameters and matches ASCII case only', () => {
    expect(typIs('dc+sd-jwt; charset=utf-8', 'dc+sd-jwt')).toBe(false);
    expect(typIs('DC+SD-JWT', 'dc+sd-jwt')).toBe(true);
    expect(typIs('application/dc+sd-jwt', 'dc+sd-jwt')).toBe(true);
  });
});

describe('PR #11 review: ES256K KB-JWT', () => {
  it('issues, presents, and verifies secp256k1 Key Binding', async () => {
    const issPriv = secp256k1.utils.randomPrivateKey();
    const issPub = secp256k1.getPublicKey(issPriv, false);
    const holdPriv = secp256k1.utils.randomPrivateKey();
    const holdPub = secp256k1.getPublicKey(holdPriv, false);
    const iss = 'https://issuer.example';
    const key = { signer: new DefaultProvider(bytesToHex(issPriv)), publicKey: issPub, kid: 'k1' as const, alg: 'ES256K' as const };
    const cred = await issue(
      {
        issuer: iss,
        vct: 'https://credentials.example/id',
        issuedAt: new Date(),
        holderKey: holdPub,
        claims: { given_name: 'Erika' },
      },
      key,
    );
    const presented = await cred.present({
      keyBinding: {
        signer: new DefaultProvider(bytesToHex(holdPriv)),
        audience: 'https://verifier.example',
        nonce: 'n1',
        issuedAt: new Date(),
      },
    });
    const res = await presented.verify(new StaticResolver(iss, [{ kid: 'k1', publicKey: issPub }]), {
      audience: 'https://verifier.example',
      nonce: 'n1',
    });
    expect(res.keyBound).toBe(true);
  });
});

describe('PR #11 review: JwtProof2020 proof set', () => {
  const resolver = { resolveDocument: async () => ({ id: 'did:ex:1', verificationMethod: [] }) };
  it('allows a one-element proof array', async () => {
    try {
      await verifyProof({ proof: [{ type: 'JwtProof2020', jwt: 'a.b.c' }] }, resolver as never);
    } catch (err) {
      expect((err as Error).message).not.toMatch(/only proof/);
    }
  });
  it('refuses JwtProof2020 when another proof is present', async () => {
    await expect(
      verifyProof(
        {
          proof: [
            { type: 'JwtProof2020', jwt: 'a.b.c' },
            { type: 'DataIntegrityProof', cryptosuite: 'ecdsa-rdfc-2019' },
          ],
        },
        resolver as never,
      ),
    ).rejects.toThrow(/only proof/);
  });
});

describe('PR #11 review: type metadata sd/mandatory', () => {
  async function meta(claim: object) {
    const doc = Buffer.from(
      JSON.stringify({
        vct: 'https://a.example/t',
        claims: [claim],
      }),
    );
    return load(staticResolver(doc), { vct: 'https://a.example/t', integrity: integrity(doc) });
  }

  it('fails sd always on a clear claim and sd never on a disclosed claim', async () => {
    const always = await meta({ path: ['x'], sd: 'always' });
    expect(() => always.validateClaims({ x: 1 }, { issued: { x: 1 } })).toThrow();
    try {
      always.validateClaims({ x: 1 }, { issued: { x: 1 } });
    } catch (err) {
      expect((err as { cause?: unknown }).cause).toBe(ErrViolated);
    }
    const never = await meta({ path: ['x'], sd: 'never' });
    expect(() => never.validateClaims({ x: 1 }, { issued: { _sd: ['d'] } })).toThrow();
  });

  it('does not treat a still-hidden mandatory claim as missing', async () => {
    const m = await meta({ path: ['x'], mandatory: true });
    m.validateClaims({}, { issued: { _sd: ['a', 'b'] } });
    expect(() => m.validateClaims({}, { issued: {} })).toThrow();
  });
});

describe('PR #11 review: WithExtendedVCTMatch policy', () => {
  it('errors when the flag is set without accepted VCTs and type metadata', async () => {
    const ctx = issuer();
    const cred = await issue({ issuer: ctx.iss, vct: 'https://example/t', claims: { n: 'x' } }, ctx.key);
    await expect(cred.verify(ctx.resolver, { extendedVCTMatch: true })).rejects.toBeInstanceOf(PolicyError);
  });
});

describe('PR #11 review: status-list inflate and fetch cap', () => {
  it('refuses an lst that inflates past the output cap', () => {
    const raw = deflateSync(Buffer.alloc(17 << 20));
    expect(() => decodeList(raw.toString('base64url'), 1)).toThrow(/inflates past/);
  });

  it('refuses a custom fetch with no readable body', async () => {
    await expect(
      get('https://example.invalid/x', ['application/json'], {
        timeoutMs: 1000,
        maxRedirects: 0,
        maxBytes: 16,
        fetch: (async () => ({ status: 200, headers: new Headers(), body: null }) as never),
      }),
    ).rejects.toBe(ErrBodyTooLarge);
  });
});
