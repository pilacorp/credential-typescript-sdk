/** 6.1-6.4 signer namespace, function-backed signers, algorithm helpers; 6.13 didv2 VM ops. */
import { p256 } from '@noble/curves/nist';
import * as sdk from '../src';
import * as legacyVmOps from '../src/did/vm-ops';

describe('signer namespace (6.1)', () => {
  it('is exported with the providers and helpers', () => {
    expect(sdk.signer.DefaultProvider).toBe(sdk.DefaultProvider);
    expect(sdk.signer.P256Provider).toBe(sdk.P256Provider);
    expect(typeof sdk.signer.newRSAFunc).toBe('function');
    expect(typeof sdk.signer.algorithmOf).toBe('function');
  });
});

describe('P256Provider (6.2)', () => {
  const priv = '06'.repeat(32);
  const digest = new Uint8Array(32).fill(9);

  it('keeps the hex constructor and accepts raw bytes (newP256Provider)', () => {
    const a = new sdk.P256Provider(priv);
    const b = sdk.signer.newP256Provider(new Uint8Array(32).fill(6));
    expect(a.sign(digest)).toEqual(b.sign(digest)); // sync, deterministic RFC 6979
    expect(a.publicKeyUncompressed()).toEqual(p256.getPublicKey(new Uint8Array(32).fill(6), false));
  });

  it('delegates to a callback (HSM/KMS), sync or async, and checks the 64-byte result', async () => {
    const inner = new sdk.P256Provider(priv);
    const sync = sdk.signer.newP256Func((d) => inner.sign(d));
    expect(sync).toBeInstanceOf(sdk.P256Provider);
    expect(await sync.sign(digest)).toEqual(inner.sign(digest));
    const async_ = sdk.P256Provider.fromFunc(async (d) => inner.sign(d));
    expect(await async_.sign(digest)).toEqual(inner.sign(digest));
    expect(async_.publicKeyUncompressed()).toBeUndefined();
    await expect(sdk.signer.newP256Func(async () => new Uint8Array(65)).sign(digest)).rejects.toThrow(/64-byte/);
    expect(() => sdk.signer.newP256Func(null as never)).toThrow(/nil/);
    expect(() => sync.sign(new Uint8Array(31))).toThrow(/32 bytes/);
  });

  it('rejects an out-of-range scalar', () => {
    expect(() => new sdk.P256Provider('00'.repeat(32))).toThrow();
  });
});

describe('AlgorithmProvider / AlgorithmOf (6.3, 6.4)', () => {
  it('defaults to RS256 and honours a declared algorithm', () => {
    expect(sdk.signer.algorithmOf(new sdk.DefaultProvider('11'.repeat(32)))).toBe('RS256');
    expect(sdk.signer.algorithmOf(sdk.signer.newRSAFunc(() => new Uint8Array(256), 'PS384'))).toBe('PS384');
    expect(sdk.signer.algorithmOf(new sdk.P256Provider('06'.repeat(32)))).toBe('ES256');
  });
  it('picks the JOSE alg from the key kind', () => {
    expect(sdk.signer.algForKeyKind('secp256k1')).toBe('ES256K');
    expect(sdk.signer.algForKeyKind('P-256')).toBe('ES256');
    expect(sdk.signer.algForKeyKind('RSA', sdk.signer.newRSAFunc(() => new Uint8Array(), 'RS512'))).toBe('RS512');
    expect(() => sdk.signer.algForKeyKind('ed25519' as never)).toThrow();
  });
});

describe('didv2 VM operations (6.13)', () => {
  it('are exposed under didv2 and the old did exports are aliases', () => {
    for (const name of [
      'addVerificationMethod',
      'rotateVerificationMethod',
      'revokeVerificationMethod',
      'addVerificationMethodPurposes',
      'removeVerificationMethodPurposes',
    ] as const) {
      expect(sdk.didv2[name]).toBe(sdk.did[name]);
      expect(legacyVmOps[name]).toBe(sdk.didv2[name]);
    }
    expect(sdk.didv2.findVerificationMethod).toBe(legacyVmOps.findVerificationMethod);
  });
});
