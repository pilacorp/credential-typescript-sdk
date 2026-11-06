/** Review gaps 5.7-5.10, 5.13-5.15, 5.20, 6.5 (verification-method helpers vs Go). */
import { p256 } from '@noble/curves/nist';
import { secp256k1 } from '@noble/curves/secp256k1';
import { generateKeyPairSync } from 'node:crypto';
import {
  HTTPResolver,
  StaticResolver,
  newDIDDocument,
  newP256MultikeyVM,
  newP256VM,
  newRSAVM,
  newSecp256k1VM,
  pathEscape,
  publicKeyHexFromVM,
  resolveSigningVM,
  resolveVerificationMethodURLForKey,
  selectLatestActiveVMForKey,
  selectLatestActiveVMForPurpose,
  decodeP256SecretMultibase,
  isP256PublicMultibase,
  vmKeyKind,
  type DIDDocument,
  type VerificationMethodEntry,
} from '../../src/common/verification-method';
import { bytesToHex } from '../../src/common/crypto/hex';
import { encodeBase58Btc } from '../../src/common/util/multibase';
import { addVerificationMethod } from '../../src/didv2';

const did = 'did:nda:0xabc';
const secpPub = `0x${bytesToHex(secp256k1.getPublicKey(new Uint8Array(32).fill(5), false))}`;
const p256Pub = p256.getPublicKey(new Uint8Array(32).fill(6), true);

const pub33 = (n: number) => `0x${bytesToHex(secp256k1.getPublicKey(new Uint8Array(32).fill(n), true))}`;
function vm(id: string): VerificationMethodEntry {
  return { id, type: 'EcdsaSecp256k1VerificationKey2019', controller: did, publicKeyHex: secpPub };
}
function docOf(vms: VerificationMethodEntry[]): DIDDocument {
  return { ...newDIDDocument(did, ...vms), authentication: vms.map((v) => v.id), assertionMethod: vms.map((v) => v.id) };
}

describe('5.7 latest-active ties go to the larger id', () => {
  test('VMs without a sequential fragment', () => {
    const a = docOf([vm(`${did}#a`), vm(`${did}#b`)]);
    expect(selectLatestActiveVMForPurpose(a, 'authentication').id).toBe(`${did}#b`);
    const rev = docOf([vm(`${did}#b`), vm(`${did}#a`)]);
    expect(selectLatestActiveVMForPurpose(rev, 'authentication').id).toBe(`${did}#b`);
  });
});

describe('5.8 sequential fragment parses like Sscanf %d', () => {
  test('#key-02 is 2, #key-2a is 2 (beats #key-1)', () => {
    for (const frag of ['#key-02', '#key-2a']) {
      const d = docOf([vm(`${did}#key-1`), vm(`${did}${frag}`)]);
      expect(selectLatestActiveVMForPurpose(d, 'authentication').id).toBe(`${did}${frag}`);
    }
  });
  test('#key-x is 0 (loses to #key-1)', () => {
    const d = docOf([vm(`${did}#key-x`), vm(`${did}#key-1`)]);
    expect(selectLatestActiveVMForPurpose(d, 'authentication').id).toBe(`${did}#key-1`);
  });
});

describe('5.9 nextSequentialKid uses strict Atoi', () => {
  test('#key-5abc is ignored, #key-7 counts', () => {
    const d = docOf([vm(`${did}#key-5abc`), vm(`${did}#key-7`)]);
    const id = addVerificationMethod(d, { publicKeyHex: pub33(9) });
    expect(id).toBe(`${did}#key-8`);
    const d2 = docOf([vm(`${did}#key-5abc`)]);
    expect(addVerificationMethod(d2, { publicKeyHex: pub33(8) })).toBe(`${did}#key-1`);
  });
});

describe('5.10 signing looks only at the revoked timestamp', () => {
  test('keyCompromise without revoked is allowed; revoked is refused', async () => {
    const hard = { ...vm(`${did}#key-1`), revocationReason: 'keyCompromise' };
    const r = new StaticResolver(docOf([hard]));
    await expect(resolveSigningVM(did, 'assertionMethod', '', r)).resolves.toMatchObject({ url: `${did}#key-1` });
    const gone = new StaticResolver(docOf([{ ...hard, revoked: new Date(0) }, vm(`${did}#key-2`)]));
    await expect(resolveSigningVM(did, 'assertionMethod', 'key-1', gone)).rejects.toThrow(/was revoked/);
  });
});

describe('5.13 publicKeyHex is read as secp256k1 whatever the type, and the point is validated', () => {
  test('type is not gated', () => {
    expect(publicKeyHexFromVM({ ...vm(`${did}#k`), type: 'JsonWebKey2020' })).toBe(secpPub.slice(2));
  });
  test('invalid point / length is refused', () => {
    expect(() => publicKeyHexFromVM({ ...vm(`${did}#k`), publicKeyHex: `0x04${'11'.repeat(64)}` })).toThrow(/invalid secp256k1/);
    expect(() => publicKeyHexFromVM({ ...vm(`${did}#k`), publicKeyHex: '0xabcd' })).toThrow(/want 33/);
  });
});

describe('5.14 private-key multibase checks the scalar range', () => {
  const enc = (d: Uint8Array) => encodeBase58Btc(new Uint8Array([0x86, 0x26, ...d]));
  test('zero and >= n are refused, a valid scalar passes', () => {
    expect(() => decodeP256SecretMultibase(enc(new Uint8Array(32)))).toThrow(/out of range/);
    expect(() => decodeP256SecretMultibase(enc(new Uint8Array(32).fill(0xff)))).toThrow(/out of range/);
    expect(decodeP256SecretMultibase(enc(new Uint8Array(32).fill(1)))).toHaveLength(32);
  });
});

describe('5.15 key-kind selection', () => {
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey;
  const vms = [newSecp256k1VM(did, 'key-1', secpPub), newP256MultikeyVM(did, 'key-2', p256Pub), newRSAVM(did, 'key-3', rsa)];
  const d = newDIDDocument(did, ...vms);
  test('selectLatestActiveVMForKey', () => {
    expect(selectLatestActiveVMForKey(d, 'assertionMethod', 'secp256k1').id).toBe(`${did}#key-1`);
    expect(selectLatestActiveVMForKey(d, 'assertionMethod', 'P-256').id).toBe(`${did}#key-2`);
    expect(selectLatestActiveVMForKey(d, 'assertionMethod', 'RSA').id).toBe(`${did}#key-3`);
    expect(() => selectLatestActiveVMForKey(newDIDDocument(did, vms[0]), 'assertionMethod', 'RSA')).toThrow(
      /no active RSA verification method/,
    );
  });
  test('resolveVerificationMethodURLForKey', async () => {
    await expect(resolveVerificationMethodURLForKey(did, 'authentication', 'P-256', new StaticResolver(d))).resolves.toBe(`${did}#key-2`);
  });
});

describe('5.20 HTTP resolver', () => {
  test('pathEscape keeps : and escapes / and !', () => {
    expect(pathEscape('did:nda:0xabc')).toBe('did:nda:0xabc');
    expect(pathEscape('a/b c!')).toBe('a%2Fb%20c%21');
  });
  const resp = (status: number) =>
    ({ status, ok: status >= 200 && status < 300, statusText: '', json: async () => ({ id: did }) }) as unknown as Response;
  test('only 200 is accepted, and the DID is path-escaped', async () => {
    const urls: string[] = [];
    const mk = (status: number) => new HTTPResolver('http://r', { fetchFn: (async (u: string) => (urls.push(u), resp(status))) as never });
    await expect(mk(200).resolveDocument(did)).resolves.toMatchObject({ id: did });
    expect(urls[0]).toBe(`http://r/${did}`);
    await expect(mk(204).resolveDocument(did)).rejects.toThrow(/non-200 status: 204/);
  });
});

describe('6.5 StaticResolver and VM builders', () => {
  test('resolve, add, unknown did', async () => {
    const r = new StaticResolver();
    r.add(newDIDDocument(did, newSecp256k1VM(did, 'key-1', secpPub)));
    await expect(r.resolveDocument(did)).resolves.toMatchObject({ id: did, assertionMethod: [`${did}#key-1`], authentication: [`${did}#key-1`] });
    await expect(r.resolveDocument('did:x:y')).rejects.toThrow(/unknown did/);
  });
  test('builders produce the Go shapes', () => {
    const m = newP256MultikeyVM(did, 'k', p256Pub);
    expect(m).toMatchObject({ id: `${did}#k`, type: 'Multikey', controller: did });
    expect(m.publicKeyMultibase!.startsWith('zDn')).toBe(true);
    expect(isP256PublicMultibase(m.publicKeyMultibase!)).toBe(true);
    const j = newP256VM(did, 'k', p256Pub);
    expect(j.type).toBe('JsonWebKey2020');
    expect(j.publicKeyJwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect(vmKeyKind(j)).toBe('P-256');
    expect(vmKeyKind(newRSAVM(did, 'k', generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey))).toBe('RSA');
    expect(() => newP256VM(did, 'k', secp256k1.getPublicKey(new Uint8Array(32).fill(5), true))).toThrow(/P-256/);
  });
});
