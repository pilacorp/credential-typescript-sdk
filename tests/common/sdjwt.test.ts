import {
  buildSDJWTPresentation,
  hashDisclosure,
  isSDJWT,
  parse,
  parseDisclosure,
} from '../../src/common/sdjwt/helper';
import { buildDisclosures } from '../../src/common/sdjwt/disclosure';
import { reconstruct } from '../../src/common/sdjwt/reconstruct';

function encodeDisclosure(arr: unknown[]): string {
  return Buffer.from(JSON.stringify(arr), 'utf8').toString('base64url');
}

describe('parseDisclosure', () => {
  it('parses an object-field disclosure', () => {
    const disc = encodeDisclosure(['salt-1', 'name', 'Alice']);
    const info = parseDisclosure(disc);
    expect(info.salt).toBe('salt-1');
    expect(info.objectField).toBe('name');
    expect(info.value).toBe('Alice');
    expect(info.isArrayElem).toBe(false);
  });

  it('parses an array-element disclosure', () => {
    const disc = encodeDisclosure(['salt-2', 42]);
    const info = parseDisclosure(disc);
    expect(info.isArrayElem).toBe(true);
    expect(info.objectField).toBe('');
  });

  it('rejects malformed disclosures', () => {
    expect(() => parseDisclosure(encodeDisclosure(['only-one']))).toThrow(/invalid disclosure structure/);
    expect(() => parseDisclosure(encodeDisclosure([1, 'name', 'Alice']))).toThrow(/salt must be a string/);
  });
});

describe('hashDisclosure', () => {
  it('rejects unsupported algorithms', () => {
    expect(() => hashDisclosure('sha-999', 'abc')).toThrow(/unsupported sd_alg/);
  });
});

describe('isSDJWT', () => {
  it('detects SD-JWT format', () => {
    const jwt = 'aaa.bbb.ccc';
    const sd = jwt + '~D1~D2~';
    expect(isSDJWT('')).toBe(false);
    expect(isSDJWT(jwt)).toBe(false);
    expect(isSDJWT(sd)).toBe(true);
    expect(isSDJWT('not-a-jwt~something~')).toBe(false);
  });
});

describe('parse', () => {
  it('splits issuer JWT and disclosures', () => {
    const jwt = 'aaa.bbb.ccc';
    const d1 = encodeDisclosure(['s1', 'name', 'Alice']);
    const d2 = encodeDisclosure(['s2', 'age', 30]);
    const sd = `${jwt}~${d1}~${d2}~`;
    const parsed = parse(sd);
    expect(parsed.baseJWT).toBe(jwt);
    expect(parsed.disclosures).toEqual([d1, d2]);
    expect(parsed.decodedDisclosures).toHaveLength(2);
  });
});

describe('buildSDJWTPresentation', () => {
  it('skips empty disclosures', () => {
    expect(buildSDJWTPresentation('a.b.c', ['d1', '', 'd2'])).toBe('a.b.c~d1~d2~');
  });
  it('emits bare JWT when no disclosures supplied', () => {
    expect(buildSDJWTPresentation('a.b.c', [])).toBe('a.b.c');
  });
});

describe('buildDisclosures + reconstruct roundtrip', () => {
  it('restores selectively-disclosed claims', () => {
    const vc = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: 'VerifiableCredential',
      credentialSubject: {
        id: 'did:example:subject',
        name: 'Alice',
        email: 'alice@example.com',
      },
    };
    const result = buildDisclosures({
      vc,
      selectivePaths: ['credentialSubject.email'],
    });
    expect(result.disclosures).toHaveLength(1);

    // email is replaced by an _sd digest in the processed VC
    const cs = result.processedVC.credentialSubject as Record<string, unknown>;
    expect(cs.email).toBeUndefined();
    expect(Array.isArray(cs._sd)).toBe(true);

    const reconstructed = reconstruct(result.processedVC, result.disclosures, true);
    const reconstructedCS = reconstructed.credentialSubject as Record<string, unknown>;
    expect(reconstructedCS.email).toBe('alice@example.com');
  });
});
