import {
  canonicalizeDocument,
  canonicalizeRDF,
  compareCodePoints,
} from '../../src/common/processor/processor';
import fixture from '../fixtures/go-canonicalize/cases.json';

type Case = { name: string; doc: Record<string, unknown>; new: string; legacy: string };

const text = (b: Uint8Array) => Buffer.from(b).toString('utf8');
const copy = (doc: Record<string, unknown>) => JSON.parse(JSON.stringify(doc));

// Expected bytes come from running Go on the same documents (see fixture.generator).
describe('canonicalization matches go-credential-sdk byte for byte', () => {
  for (const c of fixture.cases as Case[]) {
    it(c.name, async () => {
      for (const [want, run] of [
        [c.new, canonicalizeRDF],
        [c.legacy, canonicalizeDocument],
      ] as const) {
        if (want.startsWith('ERR')) {
          await expect(run(copy(c.doc))).rejects.toThrow();
        } else {
          expect(text(await run(copy(c.doc)))).toBe(want);
        }
      }
    });
  }
});

describe('canonicalization edge cases', () => {
  const vc = (subject: Record<string, unknown>) => ({
    '@context': ['https://www.w3.org/ns/credentials/v2', 'https://www.w3.org/ns/credentials/examples/v2'],
    id: 'urn:uuid:1',
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:subject', ...subject },
  });

  it('signs a small number by value, so changing it changes the bytes', async () => {
    const a = text(await canonicalizeRDF(vc({ n: 1e-7 })));
    const b = text(await canonicalizeRDF(vc({ n: 9e-7 })));
    expect(a).toContain('"1.0E-7"^^<http://www.w3.org/2001/XMLSchema#double>');
    expect(a).not.toBe(b);
  });

  it('refuses a __proto__ claim on both paths instead of leaving it unsigned', async () => {
    const doc = JSON.parse(JSON.stringify(vc({ s: 1 })).replace('"s":1', '"s":1,"__proto__":{"evil":"x"}'));
    await expect(canonicalizeRDF(doc)).rejects.toThrow(/__proto__/);
    await expect(canonicalizeDocument(doc)).rejects.toThrow(/__proto__/);
  });

  it('refuses an empty key on the strict path and drops it on the legacy path like Go', async () => {
    await expect(canonicalizeRDF(vc({ '': 'x' }))).rejects.toThrow(/empty key/);
    expect(text(await canonicalizeDocument(vc({ '': 'x' })))).toBe(text(await canonicalizeDocument(vc({}))));
  });

  it('orders strings by code point, as Go does', () => {
    expect(['😀', 'Ａ', 'a', ''].sort(compareCodePoints)).toEqual(['a', '', 'Ａ', '😀']);
    expect(compareCodePoints('ab', 'a')).toBeGreaterThan(0);
    expect(compareCodePoints('a', 'a')).toBe(0);
  });
});
