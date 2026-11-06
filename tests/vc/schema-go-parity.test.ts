// Expected values come from gojsonschema v1.2.0 via the scratch Go harness (see fixtures/go-schema-cases.json).
import cases from '../fixtures/go-schema-cases.json';
import { validateCredential } from '../../src/vc/credential-helper';

type Case = { n: string; s: unknown; d: Record<string, unknown>; valid: boolean; err: string; errs: string[] };

// Go's own parser/loader wording or order we do not reproduce; only the verdict (accept/reject) is compared.
const VERDICT_ONLY = new Set<string>([
  'ref-missing', 'ref-remote-unreachable', 'bad-type-kw', 'bad-required', 'bad-pattern', // schema errors: Go prose differs
  'contains-d7', 'contains-none', // Go also lists per-item sub-errors of contains
  'propertyNames-d7', 'anyOf-3', 'oneOf-none', 'anyOf', // closest-branch choice is score based in Go
  'many-errors', // kept exact below
]);
VERDICT_ONLY.delete('many-errors');

function baseDoc(extra: Record<string, unknown>) {
  return {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    type: ['VerifiableCredential'],
    issuer: 'did:example:issuer',
    credentialSubject: { id: 'did:example:123', age: 25 },
    credentialSchema: { id: 'https://example.org/schema/1', type: 'JsonSchema' },
    dup: [1, 1],
    ...extra,
  };
}

async function run(c: Case): Promise<string | null> {
  const doc = baseDoc(c.d);
  const schemaLoader = async () => new Uint8Array(Buffer.from(JSON.stringify(c.s)));
  try {
    await validateCredential(doc as never, { schemaLoader } as never);
    return null;
  } catch (e) {
    return (e as Error).message;
  }
}

describe('validateCredential vs gojsonschema', () => {
  it.each((cases as Case[]).map((c) => [c.n, c] as const))('%s', async (_n, c) => {
    const msg = await run(c);
    if (c.valid) return expect(msg).toBeNull();
    expect(msg).not.toBeNull();
    if (c.err) {
      // hard (schema/loader) errors
      expect(msg).toMatch(/^failed to validate schema: /);
      if (!VERDICT_ONLY.has(c.n)) expect(msg).toContain(c.err);
      return;
    }
    expect(msg).toMatch(/^credential validation failed: \[/);
    if (VERDICT_ONLY.has(c.n)) return;
    const got = msg!.slice('credential validation failed: ['.length, -1);
    // Go joins with single spaces; compare as unordered line sets (Go's order is map-random).
    const lineRx = /(?:^|(?<= ))(?:\(root\)|[^\s:]+): /g;
    const split = (str: string) => {
      const idx = [...str.matchAll(lineRx)].map((m) => m.index!);
      return idx.map((i, k) => str.slice(i, idx[k + 1] ?? str.length).trim()).sort();
    };
    expect(split(got)).toEqual(split(c.errs.join(' ')));
  });

  it('wraps custom loader failures like Go', async () => {
    const doc = baseDoc({});
    await expect(validateCredential(doc as never, { schemaLoader: async () => { throw new Error('boom'); } } as never)).rejects.toThrow('failed to load schema via custom loader: boom');
    await expect(validateCredential(doc as never, { schemaLoader: async () => new Uint8Array() } as never)).rejects.toThrow('failed to load schema via custom loader: schema is empty');
  });

  it('rejects non-object credentialSchema entries and missing ids like Go', async () => {
    const noLoader = { schemaLoader: async () => new Uint8Array(Buffer.from('{}')) } as never;
    await expect(validateCredential(baseDoc({ credentialSchema: ['https://x/y'] }) as never, noLoader)).rejects.toThrow('failed to unmarshal schema');
    await expect(validateCredential(baseDoc({ credentialSchema: { type: 'JsonSchema' } }) as never, noLoader)).rejects.toThrow('credentialSchema.id is required');
    await expect(validateCredential(baseDoc({ credentialSchema: { id: 5 } }) as never, noLoader)).rejects.toThrow('must be a non-empty string');
  });
});
