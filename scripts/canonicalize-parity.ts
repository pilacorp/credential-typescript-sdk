/**
 * Cross-language canonicalization parity check.
 *
 * For each fixture:
 *  1. Compute the TS digest via the SDK's canonicalize() pipeline.
 *  2. Pipe the same JSON into the Go helper `cmd/canonicalize-digest` and
 *     capture its digest from stdout.
 *  3. Compare the two hex strings.
 *
 * Requirements:
 *  - `go` available on PATH.
 *  - go-credential-sdk checked out at a sibling path (or set GO_SDK_PATH env).
 *
 * Run with: `npx ts-node scripts/canonicalize-parity.ts`
 */
import { spawnSync } from 'child_process';
import { resolve } from 'path';
import { existsSync } from 'fs';
import { bytesToHex } from '../src/common/crypto/hex';
import { canonicalize } from '../src/common/jsonmap/jsonmap';

type Fixture = {
  name: string;
  doc: Record<string, unknown>;
};

const fixtures: Fixture[] = [
  {
    name: 'minimal VC',
    doc: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:json-vc-1',
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      validFrom: '2024-01-01T00:00:00Z',
      credentialSubject: { id: 'did:example:holder', name: 'Alice' },
    },
  },
  {
    name: 'integer + float + boolean fields',
    doc: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:numbers',
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: {
        id: 'did:example:holder',
        age: 30,
        gpa: 3.75,
        verified: true,
        active: false,
      },
    },
  },
  {
    name: 'nested object + arrays',
    doc: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:nested',
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: {
        id: 'did:example:holder',
        roles: ['admin', 'editor'],
        address: { city: 'Hanoi', zip: '100000' },
      },
    },
  },
  {
    name: 'unicode + special characters',
    doc: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:unicode',
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: {
        id: 'did:example:holder',
        name: 'Nguyễn Văn A',
        emoji: '🎉',
        quote: 'He said "hi"',
        slash: 'a/b\\c',
      },
    },
  },
  {
    name: 'key ordering should not matter',
    doc: {
      issuer: 'did:example:issuer',
      validFrom: '2024-01-01T00:00:00Z',
      type: ['VerifiableCredential'],
      id: 'urn:uuid:reorder',
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      credentialSubject: { name: 'Alice', id: 'did:example:holder' },
    },
  },
  {
    name: 'proof field must be ignored',
    doc: {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:with-proof',
      type: ['VerifiableCredential'],
      issuer: 'did:example:issuer',
      credentialSubject: { id: 'did:example:holder', name: 'Alice' },
      proof: {
        type: 'DataIntegrityProof',
        cryptosuite: 'ecdsa-rdfc-2019',
        created: '2024-01-01T00:00:00Z',
        verificationMethod: 'did:example:issuer#key-1',
        proofPurpose: 'assertionMethod',
        proofValue: 'deadbeef',
      },
    },
  },
];

function resolveGoRepo(): string {
  const fromEnv = process.env.GO_SDK_PATH;
  if (fromEnv) return resolve(fromEnv);
  return resolve(__dirname, '..', '..', 'go-credential-sdk');
}

function goDigest(goRepo: string, doc: Record<string, unknown>): string {
  const result = spawnSync('go', ['run', './cmd/canonicalize-digest'], {
    cwd: goRepo,
    input: JSON.stringify(doc),
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(`go helper failed (exit ${result.status}): ${result.stderr}`);
  }
  return result.stdout.trim();
}

async function main(): Promise<void> {
  const goRepo = resolveGoRepo();
  if (!existsSync(goRepo)) {
    console.error(`go-credential-sdk not found at ${goRepo}`);
    console.error('Set GO_SDK_PATH to override.');
    process.exit(1);
  }

  let pass = 0;
  let fail = 0;
  for (const fx of fixtures) {
    const tsDigest = bytesToHex(await canonicalize(fx.doc));
    const goRes = goDigest(goRepo, fx.doc);
    const ok = tsDigest === goRes;
    if (ok) pass++;
    else fail++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${fx.name}`);
    console.log(`      ts: ${tsDigest}`);
    console.log(`      go: ${goRes}`);
  }

  console.log();
  console.log(`Summary: ${pass}/${pass + fail} passed`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
