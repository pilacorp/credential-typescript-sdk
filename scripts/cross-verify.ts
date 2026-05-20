/**
 * Cross-language verify test:
 *  1. Use the TS SDK to issue a JWT VC and a JSON-LD VC.
 *  2. Write each to a tmp file.
 *  3. Spawn the Go SDK's verify-vc-file CLI to verify each one against the
 *     Pila testnet DID resolver.
 *
 * Requirements:
 *  - go-credential-sdk checked out as a sibling directory (or GO_SDK_PATH).
 *  - Network access to the resolver URL.
 *  - The issuer/holder keys below correspond to DIDs already registered on
 *    the testnet — if you change them, verify will fail with a key mismatch.
 *
 * Run: `npx ts-node scripts/cross-verify.ts`
 */
import { spawnSync } from 'child_process';
import { writeFileSync } from 'fs';
import { tmpdir } from 'os';
import { join, resolve } from 'path';
import { vc, verificationMethod } from '../src';

const ISSUER_PRIVATE_KEY =
  '0x36548b79c828ac6a455feb0e9d92da3b859b732240332d3abf57277ffc110c37';
const ISSUER_DID =
  'did:nda:testnet:0x9b758618ff4011303a499d3cd96421bddc81467e';
const HOLDER_DID =
  'did:nda:testnet:0xbd34a8456aa0d2ad4661787be07d4db42e6b072d';
const DID_RESOLVER_BASE_URL = 'https://auth-dev.pila.vn/api/v1/did';

function resolveGoRepo(): string {
  if (process.env.GO_SDK_PATH) return resolve(process.env.GO_SDK_PATH);
  return resolve(__dirname, '..', '..', 'go-credential-sdk');
}

async function issueJWTVC(): Promise<string> {
  const cred = await vc.newJWTCredential(
    {
      context: ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:cross-jwt-vc-1',
      types: ['VerifiableCredential'],
      issuer: ISSUER_DID,
      subject: [
        {
          id: HOLDER_DID,
          customFields: {
            name: 'Alice Nguyen',
            membershipLevel: 'Gold',
          },
        },
      ],
    },
    {
      verificationMethodKey: 'key-1',
      resolver: verificationMethod.newHTTPResolver(DID_RESOLVER_BASE_URL),
    },
  );
  await cred.addProof(ISSUER_PRIVATE_KEY);
  return (await cred.serialize()) as string;
}

async function issueJSONVC(): Promise<string> {
  const cred = await vc.newJSONCredential(
    {
      context: ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:cross-json-vc-1',
      types: ['VerifiableCredential'],
      issuer: ISSUER_DID,
      validFrom: new Date('2024-01-01T00:00:00Z'),
      subject: [
        {
          id: HOLDER_DID,
          customFields: {
            name: 'Alice Nguyen',
            membershipLevel: 'Gold',
          },
        },
      ],
    },
    {
      verificationMethodKey: 'key-1',
      resolver: verificationMethod.newHTTPResolver(DID_RESOLVER_BASE_URL),
    },
  );
  await cred.addProof(ISSUER_PRIVATE_KEY);
  const doc = await cred.serialize();
  return JSON.stringify(doc);
}

function goVerify(goRepo: string, file: string): { ok: boolean; out: string; err: string } {
  const res = spawnSync(
    'go',
    ['run', './cmd/verify-vc-file', `--resolver=${DID_RESOLVER_BASE_URL}`, file],
    { cwd: goRepo, encoding: 'utf8' },
  );
  return {
    ok: res.status === 0,
    out: (res.stdout || '').trim(),
    err: (res.stderr || '').trim(),
  };
}

async function main(): Promise<void> {
  const goRepo = resolveGoRepo();

  console.log('━━━ Issuing JWT VC with TS SDK ━━━');
  const jwtToken = await issueJWTVC();
  const jwtFile = join(tmpdir(), 'cross-jwt-vc.txt');
  writeFileSync(jwtFile, jwtToken, 'utf8');
  console.log(`  wrote ${jwtFile} (${jwtToken.length} bytes)`);

  console.log('━━━ Issuing JSON-LD VC with TS SDK ━━━');
  const jsonDoc = await issueJSONVC();
  const jsonFile = join(tmpdir(), 'cross-json-vc.json');
  writeFileSync(jsonFile, jsonDoc, 'utf8');
  console.log(`  wrote ${jsonFile} (${jsonDoc.length} bytes)`);

  console.log();
  console.log('━━━ Go verify ━━━');
  let fail = 0;
  for (const [label, file] of [
    ['JWT VC', jwtFile],
    ['JSON-LD VC', jsonFile],
  ] as const) {
    const r = goVerify(goRepo, file);
    if (r.ok) {
      console.log(`  ✓ ${label}: ${r.out}`);
    } else {
      fail++;
      console.log(`  ✗ ${label}:`);
      if (r.out) console.log(`    stdout: ${r.out}`);
      if (r.err) console.log(`    stderr: ${r.err}`);
    }
  }

  console.log();
  console.log(fail === 0 ? 'All VCs verified by Go SDK ✓' : `${fail} failure(s)`);
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('Cross-verify failed:', err);
  process.exit(1);
});
