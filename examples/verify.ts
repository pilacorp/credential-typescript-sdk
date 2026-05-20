/**
 * Verify a Verifiable Credential that the user provides.
 *
 * Run from the project root:
 *   # 1) Pass a file path:
 *   npx ts-node examples/verify.ts ./my-vc.json
 *
 *   # 2) Pipe via stdin:
 *   cat ./my-vc.json | npx ts-node examples/verify.ts
 *
 * Accepts:
 *  - JSON-LD VC (a JSON object with a `proof`)
 *  - JWT VC compact string (header.payload.signature)
 *  - SD-JWT VC (… ~ disclosure ~ …)
 */

import { readFileSync } from 'node:fs';
import { vc, verificationMethod } from '../src';

const DID_RESOLVER_BASE_URL = 'https://auth-dev.pila.vn/api/v1/did';
const resolver = verificationMethod.newHTTPResolver(DID_RESOLVER_BASE_URL);
vc.init(DID_RESOLVER_BASE_URL);

async function readInput(): Promise<string> {
  const argPath = process.argv[2];
  if (argPath) {
    return readFileSync(argPath, 'utf8');
  }
  if (process.stdin.isTTY) {
    throw new Error(
      'No input provided. Pass a file path as the first arg, or pipe the VC via stdin.',
    );
  }
  return await new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on('data', (c) => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

async function main() {
  const raw = (await readInput()).trim();
  if (!raw) throw new Error('Empty input.');

  console.log('━━━ Parsing credential ━━━');
  const parsed = await vc.parseCredential(raw);

  console.log('━━━ Verifying credential ━━━');
  await parsed.verify({ resolver, verifyProof: true, validateSchema: true, checkRevocation: true , checkExpiration: true , didBaseURL: DID_RESOLVER_BASE_URL , verificationMethodKey: 'key-1'});
  console.log('  ✓ VC verified');

  const issuer = parsed.extractField('issuer');
  const subjectId = parsed.extractField('credentialSubject.id');
  const id = parsed.extractField('id');
  console.log();
  console.log('id      :', id);
  console.log('issuer  :', issuer);
  console.log('subject :', subjectId);
}

main().catch((err) => {
  console.error('Verification failed:', err?.message ?? err);
  process.exitCode = 1;
});
