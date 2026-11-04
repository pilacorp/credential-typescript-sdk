/**
 * Issue a JSON-LD VC with ecdsa-rdfc-2019 (P-256) for Go SDK verification.
 *
 *   npm run issue:go-interop
 *
 * Document shape matches go-credential-sdk/credential/examples/interop/main.go.
 */
import fs from 'fs';
import path from 'path';

import { addECDSAProof } from '../src/common/jsonmap/jsonmap';
import { encodeP256PublicMultibase } from '../src/common/verification-method/multikey';
import type { DIDDocument, ResolverProvider } from '../src/common/verification-method';
import type { JSONMap } from '../src/common/util/json';
import { P256Provider } from '../src/common/signer/p256-provider';

/** W3C P-256 test private key (same as Go interop example). */
const P256_PRIV = 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721';
const ISSUER = 'did:example:issuer';
const VM = `${ISSUER}#key-1`;

class StaticResolver implements ResolverProvider {
  constructor(private readonly doc: DIDDocument) {}

  async resolveDocument(): Promise<DIDDocument> {
    return this.doc;
  }
}

async function main(): Promise<void> {
  const signer = new P256Provider(P256_PRIV);
  const publicKeyMultibase = encodeP256PublicMultibase(signer.publicKeyUncompressed());
  const resolver = new StaticResolver({
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/v1',
      'https://www.w3.org/ns/cid/v1',
    ],
    id: ISSUER,
    verificationMethod: [
      {
        id: VM,
        type: 'Multikey',
        controller: ISSUER,
        publicKeyMultibase,
      },
    ],
    assertionMethod: [VM],
    authentication: [VM],
  });

  const credential: JSONMap = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:0f7c2d1e-3b4a-4c5d-8e9f-0a1b2c3d4e5f',
    type: ['VerifiableCredential'],
    issuer: ISSUER,
    validFrom: '2024-01-01T00:00:00Z',
    credentialSubject: {
      id: 'did:example:subject',
    },
  };

  await addECDSAProof(credential, signer, VM, 'assertionMethod');

  const { JSONCredential } = await import('../src/vc/json-credential');
  await JSONCredential.parse(JSON.stringify(credential), { resolver, verifyProof: true });

  const outDir = path.resolve(__dirname, '../../go-credential-sdk/credential/examples/interop');
  const outFile = path.join(outDir, 'vc-from-ts.json');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(
    outFile,
    `${JSON.stringify({ credential, publicKeyMultibase }, null, 2)}\n`,
    'utf8',
  );

  console.log(`wrote ${outFile}`);
  console.log('verify with Go:');
  console.log('  (cd ../go-credential-sdk && go run ./credential/examples/verifyfromts)');
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
