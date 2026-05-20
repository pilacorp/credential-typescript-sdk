/**
 * End-to-end demo: issue VC + VP and verify them.
 *
 * Run from the project root:
 *   npm run example
 *
 * What this script does
 * ─────────────────────
 *  1. Generates secp256k1 keypairs for an Issuer and a Holder.
 *  2. Resolves DID Documents via Pila's HTTP DID resolver.
 *  3. Issues a JWT VC (AuthorizationCredential) and a JSON-LD VC, signing
 *     locally with the generated private key.
 *  4. Verifies each VC against the on-chain DID Document.
 *  5. Issues a JWT VP and a JSON-LD VP, each embedding one VC.
 *  6. Verifies each VP.
 */

import { vc, vp, verificationMethod } from '../src';

// ─────────────────────────────────────────────────────────────
// 1. Keys and DIDs
// ─────────────────────────────────────────────────────────────

// Real keys corresponding to the registered public keys on the DID
// Document. Signatures produced with these will verify end-to-end.
const issuerPrivateKey = '0x36548b79c828ac6a455feb0e9d92da3b859b732240332d3abf57277ffc110c37';
const holderPrivateKey = '0x7f67dfc76bbcc1bea1bb31b628a09c8633ddd2f8237657b9380b38b342abf806';

// Pila testnet DIDs that you've already registered on the DID network.
const ISSUER_DID = 'did:nda:testnet:0x9b758618ff4011303a499d3cd96421bddc81467e';
const HOLDER_DID = 'did:nda:testnet:0xbd34a8456aa0d2ad4661787be07d4db42e6b072d';

// ─────────────────────────────────────────────────────────────
// 2. Resolver wiring
// ─────────────────────────────────────────────────────────────

// Real HTTP resolver pointing at the Pila testnet DID network.
// Replace the URL if you're targeting a different environment.
const DID_RESOLVER_BASE_URL = 'https://auth-dev.pila.vn/api/v1/did';
const resolver = verificationMethod.newHTTPResolver(DID_RESOLVER_BASE_URL);

// Set the SDK's default base URL too — this propagates to:
//   - vc.verify() / vp.verify() calls that don't take an explicit resolver
//   - the inner vc.verify() call that vp.newJWT/JSONPresentation runs
//     against each embedded credential at build time
vc.init(DID_RESOLVER_BASE_URL);
vp.init(DID_RESOLVER_BASE_URL);

// ⚠️  Caveat: verify steps below succeed ONLY when the signing private
//     key matches the public key registered for that DID on the network.
//     The demo mints fresh random keys, so:
//       - VC issuance + payload printing → works
//       - VC/VP verify against real testnet → FAILS (signature mismatch)
//     To make verify pass, plug in the actual issuer/holder private keys
//     for DIDs you've registered on https://api.ndadid.vn.

// ─────────────────────────────────────────────────────────────
// 3. Main flow
// ─────────────────────────────────────────────────────────────

async function main() {
  console.log('Issuer DID:', ISSUER_DID);
  console.log('Holder DID:', HOLDER_DID);
  console.log();

  // ── Issue a JWT AuthorizationCredential ─────────────────────
  // Produces a JWT whose decoded payload looks like:
  //   {
  //     "iss": "<ISSUER_DID>",
  //     "jti": "<vc.id>",
  //     "sub": "<subject.id>",
  //     "vc": { @context, type, issuer, id, credentialSubject,
  //             credentialSchema, credentialStatus }
  //   }
  // We deliberately omit `validFrom` / `validUntil` so the SDK doesn't
  // add `iat` / `nbf` / `exp` claims — matching the target payload shape.
  console.log('━━━ Issuing JWT AuthorizationCredential ━━━');

  const VC_ID = 'did:nda:testnet:881d7786-aaee-4e78-b499-62da3e622974';

  const jwtVC = await vc.newJWTCredential(
    {
      context: [
        'https://www.w3.org/ns/credentials/v2',
        'https://www.w3.org/ns/credentials/examples/v2',
      ],
      id: VC_ID,
      types: ['VerifiableCredential', 'AuthorizationCredential'],
      issuer: ISSUER_DID,
      // Authorization credential is self-issued: subject == issuer DID.
      subject: [
        {
          id: ISSUER_DID,
          customFields: {
            permissions: [
              {
                actions: ['*'],
                effect: 'allow',
                resources: ['*'],
              },
            ],
          },
        },
      ],
      schemas: [
        {
          id: 'https://auth-dev.pila.vn/api/v1/schemas/e8429e35-5486-4f05-a06c-2bd211f99fc8',
          type: 'JsonSchema',
        },
      ],
      credentialStatus: [
        {
          id: `${ISSUER_DID}/credentials/status/35#458`,
          type: 'BitstringStatusListEntry',
          statusPurpose: 'revocation',
          statusListIndex: '458',
          statusListCredential: `https://auth-dev.pila.vn/api/v1/issuers/${ISSUER_DID}/credentials/status/35`,
        },
      ],
    },
  );

  // Sign with the issuer's private key.
  await jwtVC.addProof(issuerPrivateKey);
  const jwtVCToken = (await jwtVC.serialize()) as string;
  console.log('JWT VC:', jwtVCToken);

  // Print decoded payload so you can compare with the target spec.
  const decodedPayload = JSON.parse(
    Buffer.from(jwtVCToken.split('.')[1], 'base64url').toString('utf8'),
  );
  console.log('Decoded payload:');
  console.log(JSON.stringify(decodedPayload, null, 2));

  // ── Verify the JWT VC ───────────────────────────────────────
  console.log('Verifying JWT VC…');
  const parsedJWTVC = await vc.parseCredential(jwtVCToken);
  await parsedJWTVC.verify({ resolver, verifyProof: true , validateSchema: true});
  console.log('  ✓ JWT VC verified');
  console.log(
    '  subject.permissions[0].actions =',
    parsedJWTVC.extractField('credentialSubject.permissions'),
  );
  console.log();

  // ── Issue a JSON-LD VC ──────────────────────────────────────
  console.log('━━━ Issuing JSON-LD VC ━━━');
  const jsonVC = await vc.newJSONCredential(
    {
      context: ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:json-vc-1',
      types: ['VerifiableCredential'],
      issuer: ISSUER_DID,
      schemas: [
        {
          id: 'https://auth-dev.pila.vn/api/v1/schemas/e8429e35-5486-4f05-a06c-2bd211f99fc8',
          type: 'JsonSchema',
        },
      ],
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
    { verificationMethodKey: 'key-1', resolver },
  );
  await jsonVC.addProof(issuerPrivateKey);

  const jsonVCDoc = await jsonVC.serialize();
  console.log('JSON-LD VC proof.type =', (jsonVCDoc as any).proof?.type);
  // Print the full JSON-LD VC document so you can inspect the proof structure.
  console.log('JSON-LD VC document:');
  console.log(JSON.stringify(jsonVCDoc, null, 2));

  // ── Verify the JSON-LD VC ───────────────────────────────────
  console.log('Verifying JSON-LD VC…');
  const parsedJSONVC = await vc.parseCredential(JSON.stringify(jsonVCDoc));
  await parsedJSONVC.verify({ resolver, verifyProof: true, validateSchema: true,  });
  console.log('  ✓ JSON-LD VC verified');
  console.log();

  // ── Issue a JWT VP (embedding the JWT VC) ───────────────────
  console.log('━━━ Issuing JWT VP ━━━');
  const jwtVP = await vp.newJWTPresentation(
    {
      context: ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:jwt-vp-1',
      types: ['VerifiablePresentation'],
      holder: HOLDER_DID,
      validFrom: new Date('2024-02-01T00:00:00Z'),
      verifiableCredentials: [jwtVC],
    },
    { verificationMethodKey: 'key-1', resolver },
  );
  await jwtVP.addProof(holderPrivateKey);

  const jwtVPToken = (await jwtVP.serialize()) as string;
  console.log('JWT VP:', jwtVPToken);

  // ── Verify the JWT VP ───────────────────────────────────────
  console.log('Verifying JWT VP…');
  const parsedJWTVP = await vp.parsePresentation(jwtVPToken);
  await parsedJWTVP.verify();
  console.log('  ✓ JWT VP verified');
  console.log();

  // ── Issue a JSON-LD VP (embedding the JSON-LD VC) ───────────
  console.log('━━━ Issuing JSON-LD VP ━━━');
  const jsonVP = await vp.newJSONPresentation(
    {
      context: ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:json-vp-1',
      types: ['VerifiablePresentation'],
      holder: HOLDER_DID,
      verifiableCredentials: [jsonVC],
    },
    { verificationMethodKey: 'key-1', resolver },
  );
  await jsonVP.addProof(holderPrivateKey, {
    verificationMethodKey: 'key-1',
    resolver,
  });

  const jsonVPDoc = await jsonVP.serialize();
  console.log('JSON-LD VP proof.type =', (jsonVPDoc as any).proof?.type);

  // ── Verify the JSON-LD VP ───────────────────────────────────
  console.log('Verifying JSON-LD VP…');
  const parsedJSONVP = await vp.parsePresentation(JSON.stringify(jsonVPDoc));
  await parsedJSONVP.verify({ resolver , verifyProof: true });
  console.log('  ✓ JSON-LD VP verified');
  console.log();

  // ── Bonus: SD-JWT VC ────────────────────────────────────────
  console.log('━━━ Bonus: SD-JWT VC with selective disclosure ━━━');
  const sdVC = await vc.newJWTCredential(
    {
      context: ['https://www.w3.org/ns/credentials/v2'],
      id: 'urn:uuid:sd-vc-1',
      types: ['VerifiableCredential'],
      issuer: ISSUER_DID,
      validFrom: new Date('2024-01-01T00:00:00Z'),
      subject: [
        {
          id: HOLDER_DID,
          customFields: {
            name: 'Alice Nguyen',
            email: 'alice@example.com',
            dateOfBirth: '1990-05-15',
          },
        },
      ],
    },
    {
      verificationMethodKey: 'key-1',
      resolver,
      sdSelectivePaths: ['credentialSubject.email', 'credentialSubject.dateOfBirth'],
    },
  );
  await sdVC.addProof(issuerPrivateKey);
  const sdToken = (await sdVC.serialize()) as string;
  console.log('SD-JWT (compact):', sdToken.slice(0, 100) + '…');
  console.log('  contains ~ disclosure separator:', sdToken.includes('~'));

  const parsedSDVC = await vc.parseCredential(sdToken);
  console.log('  reconstructed email =', parsedSDVC.extractField('credentialSubject.email'));
  console.log();

  console.log('━━━ Done. All credentials & presentations verified ✓ ━━━');
}

main().catch((err) => {
  console.error('Demo failed:', err);
  process.exitCode = 1;
});
