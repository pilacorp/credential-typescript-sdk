# @pilacorp/credential-sdk

Node.js / TypeScript port của [`go-credential-sdk`](https://github.com/pilacorp/go-credential-sdk).
Hỗ trợ issue & verify W3C Verifiable Credentials (VC) và Verifiable Presentations (VP) ở cả 2 định dạng:

- **JSON-LD** với `DataIntegrityProof` / cryptosuite `ecdsa-rdfc-2019` (URDNA2015 canonicalization + SHA-256 + secp256k1)
- **JWT** ký bằng ES256K (secp256k1), kèm hỗ trợ **SD-JWT** (selective disclosure)

Pipeline canonicalization đã được kiểm tra parity byte-for-byte với Go SDK — xem [`scripts/canonicalize-parity.ts`](scripts/canonicalize-parity.ts).

## Cài đặt

```bash
npm install @pilacorp/credential-sdk
```

Yêu cầu Node.js >= 18.

## Build & test

```bash
npm install
npm run build       # tsc → dist/
npm test            # jest
npm run example     # ts-node examples/main.ts (issue + verify VC end-to-end)
```

## Quick start

### Issue a JWT VC

```ts
import { vc } from '@pilacorp/credential-sdk';

const credential = await vc.newJWTCredential({
  context: ['https://www.w3.org/ns/credentials/v2'],
  id: 'urn:uuid:my-credential',
  types: ['VerifiableCredential', 'UniversityDegree'],
  issuer: 'did:nda:testnet:0x...',
  validFrom: new Date(),
  subject: [{
    id: 'did:nda:testnet:0xsubject',
    customFields: { degree: 'Bachelor of Science' },
  }],
});

// Sign with an in-memory secp256k1 key (32-byte hex, with or without 0x prefix):
await credential.addProof(privateKeyHex);

const token = await credential.serialize(); // → "eyJ...JWT...sig"
```

### Issue a JSON-LD VC

```ts
const credential = await vc.newJSONCredential(
  {
    context: ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:uuid:my-credential',
    types: ['VerifiableCredential'],
    issuer: 'did:nda:testnet:0x...',
    validFrom: new Date(),
    subject: [{ id: 'did:nda:testnet:0xsubject', customFields: { name: 'Alice' } }],
  },
  { verificationMethodKey: 'key-1' }, // optional — pick a specific VM
);
await credential.addProof(privateKeyHex);
const signedJSON = await credential.serialize();
// → { @context, id, type, issuer, validFrom, credentialSubject, proof: { ... } }
```

### Verify a VC

```ts
const parsed = await vc.parseCredential(rawCredential); // string or Uint8Array
await parsed.verify();   // resolves issuer DID via default HTTPResolver

// Or run all checks in one call:
await vc.parseCredentialWithValidation(rawCredential);
// = parseCredential + { validateSchema: true, verifyProof: true }
```

Custom resolver (testing, alternate DID network):

```ts
import { verificationMethod } from '@pilacorp/credential-sdk';

const resolver = verificationMethod.newHTTPResolver('https://my-did-network.example/api/v1/did');
await parsed.verify({ resolver });
```

Hoặc đặt resolver mặc định cho toàn package (áp dụng cho mọi call không truyền `resolver` riêng — bao gồm bước verify VC bên trong `newJWTPresentation` / `newJSONPresentation`):

```ts
vc.init('https://my-did-network.example/api/v1/did');
vp.init('https://my-did-network.example/api/v1/did');
```

### Issue and verify a VP

```ts
import { vp } from '@pilacorp/credential-sdk';

const presentation = await vp.newJWTPresentation({
  context: ['https://www.w3.org/ns/credentials/v2'],
  id: 'urn:uuid:my-vp',
  types: ['VerifiablePresentation'],
  holder: 'did:nda:testnet:0xholder',
  verifiableCredentials: [credential],
});
await presentation.addProof(holderPrivateKeyHex);
const vpToken = await presentation.serialize();

// Later, verify:
const incoming = await vp.parsePresentation(vpToken);
await incoming.verify();
```

### Multi verification-method support

Một DID Document có thể có nhiều verification method (`key-1`, `key-2`, …). Truyền `verificationMethodKey` để chọn key cụ thể; nếu bỏ qua, SDK tự resolve VM mới nhất còn active cho purpose tương ứng (`assertionMethod` cho VC, `authentication` cho VP).

```ts
// Fragment dạng ngắn → SDK tự nối với DID issuer:
await vc.newJSONCredential(contents, { verificationMethodKey: 'key-2' });

// Hoặc full DID URL:
await vc.newJSONCredential(contents, {
  verificationMethodKey: 'did:nda:testnet:0x...#key-2',
});
```

### Selective disclosure (SD-JWT)

```ts
const credential = await vc.newJWTCredential(contents, {
  sdSelectivePaths: ['credentialSubject.email', 'credentialSubject.dateOfBirth'],
  sdShuffle: true,                                    // randomise `_sd` order
  sdDecoys: [{ path: 'credentialSubject', count: 3 }],// inject decoy digests
});
await credential.addProof(privateKeyHex);
const sdJwt = await credential.serialize(); // "header.payload.sig~D1~D2~"
```

Khi parse lại, các field disclosed sẽ được reconstruct trong-place:

```ts
const parsed = await vc.parseCredential(sdJwt);
parsed.extractField('credentialSubject.email'); // → "alice@example.com"
```

### External signing (Vault / HSM / KMS)

Implement interface `SignerProvider`:

```ts
import type { SignerProvider } from '@pilacorp/credential-sdk';

class VaultSigner implements SignerProvider {
  async sign(digest: Uint8Array): Promise<Uint8Array> {
    // digest is exactly 32 bytes (SHA-256 / RDFC-2019).
    // Must return secp256k1 signature: 64 bytes (R||S) or 65 bytes (R||S||V).
  }
}

await credential.addProofByProvider(new VaultSigner());
```

## Credential options

| Option | Type | Default | Description |
|---|---|---|---|
| `validateSchema` | `boolean` | `false` | Run JSON-schema validation against any `credentialSchema` entries |
| `verifyProof` | `boolean` | `false` | Cryptographically verify the proof during `parse`/`verify` |
| `checkExpiration` | `boolean` | `false` | Enforce `validFrom` / `validUntil` against current clock |
| `checkRevocation` | `boolean` | `false` | Check the `BitstringStatusListEntry` bit |
| `verificationMethodKey` | `string` | auto-resolve | VM fragment (`"key-1"`) hoặc full DID URL |
| `resolver` | `ResolverProvider` | `HTTPResolver(didBaseURL)` | DID document resolver |
| `didBaseURL` | `string` | `vcConfig.baseURL` | Base URL cho default HTTPResolver |
| `sdSelectivePaths` | `string[]` | `[]` | Paths to make selectively disclosable (issuer side) |
| `sdShuffle` / `sdDecoys` / `sdAlg` | — | — | SD-JWT privacy knobs |
| `schemaLoader` | `(id) => bytes` | network | Custom loader for JSON schemas |

## API surface

| Module | Exports |
|---|---|
| `vc` | `parseCredential`, `parseCredentialWithValidation`, `newJWTCredential`, `newJSONCredential`, `JWTCredential`, `JSONCredential`, `init` |
| `vp` | `parsePresentation`, `parsePresentationWithValidation`, `newJWTPresentation`, `newJSONPresentation`, `JWTPresentation`, `JSONPresentation`, `init` |
| `sdjwt` | `buildDisclosures`, `reconstruct`, `parse`, `buildSDJWTPresentation`, `isSDJWT`, `hashDisclosure`, `parseDisclosures` |
| `verificationMethod` | `HTTPResolver`, `newHTTPResolver`, `ResolverProvider`, `selectLatestActiveVMForPurpose`, `resolveVerificationMethodURL`, `normalizeVerificationMethodURL`, … |
| `credentialStatus` | `isRevoked`, `fetchAndCheckRevocation`, `StatusListClient` |
| `jsoncanonicalizer` | `transform` (RFC 8785 JCS) |
| top-level | `SignerProvider`, `DefaultProvider`, `Proof` |

`Credential` interface (cả JWT và JSON-LD đều implement):

```ts
addProof(priv, opts?)              // ký với in-memory key
addProofByProvider(signer, opts?)  // ký qua external SignerProvider
addCustomProof(proof, opts?)       // gắn proof do caller tự tạo
getSigningInput()                  // bytes thực sự được ký (debug)
verify(opts?)                      // throw nếu invalid
serialize()                        // JWT string hoặc JSON object
getContents() / getType()
extractField(path)                 // "credentialSubject.email"
addSelectiveDisclosures(paths)     // chỉ JWT
```

Xem [`src/index.ts`](src/index.ts) để có public surface đầy đủ và [`examples/main.ts`](examples/main.ts) để có demo end-to-end.

## Differences vs the Go SDK

- API là async (Promise) vì I/O của Node là non-blocking.
- Options dùng một object duy nhất thay cho variadic `WithX()` builders của Go.
- Behaviour parity được giữ. `newJWTPresentation` / `newJSONPresentation` cũng gọi `vc.verify()` cho từng VC tại thời điểm build (qua HTTPResolver mặc định) — gọi `vc.init(baseURL)` trước nếu DID issuer của bạn không resolve được ở URL mặc định.
- JSON-LD canonicalization (URDNA2015 + SHA-256) được test parity với `piprate/json-gold` của Go — kết quả digest khớp byte-for-byte trên các fixtures string / số / boolean / unicode / nested / key reorder.

## License

Apache-2.0
