# credential-typescript-sdk

Node.js / TypeScript port của [`go-credential-sdk`](https://github.com/pilacorp/go-credential-sdk).
Hỗ trợ issue & verify W3C Verifiable Credentials (VC) và Verifiable Presentations (VP) ở các định dạng:

- **JSON-LD** với `DataIntegrityProof` — cryptosuite `ecdsa-rdfc-2019` (URDNA2015 + SHA-256, secp256k1 hoặc P-256) và `ecdsa-sd-2023` (P-256, selective disclosure)
- **JWT (VC 1.1)** ký bằng ES256K (`JWTCredential` / `JWTPresentation`)
- **JOSE (VC 2.0, vc-jose-cose)**: `vc+jwt` / `vc+sd-jwt` và `vp+jwt` (`JOSECredential` / `JOSEPresentation`) — **SD-JWT chỉ được issue/đọc qua JOSE**; `JWTCredential` từ chối SD-JWT
- Khóa **secp256k1**, **P-256** (Multikey / JWK) và **RSA** (JsonWebSignature2020, chỉ verify); signer ngoài (HSM/KMS) qua callback

Ngoài VC/VP, SDK hiện cũng đã có:

- **DID (v1)** helpers (`did`): derive DID từ public key, build DID Document, tạo payload `issuer_did/document/transaction`, generate DID + signed Layer2 registration transaction
- **DIDv2** (`didv2`, port của `didv2` trong Go SDK): DID generator theo capability của issuer, DID Document nhiều verification method (secp256k1 `#key-1` + P-256 Multikey `#key-2`), thao tác VM (add / rotate / revoke / purposes), Sub-DID, DID registry contract
- **DIDComm** core: derive shared secret bằng **secp256k1**, encrypt / decrypt JWE theo shape SDK Go cũ

Canonicalization (URDNA2015, JCS) được kiểm tra với các test vector của Go SDK — xem `tests/common/go-interop.test.ts`, `tests/common/go-rdfc-numeric-interop.test.ts`, `tests/common/jsoncanonicalizer.test.ts`.

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

### DID helpers

```ts
import { did } from '@pilacorp/credential-sdk';

const parsed = did.parsePublicKeyToDid(publicKeyHex);
// => { curve, address, did, publicKeyHex }

const created = did.createDidFromPublicKey(publicKeyHex, {
  didType: 'people',
});
// => { did, address, curve, document }

const payload = did.createDidFromPublicKeyWithTransaction(publicKeyHex, {
  issuerDid: 'did:nda:testnet:0xissuer',
  didIdentifier: 'did:nda:testnet:0xholder',
  didType: 'people',
  transaction: { txHash: '0x...', txHex: '0x...' },
});
// => { did, document, registration: { issuer_did, document, transaction } }
```

Generate DID + signed transaction giống flow SDK Go:

```ts
const generator = new did.DIDGenerator({
  rpc: 'https://rpc-testnet.pila.vn',
  chainId: 6789,
  didAddress: '0x0000000000000000000000000000000000018888',
  method: 'did:nda',
});

const generated = await generator.generateDID({
  type: 'people',
  metadata: { name: 'User 1' },
});
// => { did, secret.privateKeyHex, document, transaction }

const regeneratedTx = await generator.reGenerateDIDTX(
  generated.secret.privateKeyHex,
  generated.document.didDocumentMetadata ?? {},
);
```

### DIDComm helpers

```ts
import { didcomm } from '@pilacorp/credential-sdk';

const message = didcomm.encrypt(
  JSON.stringify({ hello: 'world' }),
  receiverPublicKeyHex,
  senderPrivateKeyHex,
);

const decrypted = didcomm.decrypt(
  message,
  senderPublicKeyHex,
  receiverPrivateKeyHex,
);
// => { protected, plaintext, json }
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

### JOSE VC (vc+jwt) và SD-JWT

`JOSECredential` là định dạng VC 2.0 (vc-jose-cose). Có `sdSelectivePaths` thì token là `vc+sd-jwt` (selective disclosure); không có thì là `vc+jwt`. `alg` được chọn theo loại khóa của verification method (secp256k1 → `ES256K`, P-256 → `ES256`).

```ts
import { vc, DefaultProvider } from '@pilacorp/credential-sdk';

const credential = await vc.newJOSECredential(
  {
    context: ['https://www.w3.org/ns/credentials/v2'],
    types: ['VerifiableCredential'],
    issuer: 'did:nda:testnet:0x...',
    subject: [{ id: 'did:nda:testnet:0xsubject', customFields: { email: 'alice@example.com', dateOfBirth: '1990-01-01' } }],
  },
  {
    verificationMethodKey: 'key-1',
    sdSelectivePaths: ['credentialSubject.email', 'credentialSubject.dateOfBirth'],
    sdShuffle: true,                                     // randomise `_sd` order
    sdDecoys: [{ path: 'credentialSubject', count: 3 }], // inject decoy digests
  },
);
await credential.addProofByProvider(new DefaultProvider(privateKeyHex));
const sdJwt = await credential.serialize(); // "header.payload.sig~D1~D2~"

// Holder presents only some disclosures:
const emailOnly = credential.decodedDisclosures().find((d) => d.fieldName === 'email')!;
const presented = await credential.present([emailOnly.disclosure]);

// Verifier:
const parsed = await vc.parseCredential(await presented.serialize(), { verifyProof: true });
parsed.extractField('credentialSubject.email'); // → "alice@example.com"
```

`vc.parseCredential` định tuyến theo `typ` của header (`vc+jwt` / `vc+sd-jwt` → JOSE; còn lại → JWT VC 1.1). Một `EnvelopedVerifiableCredential` (`data:application/vc+jwt,...`) cũng được unwrap thành `JOSECredential`.

### ECDSA-SD (ecdsa-sd-2023, P-256)

Selective disclosure cho VC JSON-LD. Verification method của issuer phải giữ khóa **P-256** (Multikey `publicKeyMultibase` hoặc JWK); SDK chọn cryptosuite theo khóa của VM, không theo class của signer.

```ts
import { vc, P256Provider } from '@pilacorp/credential-sdk';

const cred = await vc.ECDSASDCredential.create(contents, { verificationMethodKey: 'key-2' });
// mandatory pointers luôn được disclose; mọi claim còn lại có thể ẩn đi:
await cred.addProofByProvider(new P256Provider(p256PrivateKeyHex), ['/issuer', '/credentialSubject/id'], {
  verificationMethodKey: 'key-2',
});

// Holder derive một bản chỉ lộ /credentialSubject/name:
const derived = await cred.derive(['/credentialSubject/name']);
await derived.verify({ verifyProof: true });
const json = await derived.serialize();
```

### JOSE VP (vp+jwt)

```ts
import { vp, vc, DefaultProvider } from '@pilacorp/credential-sdk';

const presentation = await vp.newJOSEPresentation(
  {
    context: ['https://www.w3.org/ns/credentials/v2'],
    types: ['VerifiablePresentation'],
    holder: 'did:nda:testnet:0xholder',
    verifiableCredentials: [joseCredential], // gói thành EnvelopedVerifiableCredential
  },
  { verificationMethodKey: 'key-1' },
);
await presentation.addProofByProvider(new DefaultProvider(holderPrivateKeyHex));
const token = await presentation.serialize();

await vp.parsePresentation(token, { verifyProof: true }); // kiểm tra holder binding
```

VP `vp+jwt` chỉ nhận VC dạng enveloping-secured (JOSE); VC Data Integrity (JSON-LD) bị từ chối.

### Challenge / domain (VP)

Gắn `challenge` (JWT: `nonce`, JSON-LD: `proof.challenge`) và `domain` (JWT: `aud`, JSON-LD: `proof.domain`) khi ký, và yêu cầu chúng khi verify:

```ts
// JWT / JOSE VP: truyền khi tạo VP.
const p = await vp.newJWTPresentation(contents, { challenge: 'nonce-123', domain: 'verifier.example' });
await p.addProofByProvider(new DefaultProvider(holderPrivateKeyHex));

// JSON-LD VP: truyền ở bước ký.
const jp = await vp.newJSONPresentation(contents);
await jp.addProofByProvider(new DefaultProvider(holderPrivateKeyHex), { challenge: 'nonce-123', domain: 'verifier.example' });

// Verifier: expected* tự bật verifyProof; sai giá trị → CredentialError
// với code ChallengeMismatch / DomainMismatch; requireAudience → AudienceUnbound.
await vp.parsePresentation(token, {
  expectedChallenge: 'nonce-123',
  expectedDomain: 'verifier.example',
});
```

### External signing (Vault / HSM / KMS) và P-256

Implement interface `SignerProvider`, hoặc dùng callback có sẵn trong namespace `signer`:

```ts
import { signer, type SignerProvider } from '@pilacorp/credential-sdk';

class VaultSigner implements SignerProvider {
  async sign(digest: Uint8Array): Promise<Uint8Array> {
    // digest is exactly 32 bytes (SHA-256 / RDFC-2019).
    // secp256k1: return 64 bytes (R||S) or 65 bytes (R||S||V).
    // P-256:     return 64 bytes (R||S), low-S.
  }
}
await credential.addProofByProvider(new VaultSigner());

// Hoặc gói một callback KMS (Go: NewP256Func / NewRSAFunc):
const p256 = signer.newP256Func(async (digest) => kms.signP256(digest)); // 64-byte R||S
const rsa = signer.newRSAFunc(async (digest) => kms.signRSA(digest), 'PS256');

// Khóa in-memory: hex constructor vẫn dùng được, hoặc 32 raw bytes.
const local = new signer.P256Provider(privateKeyHex);
signer.algorithmOf(rsa); // "PS256" (mặc định "RS256")
```

Scheme ký do **verification method** quyết định (loại khóa của VM), không phải class của signer; chỉ `JsonWebSignature2020` RSA đọc `algorithm()` của signer. `signer.algForKeyKind('P-256')` → `"ES256"`.

Tạo VM cho resolver cục bộ/test (không cần network): `verificationMethod.StaticResolver` cùng `newSecp256k1VM`, `newP256VM`, `newP256MultikeyVM`, `newRSAVM`, `newDIDDocument`:

```ts
import { verificationMethod as vm } from '@pilacorp/credential-sdk';

const did = 'did:example:issuer';
const resolver = new vm.StaticResolver(
  vm.newDIDDocument(did, vm.newP256MultikeyVM(did, 'key-2', p256CompressedOrUncompressedPub)),
);
```

### DIDv2

```ts
import { didv2, signer } from '@pilacorp/credential-sdk';

const generator = didv2.newDIDGenerator(
  didv2.WithRPC('https://rpc-new.pila.vn'),
  didv2.WithIssuerSignerProvider(new didv2.DefaultProvider(issuerPrivateKeyHex)),
  didv2.WithP256VerificationMethod(), // publish the same scalar as P-256 Multikey at #key-2
);
const created = await generator.generateDID(didv2.DIDTypePeople, '', { name: 'User 1' });
// => { did, document, transaction: { txHex, txHash }, secret: { privateKeyHex } }

// Verification-method operations (Go: DIDDocument methods):
const doc = created.document;
didv2.revokeVerificationMethod(doc, '#key-2', 'superseded');
didv2.rotateVerificationMethod(doc, '#key-1', { publicKeyHex: newCompressedPub });
didv2.hashDIDDocument(doc); // DocHash, byte-identical to Go (keeps `revoked` offset/ns)
```

Lưu ý: `didv2.DefaultProvider` (có `getAddress()`, `sign` trả recovery id `v` 0/1 như Go) khác `DefaultProvider` top-level dùng cho VC/VP. Các hàm thao tác VM của `didv2` vẫn được export dưới tên cũ trong namespace `did` (alias). `didv2.generateDualCurveKeyPair()` là keygen dual-curve chuẩn (`generateDualCurveDIDKeyPair` là alias deprecated); `did.generateDualCurveKeyPair` giữ shape cũ. Lỗi Sub-DID có thể so sánh kiểu `errors.Is`: `didv2.subdid.errorIs(err, didv2.subdid.ErrConsentInvalid)`.

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
| `clockSkewLeewayMs` | `number` | `0` | Leeway cho `validFrom` / `validUntil` / `exp` / `nbf` |
| `sdSelectivePaths` | `string[]` | `[]` | Paths to make selectively disclosable (issuer side, **JOSE only**) |
| `sdShuffle` / `sdDecoys` / `sdAlg` | — | — | SD-JWT privacy knobs |
| `schemaLoader` | `(id) => bytes` | network | Custom loader for JSON schemas |
| `proofVerificationMethod` | `string` | all proofs | Chỉ verify proof dùng VM này (JSON-LD) |
| `replaceProof` | `boolean` | `false` | JWT / JOSE: cho phép ký đè token đã ký (JSON-LD từ chối option này — proof được append) |

## API surface

| Module | Exports |
|---|---|
| `vc` | `parseCredential`, `parseCredentialWithValidation`, `newJWTCredential`, `newJSONCredential`, `newJOSECredential`, `newECDSASDCredential`, `JWTCredential`, `JSONCredential`, `JOSECredential`, `ECDSASDCredential`, `init` |
| `vp` | `parsePresentation`, `parsePresentationWithValidation`, `newJWTPresentation`, `newJSONPresentation`, `newJOSEPresentation`, `JWTPresentation`, `JSONPresentation`, `JOSEPresentation`, `init` |
| `signer` | `DefaultProvider` (secp256k1), `P256Provider`, `newP256Provider`, `newP256Func`, `RSAProvider`, `newRSAFunc`, `AlgorithmProvider`, `algorithmOf`, `algForKeyKind`, `SignerProvider` |
| `sdjwt` | `buildDisclosures`, `reconstruct`, `parse`, `buildSDJWTPresentation`, `isSDJWT`, `hashDisclosure`, `parseDisclosures` |
| `ecdsasd` | `createBaseProof`, `deriveProof`, `verifyProof`, `Cryptosuite` |
| `verificationMethod` | `HTTPResolver`, `newHTTPResolver`, `StaticResolver`, `newSecp256k1VM`, `newP256VM`, `newP256MultikeyVM`, `newRSAVM`, `newDIDDocument`, `ResolverProvider`, `selectLatestActiveVMForPurpose`, `selectLatestActiveVMForKey`, `resolveVerificationMethodURL`, `resolveVerificationMethodURLForKey`, `normalizeVerificationMethodURL`, … |
| `credentialStatus` | `isRevoked`, `fetchAndCheckRevocation`, `StatusListClient` |
| `did` | `parsePublicKeyToDid`, `buildDidDocument`, `createDidFromPublicKey`, `createDidFromPublicKeyWithTransaction`, `submitDidRegistration`, `DIDGenerator`, VM-op aliases |
| `didv2` | `newDIDGenerator`, `With*` options, `DefaultProvider`, `generateDIDDocument`, `hashDIDDocument`, `validateDIDDocument`, `generateDualCurveKeyPair`, VM operations (`addVerificationMethod`, `rotateVerificationMethod`, `revokeVerificationMethod`, `*VerificationMethodPurposes`), `didcontract`, `subdid` |
| `didcomm` | `getSharedSecret`, `encrypt`, `decrypt`, `encryptJWE`, `decryptJWE` |
| `jsoncanonicalizer` | `transform` (RFC 8785 JCS) |
| top-level | `SignerProvider`, `DefaultProvider`, `P256Provider`, `RSAProvider`, `Proof`, `CredentialError`, `ErrorCode` |

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
- Options dùng một object duy nhất thay cho variadic `WithX()` builders của Go (DIDv2 giữ nguyên `WithX()` options).
- Dựng VP (`newJWTPresentation` / `newJSONPresentation` / `newJOSEPresentation`) **không** verify các VC bên trong, giống Go. Muốn verify các VC thì truyền `validateVC` (`true` hoặc `CredentialOptions`) cùng `resolver` bạn chọn; `vc.init(baseURL)` / `vp.init(baseURL)` đặt resolver mặc định.
- `DIDDocument` ở TS là interface dữ liệu; các thao tác VM của Go (`doc.RotateVerificationMethod`, …) là hàm tự do trong `didv2`.
- Gói chỉ có CommonJS (chưa có `exports` map). RSA chỉ verify; ký RSA qua `signer.newRSAFunc` (callback).
- JSON-LD canonicalization (URDNA2015 + SHA-256) được test với `piprate/json-gold` của Go trên các fixtures string / số / boolean / unicode / nested / key reorder; số lớn/nhỏ của proof legacy (hex) được xử lý riêng — xem `tests/common/go-rdfc-numeric-interop.test.ts`.

## License

Apache-2.0
