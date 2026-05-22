# credential-typescript-sdk Go Parity Roadmap

This document maps the current TypeScript SDK against the old Go-based SSI core used by `ndakey-sdk-wallet`.

The goal is not to move the entire backend into the SDK.
The goal is to complete the SDK only for the parts that belonged to the old Go SDK role:

- DID core
- VC core
- VP core
- DIDComm core
- VC/VP verification core

Everything else should remain in the app layer:

- passkey/auth
- partner/callback-config
- kyc/qts/s3
- mDOC
- OpenID4VCI protocol layer
- Google Wallet / Apple Wallet
- AStar / telco integrations

## 1. Can we continue immediately?

Yes.

But only for the parts that are already structurally close:

1. VC issue
2. VP issue
3. VC/VP verification

These can be integrated into the app immediately because the TypeScript SDK already contains:

- VC issue/parse/verify
- VP issue/parse/verify
- DID resolver support
- verification method selection
- revocation/status helpers

The parts that needed to be built inside the SDK before full app parity were:

1. DID create from public key
2. Layer2 DID registration payload support
3. DID transaction helpers
4. DIDComm encrypt/decrypt

These are now implemented in the TypeScript SDK.

## 2. Current status matrix

| Capability | Go old system | TypeScript SDK now | App Node now | Action |
| --- | --- | --- | --- | --- |
| VC issue | yes | yes | simplified | integrate SDK now |
| VC verify | yes | yes | simplified | integrate SDK now |
| VP issue | yes | yes | simplified | integrate SDK now |
| VP verify | yes | yes | simplified | integrate SDK now |
| DID resolve | yes | yes | real | align SDK usage gradually |
| DID create via external service | yes | no | real | keep in app |
| DID from public key | yes | yes | mock/simplified | wire SDK into app |
| Layer2 DID registration | yes | yes (payload + submit helpers) | missing | wire SDK into app |
| DID tx generation | yes | yes | missing | wire SDK into app |
| DIDComm decrypt | yes | yes | real current flow | replace app implementation with SDK |
| DIDComm encrypt | yes | yes | partial | replace app implementation with SDK |
| mDOC issue/verify | yes | no | real | keep in app |
| OpenID4VCI protocol | yes | no | real | keep in app |
| Wallet export | yes | no | real | keep in app |

## 3. Old Go SDK usage that must drive this roadmap

These are the real reference points from the Go codebase.

### VC issuance

- [internal/service/vc/identify.go](/Users/datdv/Documents/pila/ndakey-sdk-wallet-test/ndakey-sdk-wallet/internal/service/vc/identify.go:1)
- [internal/service/vc/sim-identity.go](/Users/datdv/Documents/pila/ndakey-sdk-wallet-test/ndakey-sdk-wallet/internal/service/vc/sim-identity.go:1)
- [internal/service/vc/term-condition.go](/Users/datdv/Documents/pila/ndakey-sdk-wallet-test/ndakey-sdk-wallet/internal/service/vc/term-condition.go:1)

SDK role in Go:

- build VC contents
- sign proof
- serialize VC

### DID generation and registration

- [internal/service/did_generator.go](/Users/datdv/Documents/pila/ndakey-sdk-wallet-test/ndakey-sdk-wallet/internal/service/did_generator.go:1)

SDK role in Go:

- generate DID
- build DID document
- generate or carry DID transaction
- support Layer2 registration flow

### DIDComm

- [internal/server/handler/didcomm.go](/Users/datdv/Documents/pila/ndakey-sdk-wallet-test/ndakey-sdk-wallet/internal/server/handler/didcomm.go:1)
- [internal/server/handler/vc.go](/Users/datdv/Documents/pila/ndakey-sdk-wallet-test/ndakey-sdk-wallet/internal/server/handler/vc.go:1)

SDK role in Go:

- derive shared secret from keys
- encrypt VC payload
- decrypt JWE payload

## 4. What should remain outside the SDK

Do not pull these into the SDK:

- `mDOC`
- `wallet`
- `openid4vci` HTTP/protocol orchestration
- `auth`
- `passkey`
- `partner`
- `kyc`
- `qts`
- `s3`
- `astar`
- `telco`

Reason:

- these are app/business/provider layers, not portable SSI-core primitives

## 5. Implementation phases

## Phase 1: integrate what already exists

Target:

- app Node `vc`
- app Node `vp`
- app Node `verification`

SDK work required:

- no major new primitive
- mainly public API stabilization, tests, and app integration support

App-side outcome:

- replace simplified providers in:
  - `sdk-vc.provider.ts`
  - `sdk-vp.provider.ts`
  - `sdk-verification.provider.ts`

Done condition:

- `POST /api/v1/vcs` is SDK-backed
- `POST /api/v1/vcs/term-condition` is SDK-backed
- `POST /api/v1/vp/share` uses real VP generation
- `POST /api/v1/verify/vc` uses SDK verification
- `POST /api/v1/verify/finish` can verify VP payloads more truthfully

## Phase 2: add DID module to the SDK

Status: completed

New SDK module:

- `src/did`

Must include:

- public key parsing
- support for secp256k1 and P-256 input forms used in Go
- DID identifier derivation
- DID document builder
- verification method builder
- authentication/assertionMethod wiring

Go parity reference:

- `parsePublicKeyToDID(...)`
- `createDIDDocumentFromPublicKey(...)`
in [internal/service/did_generator.go](/Users/datdv/Documents/pila/ndakey-sdk-wallet-test/ndakey-sdk-wallet/internal/service/did_generator.go:1)

Done condition:

- SDK can generate a DID document and DID identifier from the public key shapes the Go backend accepts
- SDK can generate DID + signed registration transaction
- SDK can re-generate signed registration transaction from private key and DID metadata

## Phase 3: add Layer2 registration support to the SDK

Status: completed

New SDK responsibility:

- DID transaction model
- tx passthrough support
- registration payload support

Must include:

- `createDidByPublicKey(...)`
- `createDidByPublicKeyWithTx(...)`
- registration request builder

Important design constraint:

- the SDK should stop at SSI-core and registration payload construction
- raw HTTP submission may live in SDK or app; the TypeScript SDK now includes a submit helper because the Go SDK flow also bundled API-facing registration examples

Done condition:

- app can replace `POST /api/v1/dids/from-public-key` simplified flow with SDK-backed logic

## Phase 4: add DIDComm module to the SDK

Status: completed

New SDK module:

- `src/didcomm`

Must include:

- key normalization
- shared secret derivation
- encrypt
- decrypt
- JWE structure mapping

Parity reference:

- [internal/server/handler/didcomm.go](/Users/datdv/Documents/pila/ndakey-sdk-wallet-test/ndakey-sdk-wallet/internal/server/handler/didcomm.go:1)
- Go SDK source in `/Users/datdv/go/pkg/mod/github.com/pilacorp/go-credential-sdk@v1.4.1/didcomm`

Done condition:

- app `didcomm` provider can switch from local crypto implementation to SDK-backed implementation without route changes

## Phase 5: app replacement pass

After SDK phases 1-4, the app should replace remaining placeholders:

- `sdk-vc.provider.ts`
- `sdk-vp.provider.ts`
- `sdk-verification.provider.ts`
- `sdk-did.provider.ts`
- `sdk-didcomm.provider.ts`

Done condition:

- all credential-adapter providers are real for:
  - VC
  - VP
  - verification
  - DID from public key
  - DIDComm

## 6. Recommended concrete task order

### Immediate

1. Implement app-side `sdk-vc.provider.ts`
2. Implement app-side `sdk-vp.provider.ts`
3. Implement app-side `sdk-verification.provider.ts`
4. Implement app-side `sdk-did.provider.ts`
5. Implement app-side `sdk-didcomm.provider.ts`

## 7. What “full enough” means

The SDK is “full enough” for this project when all of the following are true:

- VC issuance is SDK-backed
- VP issuance is SDK-backed
- VC/VP verification is SDK-backed
- `dids/from-public-key` is SDK-backed
- DIDComm is SDK-backed

The SDK does **not** need to own:

- mDOC
- wallet export
- OpenID4VCI controllers/services
- passkey/auth

Those belong to the app.

## 8. Final recommendation

Proceed now, but in this exact order:

1. integrate SDK into app for VC/VP/verification
2. switch `did` app provider to SDK-backed implementation
3. switch `didcomm` app provider to SDK-backed implementation
4. harden end-to-end parity in the Node app

This is the shortest path to making the Node system structurally similar to the Go system without pushing app-specific logic into the SDK.
