/**
 * JSON-LD verifiable credential — Node port of vc/json_credential.go.
 */
import type { Proof } from '../common/dto/proof';
import {
  addCustomProof,
  addECDSAProof,
  addEcdsaSecp256k1Proof,
  createProofSigning,
  didFromField,
  documentDigest,
  refuseHexRdfcProof,
  toMap,
  verifyDetachedProof,
  verifyProof,
} from '../common/jsonmap/jsonmap';
import { bytesToHex, hexToBytes } from '../common/crypto/hex';
import { canonicalizeDocument, canonicalizeRDF, computeDigest } from '../common/processor/processor';
import { P256Provider } from '../common/signer/p256-provider';
import type { SignerProvider } from '../common/signer/signer';
import {
  publicKeyHexFromVM,
  resolveSigningVM,
  VerificationMethodEntry,
  vmKeyKind,
} from '../common/verification-method';
import { getOptions, refuseReplaceOnJSONLD, signingOptions } from './options';
import {
  checkExpiration,
  checkRevocation,
  extractFieldFromMap,
  requireCredentialProperties,
  serializeCredentialContents,
  validateCredential,
} from './credential-helper';
import type {
  CredentialContents,
  CredentialData,
  CredentialOptions,
  SignableCredential,
} from './types';

export class JSONCredential implements SignableCredential {
  private credentialData: CredentialData;
  private verificationMethodKey: string;

  constructor(credentialData: CredentialData, verificationMethodKey = '') {
    this.credentialData = credentialData;
    this.verificationMethodKey = verificationMethodKey;
  }

  static async create(
    vcc: CredentialContents,
    opts: CredentialOptions = {},
  ): Promise<JSONCredential> {
    const m = serializeCredentialContents(vcc);
    const options = getOptions(opts);
    const cred = new JSONCredential(m, options.verificationMethodKey);
    await cred.executeOptions(opts);
    return cred;
  }

  static async parse(rawJSON: Uint8Array | string, opts: CredentialOptions = {}): Promise<JSONCredential> {
    const buf = typeof rawJSON === 'string' ? Buffer.from(rawJSON, 'utf8') : Buffer.from(rawJSON);
    if (buf.length === 0) throw new Error('JSON string is empty');
    let parsed: unknown;
    try {
      parsed = JSON.parse(buf.toString('utf8'));
    } catch (err) {
      throw new Error(`failed to unmarshal credential: ${(err as Error).message}`);
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('invalid JSON format');
    }
    requireCredentialProperties(parsed as CredentialData);
    const cred = new JSONCredential(parsed as CredentialData);
    await cred.executeOptions(opts);
    return cred;
  }

  /** Signs with a raw P-256 private key (hex scalar), like Go. For secp256k1 use addProofByProvider(new DefaultProvider(hex)). */
  async addProof(priv: string, opts: CredentialOptions = {}): Promise<void> {
    await this.addProofByProvider(new P256Provider(priv), opts);
  }

  /**
   * Signs with a provider. The suite follows the VM's key: P-256 gives
   * ecdsa-rdfc-2019, secp256k1 gives EcdsaSecp256k1Signature2019; RSA is
   * refused. The proof is APPENDED to the proof set.
   */
  async addProofByProvider(
    signer: SignerProvider,
    opts: CredentialOptions = {},
  ): Promise<void> {
    if (!signer) throw new Error('signer provider cannot be nil');
    refuseReplaceOnJSONLD(opts);
    await this.executeOptions(signingOptions(opts));

    const { vm, url: vmURL } = await this.resolveSigningVMEntry(opts);
    const kind = vmKeyKind(vm);
    if (!kind) throw new Error(`verification method '${vmURL}' has an unrecognized key type`);
    if (kind !== 'secp256k1' && kind !== 'P-256') {
      throw new Error(`unsupported key kind ${kind} for JSON-LD signing`);
    }
    const vmPublicKey = hexToBytes(publicKeyHexFromVM(vm));
    if (kind === 'secp256k1') {
      await addEcdsaSecp256k1Proof(this.credentialData, signer, vmURL, 'assertionMethod', { vmPublicKey });
    } else {
      await addECDSAProof(this.credentialData, signer, vmURL, 'assertionMethod', { vmPublicKey });
    }
  }

  /** Resolves the VM to sign with; shared with ECDSASDCredential. */
  async resolveSigningVMEntry(
    opts: CredentialOptions = {},
  ): Promise<{ vm: VerificationMethodEntry; url: string }> {
    const issuer = didFromField(this.credentialData.issuer);
    if (!issuer) throw new Error('issuer is missing or invalid');
    const options = getOptions(opts);
    return resolveSigningVM(
      issuer,
      'assertionMethod',
      options.verificationMethodKey || this.verificationMethodKey,
      options.resolver,
    );
  }

  async getSigningInput(): Promise<Uint8Array> {
    return documentDigest(this.credentialData);
  }

  /** The digest the external signer signs for `proof` (go CreateProofSigning); pass getSigningInput() as docHash. */
  async createProofSigning(docHash: Uint8Array, proof: Proof): Promise<Uint8Array> {
    return createProofSigning(this.credentialData, docHash, proof);
  }

  /**
   * Attaches a proof signed outside the SDK (getSigningInput → createProofSigning
   * → sign → addCustomProof). With verifyProof the incoming proof alone is
   * checked first; a failed check leaves the credential as it was.
   */
  async addCustomProof(proof: Proof, opts: CredentialOptions = {}): Promise<void> {
    if (!proof) throw new Error('proof cannot be nil');
    refuseReplaceOnJSONLD(opts);
    refuseHexRdfcProof(proof);
    if (opts.verificationMethodKey) {
      throw new Error(
        'verificationMethodKey cannot be applied by addCustomProof: set proof.verificationMethod on the proof you sign',
      );
    }
    if (opts.verifyProof) {
      await verifyDetachedProof(this.credentialData, getOptions(opts).resolver, proof);
    }
    await this.executeOptions(signingOptions(opts));
    addCustomProof(this.credentialData, proof);
  }

  async verify(opts: CredentialOptions = {}): Promise<void> {
    await this.executeOptions({ ...opts, verifyProof: true });
  }

  async serialize(): Promise<CredentialData> {
    if (!this.credentialData.proof) {
      throw new Error('credential must have proof before serialization');
    }
    return toMap(this.credentialData) as CredentialData;
  }

  getContents(): Uint8Array {
    return new Uint8Array(Buffer.from(JSON.stringify(this.credentialData), 'utf8'));
  }

  getType(): 'JSON' {
    return 'JSON';
  }

  extractField(path: string): unknown {
    if (!this.credentialData) return null;
    return extractFieldFromMap(this.credentialData, path);
  }

  /**
   * SHA-256 (hex) of the canonicalized credential including its proof. A
   * multibase proof (Data Integrity) uses the library canonicalizer; a legacy
   * hex proof keeps the compatible one so digests already anchored do not change.
   */
  async hash(): Promise<string> {
    if (!this.credentialData.proof) {
      throw new Error('credential must have proof before hashing');
    }
    const raw = this.credentialData.proof;
    const first = (Array.isArray(raw) ? raw[0] : raw) as { proofValue?: string };
    const pv = typeof first?.proofValue === 'string' ? first.proofValue : '';
    const multibase = pv.startsWith('z') || pv.startsWith('u');
    const canonical = multibase
      ? await canonicalizeRDF(this.credentialData)
      : await canonicalizeDocument(this.credentialData);
    return bytesToHex(computeDigest(canonical));
  }

  async addSelectiveDisclosures(_selectivePaths: string[]): Promise<Credential> {
    throw new Error('JSON credential does not support selective disclosures');
  }

  async executeOptions(opts: CredentialOptions = {}): Promise<void> {
    const options = getOptions(opts);
    const tasks: Promise<void>[] = [];

    if (options.validateSchema) {
      tasks.push(
        (async () => {
          try {
            await validateCredential(this.credentialData, options);
          } catch (err) {
            throw new Error(`validate credential: ${(err as Error).message}`);
          }
        })(),
      );
    }
    if (options.checkRevocation) {
      tasks.push(
        (async () => {
          try {
            await checkRevocation(this.credentialData);
          } catch (err) {
            throw new Error(`check revocation: ${(err as Error).message}`);
          }
        })(),
      );
    }
    if (options.verifyProof) {
      tasks.push(
        (async () => {
          let ok: boolean;
          try {
            ok = await verifyProof(this.credentialData, options.resolver, options.proofVerificationMethod);
          } catch (err) {
            throw new Error(`verify proof: ${(err as Error).message}`);
          }
          if (!ok) throw new Error('verify proof: invalid proof');
        })(),
      );
    }

    if (tasks.length > 0) {
      const results = await Promise.allSettled(tasks);
      for (const r of results) {
        if (r.status === 'rejected') {
          throw new Error(`credential verification failed: ${(r.reason as Error).message}`);
        }
      }
    }

    if (options.checkExpiration) {
      try {
        checkExpiration(this.credentialData, options.clockSkewLeewayMs);
      } catch (err) {
        throw new Error(`failed to check expiration: ${(err as Error).message}`);
      }
    }
  }

  /** Exposed for tests / VP serialization. */
  getInternalData(): CredentialData {
    return this.credentialData;
  }
}
