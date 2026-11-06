/**
 * JSON-LD verifiable presentation — Node port of vp/json_presentation.go.
 */
import type { Proof } from '../common/dto/proof';
import {
  addCustomProof,
  addECDSAProof,
  addEcdsaSecp256k1Proof,
  createProofSigning,
  didFromField,
  documentDigest,
  proofs as proofsOf,
  refuseHexRdfcProof,
  toMap,
  verifyDetachedProof,
  verifyProof,
} from '../common/jsonmap/jsonmap';
import { hexToBytes } from '../common/crypto/hex';
import { P256Provider } from '../common/signer/p256-provider';
import type { SignerProvider } from '../common/signer/signer';
import { publicKeyHexFromVM, resolveSigningVM, vmKeyKind } from '../common/verification-method';
import { CredentialError, ErrorCode } from '../common/errors';
import { getOptions, refuseReplaceOnJSONLD, signingOptions } from './options';
import { audContains } from './audience';
import {
  checkExpiration,
  extractFieldFromMap,
  serializePresentationContents,
  verifyCredentials,
} from './presentation-helper';
import type {
  PresentationContents,
  PresentationData,
  PresentationOptions,
  SignablePresentation,
} from './types';

export class JSONPresentation implements SignablePresentation {
  private presentationData: PresentationData;
  private verificationMethodKey: string;

  constructor(presentationData: PresentationData, verificationMethodKey = '') {
    this.presentationData = presentationData;
    this.verificationMethodKey = verificationMethodKey;
  }

  static async create(
    vpc: PresentationContents,
    opts: PresentationOptions = {},
  ): Promise<JSONPresentation> {
    const m = await serializePresentationContents(vpc);
    const options = getOptions(opts);
    const pres = new JSONPresentation(m, options.verificationMethodKey);
    await pres.executeOptions(opts);
    return pres;
  }

  static async parse(
    rawJSON: Uint8Array | string,
    opts: PresentationOptions = {},
  ): Promise<JSONPresentation> {
    const buf = typeof rawJSON === 'string' ? Buffer.from(rawJSON, 'utf8') : Buffer.from(rawJSON);
    if (buf.length === 0) throw new Error('JSON string is empty');
    let parsed: unknown;
    try {
      parsed = JSON.parse(buf.toString('utf8'));
    } catch (err) {
      throw new Error(`failed to unmarshal presentation: ${(err as Error).message}`);
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('invalid JSON format');
    }
    const pres = new JSONPresentation(parsed as PresentationData);
    await pres.executeOptions(opts);
    return pres;
  }

  /** Signs with a raw P-256 private key (hex scalar), like Go. For secp256k1 use addProofByProvider(new DefaultProvider(hex)). */
  async addProof(priv: string, opts: PresentationOptions = {}): Promise<void> {
    await this.addProofByProvider(new P256Provider(priv), opts);
  }

  /** Signs (appending to the proof set) bound to the VM the options pin, or the holder's default one. */
  async addProofByProvider(
    signer: SignerProvider,
    opts: PresentationOptions = {},
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
    const options = getOptions(opts);
    const extras = {
      challenge: options.challenge || undefined,
      domain: options.domain || undefined,
      vmPublicKey: hexToBytes(publicKeyHexFromVM(vm)),
    };
    if (kind === 'secp256k1') {
      await addEcdsaSecp256k1Proof(this.presentationData, signer, vmURL, 'authentication', extras);
    } else {
      await addECDSAProof(this.presentationData, signer, vmURL, 'authentication', extras);
    }
  }

  private async resolveSigningVMEntry(opts: PresentationOptions) {
    const holder = didFromField(this.presentationData.holder);
    if (!holder) throw new Error('holder is missing or invalid');
    const options = getOptions(opts);
    return resolveSigningVM(
      holder,
      'authentication',
      options.verificationMethodKey || this.verificationMethodKey,
      options.resolver,
    );
  }

  async getSigningInput(): Promise<Uint8Array> {
    return documentDigest(this.presentationData);
  }

  /** The digest the external signer signs for `proof` (go CreateProofSigning). */
  async createProofSigning(docHash: Uint8Array, proof: Proof): Promise<Uint8Array> {
    return createProofSigning(this.presentationData, docHash, proof);
  }

  /** Attaches a proof signed outside the SDK; challenge/domain/VM belong on the proof itself. */
  async addCustomProof(proof: Proof, opts: PresentationOptions = {}): Promise<void> {
    if (!proof) throw new Error('proof cannot be nil');
    refuseReplaceOnJSONLD(opts);
    refuseHexRdfcProof(proof);
    if (opts.challenge || opts.domain || opts.verificationMethodKey) {
      throw new Error(
        'challenge / domain / verificationMethodKey cannot be applied by addCustomProof: set proof.challenge, proof.domain and proof.verificationMethod on the proof you sign',
      );
    }
    if (opts.verifyProof) {
      await verifyDetachedProof(this.presentationData, getOptions(opts).resolver, proof);
    }
    await this.executeOptions(signingOptions(opts));
    addCustomProof(this.presentationData, proof);
  }

  async verify(opts: PresentationOptions = {}): Promise<void> {
    await this.executeOptions({ ...opts, verifyProof: true });
  }

  async serialize(): Promise<PresentationData> {
    if (!this.presentationData.proof) {
      throw new Error('presentation must have proof before serialization');
    }
    return toMap(this.presentationData) as PresentationData;
  }

  getContents(): Uint8Array {
    return new Uint8Array(Buffer.from(JSON.stringify(this.presentationData), 'utf8'));
  }

  getType(): 'JSON' {
    return 'JSON';
  }

  extractField(path: string): unknown {
    return extractFieldFromMap(this.presentationData, path);
  }

  async executeOptions(opts: PresentationOptions = {}): Promise<void> {
    const options = getOptions(opts);
    if (options.validateVC) {
      await verifyCredentials(this.presentationData, options);
    }
    if (options.checkExpiration) {
      checkExpiration(this.presentationData, options.clockSkewLeewayMs);
    }
    if (options.verifyProof) {
      const ok = await verifyProof(this.presentationData, options.resolver, options.proofVerificationMethod);
      if (!ok) throw new Error('invalid proof');
      this.checkChallengeAndDomain(options);
    }
  }

  // Every proof that was verified must carry the expected challenge and domain,
  // not just the first.
  private checkChallengeAndDomain(options: ReturnType<typeof getOptions>): void {
    if (options.requireAudience && !options.expectedDomain) {
      throw new CredentialError(
        ErrorCode.AudienceUnbound,
        'WithRequireAudience needs WithExpectedDomain',
      );
    }
    if (!options.expectedChallenge && !options.expectedDomain) return;
    for (const p of proofsOf(this.presentationData)) {
      if (options.proofVerificationMethod && p.verificationMethod !== options.proofVerificationMethod) continue;
      if (options.expectedChallenge && p.challenge !== options.expectedChallenge) {
        throw new CredentialError(
          ErrorCode.ChallengeMismatch,
          `proof (${p.verificationMethod}): challenge ${JSON.stringify(p.challenge)} does not match expected ${JSON.stringify(options.expectedChallenge)}`,
        );
      }
      if (options.expectedDomain && !audContains(p.domain, options.expectedDomain)) {
        throw new CredentialError(
          ErrorCode.DomainMismatch,
          `proof (${p.verificationMethod}): domain ${JSON.stringify(p.domain)} does not match expected ${JSON.stringify(options.expectedDomain)}`,
        );
      }
    }
  }
}
