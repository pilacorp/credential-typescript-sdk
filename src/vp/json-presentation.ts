/**
 * JSON-LD verifiable presentation — Node port of vp/json_presentation.go.
 */
import type { Proof } from '../common/dto/proof';
import {
  addCustomProof,
  addECDSAProof,
  canonicalize,
  toMap,
  verifyProof,
} from '../common/jsonmap/jsonmap';
import { DefaultProvider } from '../common/signer/default-provider';
import type { SignerProvider } from '../common/signer/signer';
import {
  normalizeVerificationMethodURL,
  resolveVerificationMethodURL,
} from '../common/verification-method';
import { getOptions } from './options';
import {
  checkExpiration,
  serializePresentationContents,
  verifyCredentials,
} from './presentation-helper';
import type {
  Presentation,
  PresentationContents,
  PresentationData,
  PresentationOptions,
} from './types';

export class JSONPresentation implements Presentation {
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

  async addProof(priv: string, opts: PresentationOptions = {}): Promise<void> {
    const signer = new DefaultProvider(priv);
    await this.addProofByProvider(signer, opts);
  }

  async addProofByProvider(
    signer: SignerProvider,
    opts: PresentationOptions = {},
  ): Promise<void> {
    if (!signer) throw new Error('signer provider cannot be nil');
    await this.executeOptions(opts);
    const holder = this.presentationData.holder;
    if (typeof holder !== 'string' || !holder) {
      throw new Error('holder is missing or invalid');
    }
    const options = getOptions(opts);
    let vmKey = this.verificationMethodKey;
    if (options.verificationMethodKey) vmKey = options.verificationMethodKey;
    if (!vmKey) {
      vmKey = await resolveVerificationMethodURL(holder, 'authentication', options.resolver);
    } else {
      vmKey = normalizeVerificationMethodURL(holder, vmKey);
    }
    await addECDSAProof(this.presentationData, signer, vmKey, 'authentication');
  }

  async getSigningInput(): Promise<Uint8Array> {
    return canonicalize(this.presentationData);
  }

  async addCustomProof(proof: Proof, opts: PresentationOptions = {}): Promise<void> {
    if (!proof) throw new Error('proof cannot be nil');
    await this.executeOptions({
      ...opts,
      verifyProof: opts.verifyProof || Boolean(this.presentationData.proof),
    });
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

  async executeOptions(opts: PresentationOptions = {}): Promise<void> {
    const options = getOptions(opts);
    if (options.validateVC) {
      await verifyCredentials(this.presentationData, options.clockSkewLeewayMs);
    }
    if (options.checkExpiration) {
      checkExpiration(this.presentationData, options.clockSkewLeewayMs);
    }
    if (options.verifyProof) {
      const ok = await verifyProof(this.presentationData, options.resolver);
      if (!ok) throw new Error('invalid proof');
    }
  }
}
