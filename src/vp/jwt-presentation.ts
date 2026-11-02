/**
 * JWT verifiable presentation — Node port of vp/jwt_presentation.go.
 */
import type { Proof } from '../common/dto/proof';
import { JWTVerifier, newJWTSigner } from '../common/jwt';
import { DefaultProvider } from '../common/signer/default-provider';
import type { SignerProvider } from '../common/signer/signer';
import { JSONMap } from '../common/util/json';
import { resolveSigningVM } from '../common/verification-method';
import { getOptions } from './options';
import { checkAudience, checkChallenge } from './audience';
import {
  checkExpiration,
  checkJwtTimeClaims,
  isJWTPresentation,
  serializePresentationContents,
  verifyCredentials,
} from './presentation-helper';
import type {
  Presentation,
  PresentationContents,
  PresentationData,
  PresentationOptions,
} from './types';

export class JWTPresentation implements Presentation {
  private signingInput: string;
  private payloadData: PresentationData;
  private signature: string;

  constructor(signingInput: string, payloadData: PresentationData, signature: string) {
    this.signingInput = signingInput;
    this.payloadData = payloadData;
    this.signature = signature;
  }

  static async create(
    vpc: PresentationContents,
    opts: PresentationOptions = {},
  ): Promise<JWTPresentation> {
    const m = await serializePresentationContents(vpc);

    const otherClaims: JSONMap = {};
    if (vpc.holder) {
      otherClaims.iss = vpc.holder;
      otherClaims.sub = vpc.holder;
    }
    if (vpc.validUntil) otherClaims.exp = Math.floor(vpc.validUntil.getTime() / 1000);
    if (vpc.validFrom) {
      const iat = Math.floor(vpc.validFrom.getTime() / 1000);
      otherClaims.iat = iat;
      otherClaims.nbf = iat;
    }
    if (vpc.id) otherClaims.jti = vpc.id;
    const bind = getOptions(opts);
    if (bind.challenge) otherClaims.nonce = bind.challenge;
    if (bind.domain) otherClaims.aud = bind.domain;

    const payload: JSONMap = { vp: m, ...otherClaims };

    const options = getOptions(opts);
    if (!vpc.holder) throw new Error('holder is required to resolve VM');
    const { url: kid } = await resolveSigningVM(
      vpc.holder,
      'authentication',
      options.verificationMethodKey,
      options.resolver,
    );

    const header = { typ: 'JWT', alg: 'ES256K', kid };
    const headerEncoded = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const payloadEncoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const pres = new JWTPresentation(
      headerEncoded + '.' + payloadEncoded,
      m as PresentationData,
      '',
    );
    await pres.executeOptions(opts);
    return pres;
  }

  static async parse(rawJWT: string, opts: PresentationOptions = {}): Promise<JWTPresentation> {
    if (!isJWTPresentation(rawJWT)) throw new Error('invalid JWT format');
    let trimmed = rawJWT.trim();
    if (trimmed.startsWith('"') && trimmed.endsWith('"')) trimmed = trimmed.slice(1, -1);

    const parts = trimmed.split('.');
    const headerEncoded = parts[0];
    const payloadEncoded = parts[1];
    const signature = parts.length === 3 ? parts[2] : '';

    let payloadMap: JSONMap;
    try {
      payloadMap = JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString('utf8'));
    } catch (err) {
      throw new Error(`failed to decode payload: ${(err as Error).message}`);
    }
    const vpData = payloadMap.vp;
    if (vpData === undefined) throw new Error('vp claim not found in JWT payload');
    if (!vpData || typeof vpData !== 'object' || Array.isArray(vpData)) {
      throw new Error('vp claim is not a valid JSON object');
    }

    const pres = new JWTPresentation(
      headerEncoded + '.' + payloadEncoded,
      vpData as PresentationData,
      signature,
    );
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
    const options = getOptions(opts);
    if (opts.resolver || opts.verificationMethodKey) {
      const holder = this.payloadData.holder;
      if (typeof holder === 'string' && holder) {
        const headerPart = this.signingInput.split('.')[0];
        const header = JSON.parse(Buffer.from(headerPart, 'base64url').toString('utf8')) as JSONMap;
        await resolveSigningVM(
          holder,
          'authentication',
          options.verificationMethodKey || (typeof header.kid === 'string' ? header.kid : ''),
          options.resolver,
        );
      }
    }
    if (options.challenge || options.domain) {
      const { payload, header } = this.extractPayload();
      if (options.challenge) payload.nonce = options.challenge;
      if (options.domain) payload.aud = options.domain;
      const payloadEncoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
      this.signingInput = header + '.' + payloadEncoded;
    }
    const jwtSigner = newJWTSigner(signer);
    const signature = await jwtSigner.signString(this.signingInput);
    await this.executeOptions(opts);
    this.signature = signature;
  }

  async getSigningInput(): Promise<Uint8Array> {
    return new Uint8Array(Buffer.from(this.signingInput, 'utf8'));
  }

  async addCustomProof(proof: Proof, opts: PresentationOptions = {}): Promise<void> {
    if (!proof) throw new Error('proof cannot be nil');
    if (!proof.signature || proof.signature.length === 0) {
      throw new Error('proof signature cannot be empty');
    }
    await this.executeOptions(opts);
    this.signature = Buffer.from(proof.signature).toString('base64url');
  }

  async verify(opts: PresentationOptions = {}): Promise<void> {
    await this.executeOptions({ ...opts, verifyProof: true });
  }

  async serialize(): Promise<string> {
    return this.signature ? this.signingInput + '.' + this.signature : this.signingInput;
  }

  getContents(): Uint8Array {
    return new Uint8Array(Buffer.from(JSON.stringify(this.payloadData), 'utf8'));
  }

  getType(): 'JWT' {
    return 'JWT';
  }

  private extractPayload(): { payload: JSONMap; header: string } {
    const parts = this.signingInput.split('.');
    if (parts.length !== 2) throw new Error('invalid signing input format');
    let payload: JSONMap;
    try {
      payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    } catch (err) {
      throw new Error(`failed to decode payload: ${(err as Error).message}`);
    }
    return { payload, header: parts[0] };
  }

  async executeOptions(opts: PresentationOptions = {}): Promise<void> {
    const options = getOptions(opts);
    if (options.validateVC) {
      await verifyCredentials(this.payloadData, options.clockSkewLeewayMs);
    }
    if (options.checkExpiration) {
      const { payload } = this.extractPayload();
      checkJwtTimeClaims(payload, options.clockSkewLeewayMs);
      checkExpiration(this.payloadData, options.clockSkewLeewayMs);
    }
    if (options.verifyProof) {
      const serialized = await this.serialize();
      const verifier = new JWTVerifier(options.resolver);
      await verifier.verifyJWT(serialized);
    }
    if (options.expectedChallenge || options.expectedDomain || options.requireAudience) {
      const { payload } = this.extractPayload();
      checkChallenge(payload.nonce, options.expectedChallenge);
      checkAudience(payload.aud, options);
    }
  }
}
