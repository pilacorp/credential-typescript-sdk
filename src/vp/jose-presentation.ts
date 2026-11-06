/**
 * JOSE verifiable presentation (vp+jwt / vp+sd-jwt) — Node port of
 * vp/jose_presentation.go.
 *
 * W3C VC 2.0 Securing Verifiable Presentations using JOSE (vc-jose-cose): the
 * unsecured VP is the flat JWS payload (no legacy "vp" wrapper claim), the
 * header carries typ "vp+jwt", and embedded credentials MUST be
 * EnvelopedVerifiableCredential entries. Holder binding is enforced by the
 * shared JWTVerifier (purpose=authentication), as for the VC 1.1 JWT path.
 */
import type { Proof } from '../common/dto/proof';
import { acceptSignature, JWTVerifier, resolveSigningKey, SigningKey } from '../common/jwt';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '../common/crypto/hex';
import { isSDJWT } from '../common/sdjwt';
import { DefaultProvider } from '../common/signer/default-provider';
import type { SignerProvider } from '../common/signer/signer';
import { JSONMap } from '../common/util/json';
import { TypeEnvelopedVC, TypeVCJWT, TypeVCSDJWT } from '../vc/jose-credential';
import {
  getOptions,
  refuseOverwrite,
  rejectBuildTimeOptions,
  signingOptions,
} from './options';
import { checkAudience, checkChallenge } from './audience';
import {
  checkExpiration,
  checkJwtTimeClaims,
  extractFieldFromMap,
  isJWTPresentation,
  serializePresentationContents,
  verifyCredentials,
} from './presentation-helper';
import type {
  Presentation,
  PresentationContents,
  PresentationData,
  PresentationOptions,
  SignablePresentation,
} from './types';

const CREDENTIALS_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
const TYPE_VERIFIABLE_PRESENTATION = 'VerifiablePresentation';

/** Media type vc-jose-cose gives a JWS-secured presentation (typ header). */
export const TypeVPJWT = 'vp+jwt';

/** What getType() reports for a vc-jose-cose presentation (go vp.TypeJOSE). */
export const TypeJOSE = 'JOSE';

/** Reports whether typ names a JOSE (vc-jose-cose) presentation. */
export function isJOSEPresentationTyp(typ: string | undefined): boolean {
  return typ === TypeVPJWT || typ === `application/${TypeVPJWT}`;
}

function typeNames(type: unknown): string[] {
  if (Array.isArray(type)) return type.filter((t): t is string => typeof t === 'string');
  if (typeof type === 'string') return [type];
  return [];
}

/**
 * A signature proves who produced the bytes, not what the bytes are. vc-jose-cose
 * requires the document handed back to be a well-formed VCDM 2.0 presentation:
 * v2 context first, type VerifiablePresentation.
 */
function requireJOSEPresentation(m: PresentationData): void {
  const ctx = m['@context'];
  const first = Array.isArray(ctx) ? ctx[0] : ctx;
  if (first !== CREDENTIALS_V2_CONTEXT) {
    throw new Error(
      `${TypeVPJWT} payload must name "${CREDENTIALS_V2_CONTEXT}" first in @context, got ${JSON.stringify(first)}`,
    );
  }
  if (!typeNames(m.type).includes(TYPE_VERIFIABLE_PRESENTATION)) {
    throw new Error(`${TypeVPJWT} payload must have type ${TYPE_VERIFIABLE_PRESENTATION}`);
  }
}

/**
 * vc-jose-cose §3.1.2: credentials in a vp+jwt MUST use the Enveloped
 * Verifiable Credential type. A bare vc+jwt string or bare JSON-LD credential
 * loses the data: URL that tells a verifier which mechanism secured it.
 */
function requireEnvelopedCredentials(m: PresentationData): void {
  const raw = m.verifiableCredential;
  if (raw === undefined || raw === null) return; // no credentials to hold.
  const items = Array.isArray(raw) ? raw : [raw];
  items.forEach((item, i) => {
    const entry = item as Record<string, unknown> | null;
    const ok =
      entry !== null &&
      typeof entry === 'object' &&
      !Array.isArray(entry) &&
      typeNames(entry.type).includes(TypeEnvelopedVC);
    if (!ok) {
      throw new Error(
        `credential at index ${i} must be an ${TypeEnvelopedVC}; a ${TypeVPJWT} carries credentials enveloped, not bare`,
      );
    }
  });
}

/**
 * Names the scheme that secured a token for an EnvelopedVerifiableCredential's
 * data: URL. Disclosures make it an SD-JWT (vc+sd-jwt). An unsigned token is
 * refused rather than enveloped under a label it has not earned.
 */
function envelopeMediaType(token: string): string {
  let base = token;
  const tilde = base.indexOf('~');
  if (tilde >= 0) base = base.slice(0, tilde);
  const parts = base.split('.');
  if (parts.length !== 3 || parts[2] === '') {
    throw new Error('credential is not signed; sign it before putting it in a presentation');
  }
  return isSDJWT(token) ? TypeVCSDJWT : TypeVCJWT;
}

export class JOSEPresentation implements SignablePresentation {
  private signingInput: string;
  private payloadData: PresentationData;
  private signature: string;
  private signingKey: SigningKey | null;

  constructor(
    signingInput: string,
    payloadData: PresentationData,
    signature: string,
    signingKey: SigningKey | null = null,
  ) {
    this.signingInput = signingInput;
    this.payloadData = payloadData;
    this.signature = signature;
    this.signingKey = signingKey;
  }

  static async create(
    vpc: PresentationContents,
    opts: PresentationOptions = {},
  ): Promise<JOSEPresentation> {
    if (!vpc.context || vpc.context.length === 0) {
      vpc = { ...vpc, context: [CREDENTIALS_V2_CONTEXT] };
    }
    // Build the base map without the credentials: Go envelopes them separately
    // and overrides the field, so serializing them here would be wasted work
    // (and the TS helper verifies them against the network at build time).
    const { verifiableCredentials, ...rest } = vpc;
    const payloadData = (await serializePresentationContents(rest)) as PresentationData;

    requireJOSEPresentation(payloadData);

    if (verifiableCredentials && verifiableCredentials.length > 0) {
      const enveloped: unknown[] = [];
      for (let i = 0; i < verifiableCredentials.length; i++) {
        const cred = verifiableCredentials[i];
        if (!cred) throw new Error(`credential at index ${i} is nil`);
        if (cred.getType() !== 'JOSE') {
          throw new Error(
            `credential at index ${i} is ${cred.getType()}: a ${TypeVPJWT} presentation can only carry ` +
              'enveloping-secured credentials; use a JSON presentation for Data Integrity credentials',
          );
        }
        const serialized = await cred.serialize();
        if (typeof serialized !== 'string') {
          throw new Error(`credential at index ${i} serialized to ${typeof serialized}, want a token string`);
        }
        const mediaType = envelopeMediaType(serialized);
        enveloped.push({
          '@context': [CREDENTIALS_V2_CONTEXT],
          type: [TypeEnvelopedVC],
          id: `data:application/${mediaType},${serialized}`,
        });
      }
      payloadData.verifiableCredential = enveloped;
    }

    const options = getOptions(opts);
    if (options.challenge) payloadData.nonce = options.challenge;
    if (options.domain) payloadData.aud = options.domain;

    // vc-jose-cose §1.1.2.1: vc and vp MUST NOT appear in the claims set.
    delete payloadData.vc;
    delete payloadData.vp;

    // iat gives the verifier a signing time to compare a soft revocation against.
    payloadData.iat = Math.floor(Date.now() / 1000);

    if (!vpc.holder) throw new Error('holder is required to resolve VM');
    // alg follows the VM's key; an RSA or unrecognized key is an error, not ES256K.
    const signingKey = await resolveSigningKey(
      vpc.holder,
      'authentication',
      options.verificationMethodKey,
      options.resolver,
    );

    const header = { typ: TypeVPJWT, alg: signingKey.alg, kid: signingKey.id };
    const headerEncoded = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const payloadEncoded = Buffer.from(JSON.stringify(payloadData), 'utf8').toString('base64url');

    const pres = new JOSEPresentation(headerEncoded + '.' + payloadEncoded, payloadData, '', signingKey);
    await pres.executeOptions(opts);
    return pres;
  }

  static async parse(rawJWT: string, opts: PresentationOptions = {}): Promise<JOSEPresentation> {
    let trimmed = rawJWT.trim();
    if (trimmed.startsWith('"') && trimmed.endsWith('"')) trimmed = trimmed.slice(1, -1);
    if (!isJWTPresentation(trimmed)) throw new Error('invalid JWT format');

    const parts = trimmed.split('.');
    const headerEncoded = parts[0];
    const payloadEncoded = parts[1];
    const signature = parts.length === 3 ? parts[2] : '';

    let headerMap: JSONMap;
    try {
      headerMap = JSON.parse(Buffer.from(headerEncoded, 'base64url').toString('utf8'));
    } catch (err) {
      throw new Error(`failed to decode header: ${(err as Error).message}`);
    }
    const typ = typeof headerMap.typ === 'string' ? headerMap.typ : undefined;
    if (!isJOSEPresentationTyp(typ)) {
      throw new Error(`invalid typ header for JOSEPresentation: got ${JSON.stringify(typ)}, want ${JSON.stringify(TypeVPJWT)}`);
    }

    let payloadMap: JSONMap;
    try {
      payloadMap = JSON.parse(Buffer.from(payloadEncoded, 'base64url').toString('utf8'));
    } catch (err) {
      throw new Error(`failed to decode payload: ${(err as Error).message}`);
    }
    if ('vc' in payloadMap) {
      throw new Error("invalid vc-jose-cose: 'vc' claim MUST NOT be present in payload");
    }
    if ('vp' in payloadMap) {
      throw new Error("invalid vc-jose-cose: 'vp' claim MUST NOT be present in payload");
    }
    requireJOSEPresentation(payloadMap as PresentationData);
    requireEnvelopedCredentials(payloadMap as PresentationData);

    const pres = new JOSEPresentation(
      headerEncoded + '.' + payloadEncoded,
      payloadMap as PresentationData,
      signature,
    );
    await pres.executeOptions(opts);
    return pres;
  }

  async addProof(priv: string, opts: PresentationOptions = {}): Promise<void> {
    await this.addProofByProvider(new DefaultProvider(priv), opts);
  }

  async addProofByProvider(signer: SignerProvider, opts: PresentationOptions = {}): Promise<void> {
    if (!signer) throw new Error('signer provider cannot be nil');
    rejectBuildTimeOptions(opts, false);
    refuseOverwrite(this.signature, opts);

    // challenge/domain are committed (nonce/aud) only after a successful sign.
    const options = getOptions(opts);
    let signingInput = this.signingInput;
    let payload: PresentationData | null = null;
    if (options.challenge || options.domain) {
      const decoded = this.decodeSigningInput();
      if (options.challenge) decoded.payload.nonce = options.challenge;
      if (options.domain) decoded.payload.aud = options.domain;
      payload = decoded.payload as PresentationData;
      signingInput =
        decoded.header + '.' + Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    }
    await this.executeOptions(signingOptions(opts));

    const raw = await signer.sign(sha256(Buffer.from(signingInput, 'utf8')));
    const signature = acceptSignature(this.signingKey, signingInput, raw);
    this.signingInput = signingInput;
    if (payload) this.payloadData = payload;
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
    rejectBuildTimeOptions(opts, true);
    refuseOverwrite(this.signature, opts);
    await this.executeOptions(signingOptions(opts));
    this.signature = acceptSignature(this.signingKey, this.signingInput, proof.signature);
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

  getType(): 'JOSE' {
    return TypeJOSE;
  }

  extractField(path: string): unknown {
    return extractFieldFromMap(this.payloadData, path);
  }

  /** SHA-256 (hex) of the serialized token; the presentation must be signed first. */
  async hash(): Promise<string> {
    if (!this.signature) {
      throw new Error('presentation must be signed before hashing');
    }
    return bytesToHex(sha256(Buffer.from(await this.serialize(), 'utf8')));
  }

  private decodeSigningInput(): { payload: JSONMap; header: string } {
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
      await verifyCredentials(this.payloadData, options);
    }
    if (options.checkExpiration) {
      // The vp+jwt payload is flat: exp/nbf/iat and validFrom/validUntil all sit
      // at the top level of payloadData.
      checkJwtTimeClaims(this.payloadData, options.clockSkewLeewayMs);
      checkExpiration(this.payloadData, options.clockSkewLeewayMs);
    }
    if (options.verifyProof) {
      if (!this.signature) throw new Error('presentation is not signed');
      const verifier = new JWTVerifier(options.resolver);
      await verifier.verifyJWT(this.signingInput + '.' + this.signature);
      // exp and nbf bound the signature, so they belong to proof verification.
      checkJwtTimeClaims(this.payloadData, options.clockSkewLeewayMs);
      checkChallenge(this.payloadData.nonce, options.expectedChallenge);
      checkAudience(this.payloadData.aud, options);
    }
  }
}
