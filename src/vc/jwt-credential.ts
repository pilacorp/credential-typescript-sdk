/**
 * JWT verifiable credential (VC 1.1) — Node port of vc/jwt_credential.go.
 *
 * Selective disclosure is not supported here (go #100): it is issued and read
 * as vc+sd-jwt through JOSECredential. Anything SD-shaped is refused with
 * ErrorCode.SDJWTRequiresJOSE.
 */
import { acceptSignature, JWTVerifier, resolveSigningKey, SigningKey } from '../common/jwt';
import { DefaultProvider } from '../common/signer/default-provider';
import type { SignerProvider } from '../common/signer/signer';
import type { Proof } from '../common/dto/proof';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '../common/crypto/hex';
import { JSONMap } from '../common/util/json';
import {
  hasSDOptions,
  getOptions,
  refuseOverwrite,
  rejectBuildTimeOptions,
  signingOptions,
} from './options';
import {
  checkExpiration,
  checkJwtTimeClaims,
  checkRevocation,
  extractFieldFromMap,
  normalizeCredentialData,
  serializeCredentialContents,
  validateCredential,
} from './credential-helper';
import { sdJWTRequiresJOSE } from './errors';
import { carriesSDJWT } from './sd-checks';
import type {
  CredentialContents,
  CredentialData,
  CredentialOptions,
  SignableCredential,
} from './types';

const JWT_REGEX = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;

export function isJWTCredentialString(valStr: string): boolean {
  return JWT_REGEX.test(valStr.replace(/^"|"$/g, ''));
}

export class JWTCredential implements SignableCredential {
  private signingInput: string;
  private payloadData: CredentialData;
  private signature: string;
  private signingKey: SigningKey | null;

  constructor(
    signingInput: string,
    payloadData: CredentialData,
    signature: string,
    signingKey: SigningKey | null = null,
  ) {
    this.signingInput = signingInput;
    this.payloadData = payloadData;
    this.signature = signature;
    this.signingKey = signingKey;
  }

  static async create(
    vcc: CredentialContents,
    opts: CredentialOptions = {},
  ): Promise<JWTCredential> {
    // Refused before anything is built and before the DID is resolved.
    if (hasSDOptions(opts)) throw sdJWTRequiresJOSE('JWTCredential.create');

    const m = serializeCredentialContents(vcc);
    const vcMap = normalizeCredentialData(m);
    if (carriesSDJWT(vcMap)) {
      throw sdJWTRequiresJOSE('JWTCredential.create: contents carry SD-JWT digests');
    }
    const options = getOptions(opts);

    const otherClaims: JSONMap = {};
    if (vcc.issuer) otherClaims.iss = vcc.issuer;
    if (vcc.subject && vcc.subject.length > 0 && vcc.subject[0].id) {
      otherClaims.sub = vcc.subject[0].id;
    }
    if (vcc.validUntil) {
      otherClaims.exp = Math.floor(vcc.validUntil.getTime() / 1000);
    }
    if (vcc.validFrom) {
      const iat = Math.floor(vcc.validFrom.getTime() / 1000);
      otherClaims.iat = iat;
      otherClaims.nbf = iat;
    }
    if (vcc.id) otherClaims.jti = vcc.id;

    const payload: JSONMap = { vc: vcMap, ...otherClaims };

    if (!vcc.issuer) throw new Error('issuer is required to resolve VM');
    // alg follows the key the VM holds; a kid that does not exist or is not
    // granted assertionMethod is caught here.
    const signingKey = await resolveSigningKey(
      vcc.issuer,
      'assertionMethod',
      options.verificationMethodKey,
      options.resolver,
    );

    const header = { typ: 'JWT', alg: signingKey.alg, kid: signingKey.id };
    const headerEncoded = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const payloadEncoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');

    const cred = new JWTCredential(
      headerEncoded + '.' + payloadEncoded,
      vcMap as CredentialData,
      '',
      signingKey,
    );
    await cred.executeOptions(opts);
    return cred;
  }

  static async parse(rawJWT: string, opts: CredentialOptions = {}): Promise<JWTCredential> {
    let trimmed = rawJWT.trim();
    if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
      trimmed = trimmed.slice(1, -1);
    }
    // base64url has no "~", so a valid JWT never contains one: that is the
    // SD-JWT combined form.
    if (trimmed.includes('~')) {
      throw sdJWTRequiresJOSE('JWTCredential.parse: token is in SD-JWT combined form');
    }
    if (!isJWTCredentialString(trimmed)) {
      throw new Error('invalid JWT or SD-JWT format');
    }

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
    // Digests in the signed payload make it an SD-JWT whether or not a
    // disclosure came with it.
    if (payloadMap && typeof payloadMap === 'object' && carriesSDJWT(payloadMap)) {
      throw sdJWTRequiresJOSE('JWTCredential.parse: payload carries SD-JWT digests');
    }
    const vcData = payloadMap.vc;
    if (vcData === undefined) {
      throw new Error('vc claim not found in JWT payload');
    }
    if (!vcData || typeof vcData !== 'object' || Array.isArray(vcData)) {
      throw new Error('vc claim is not a valid JSON object');
    }

    const cred = new JWTCredential(
      headerEncoded + '.' + payloadEncoded,
      vcData as CredentialData,
      signature,
    );
    await cred.executeOptions(opts);
    return cred;
  }

  async addProof(priv: string, opts: CredentialOptions = {}): Promise<void> {
    await this.addProofByProvider(new DefaultProvider(priv), opts);
  }

  async addProofByProvider(
    signer: SignerProvider,
    opts: CredentialOptions = {},
  ): Promise<void> {
    if (!signer) throw new Error('signer provider cannot be nil');
    rejectBuildTimeOptions(opts);
    refuseOverwrite(this.signature, opts);
    await this.executeOptions(signingOptions(opts));

    const raw = await signer.sign(sha256(Buffer.from(this.signingInput, 'utf8')));
    // Assigned only after the check, so a failed call cannot clear a signature.
    this.signature = acceptSignature(this.signingKey, this.signingInput, raw);
  }

  async getSigningInput(): Promise<Uint8Array> {
    return new Uint8Array(Buffer.from(this.signingInput, 'utf8'));
  }

  /** Attaches a signature made outside the SDK over getSigningInput(); held to the same key check. */
  async addCustomProof(proof: Proof, opts: CredentialOptions = {}): Promise<void> {
    if (!proof) throw new Error('proof cannot be nil');
    if (!proof.signature || proof.signature.length === 0) {
      throw new Error('proof signature cannot be empty');
    }
    rejectBuildTimeOptions(opts);
    refuseOverwrite(this.signature, opts);
    await this.executeOptions(signingOptions(opts));
    this.signature = acceptSignature(this.signingKey, this.signingInput, proof.signature);
  }

  async verify(opts: CredentialOptions = {}): Promise<void> {
    await this.executeOptions({ ...opts, verifyProof: true });
  }

  async serialize(): Promise<string> {
    return this.signature ? this.signingInput + '.' + this.signature : this.signingInput;
  }

  /** SHA-256 (hex) of the serialized JWT; the credential must be signed first. */
  async hash(): Promise<string> {
    if (!this.signature) throw new Error('credential must be signed before hashing');
    return bytesToHex(sha256(Buffer.from(await this.serialize(), 'utf8')));
  }

  getContents(): Uint8Array {
    return new Uint8Array(Buffer.from(JSON.stringify(this.payloadData), 'utf8'));
  }

  getType(): 'JWT' {
    return 'JWT';
  }

  extractField(path: string): unknown {
    if (!this.payloadData) return null;
    return extractFieldFromMap(this.payloadData, path);
  }

  /** A VC 1.1 JWT carries no disclosures (go DecodedDisclosures returns an empty slice). */
  decodedDisclosures(): never[] {
    return [];
  }

  /** Always refused: a VC 1.1 JWT has no disclosures to choose from (go Present). */
  async present(_selectedDisclosures: string[]): Promise<never> {
    throw sdJWTRequiresJOSE('JWTCredential.present');
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

  async executeOptions(opts: CredentialOptions = {}): Promise<void> {
    const options = getOptions(opts);

    const tasks: Promise<void>[] = [];

    if (options.validateSchema) {
      tasks.push(
        (async () => {
          try {
            await validateCredential(this.payloadData, options);
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
            await checkRevocation(this.payloadData);
          } catch (err) {
            throw new Error(`check revocation: ${(err as Error).message}`);
          }
        })(),
      );
    }
    if (options.verifyProof) {
      tasks.push(
        (async () => {
          if (!this.signature) throw new Error('credential is not signed');
          const serialized = await this.serialize();
          const verifier = new JWTVerifier(options.resolver);
          try {
            await verifier.verifyJWT(serialized);
          } catch (err) {
            throw new Error(`verify proof: ${(err as Error).message}`);
          }
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
        const { payload } = this.extractPayload();
        checkJwtTimeClaims(payload, options.clockSkewLeewayMs);
        checkExpiration(this.payloadData, options.clockSkewLeewayMs);
      } catch (err) {
        throw new Error(`failed to check expiration: ${(err as Error).message}`);
      }
    }
  }
}
