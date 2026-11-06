/**
 * VC-JOSE (vc+jwt / vc+sd-jwt) — Node port of vc/jose_credential.go.
 * The unsecured VC is the JWS payload (no nested `vc` claim).
 */
import { acceptSignature, JWTVerifier, resolveSigningKey, SigningKey } from '../common/jwt';
import { DefaultProvider } from '../common/signer/default-provider';
import type { SignerProvider } from '../common/signer/signer';
import type { Proof } from '../common/dto/proof';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '../common/crypto/hex';
import { CredentialError, ErrorCode } from '../common/errors';
import {
  buildDisclosures,
  buildSDJWTPresentation,
  decodeDisclosures,
  isJWT,
  isSDJWT,
  parse as parseSDJWT,
  reconstruct,
} from '../common/sdjwt';
import type { DecodedDisclosure } from '../common/sdjwt';
import { JSONMap } from '../common/util/json';
import {
  getOptions,
  refuseOverwrite,
  rejectBuildTimeOptions,
  signingOptions,
} from './options';
import { carriesSDMachinery, requireDisclosableAtTopLevel, requireSecuredClaimsSigned } from './sd-checks';
import {
  checkExpiration,
  checkJwtTimeClaims,
  checkRevocation,
  extractFieldFromMap,
  normalizeCredentialData,
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
import { isJWTCredentialString } from './jwt-credential';

export const TypeVCJWT = 'vc+jwt';
export const TypeVCSDJWT = 'vc+sd-jwt';
export const TypeEnvelopedVC = 'EnvelopedVerifiableCredential';
/** What getType() reports for a vc-jose-cose credential (go vc.TypeJOSE). */
export const TypeJOSE = 'JOSE';
const CREDENTIALS_V2_CONTEXT = 'https://www.w3.org/ns/credentials/v2';

export function isJOSECredentialTyp(typ: string | undefined): boolean {
  if (!typ) return false;
  return (
    typ === TypeVCJWT ||
    typ === `application/${TypeVCJWT}` ||
    typ === TypeVCSDJWT ||
    typ === `application/${TypeVCSDJWT}`
  );
}

export function peekJwtTyp(token: string): string | undefined {
  const base = token.includes('~') ? token.split('~')[0] : token;
  const parts = base.split('.');
  if (parts.length < 2) return undefined;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as JSONMap;
    return typeof header.typ === 'string' ? header.typ : undefined;
  } catch {
    return undefined;
  }
}

/** A signature proves who produced the bytes, not that they are a vc+jwt credential. */
function requireJOSECredential(m: CredentialData): void {
  requireCredentialProperties(m);
  const ctx = m['@context'];
  const first = Array.isArray(ctx) ? ctx[0] : ctx;
  if (first !== CREDENTIALS_V2_CONTEXT) {
    throw new Error(
      `credential must name "${CREDENTIALS_V2_CONTEXT}" first in @context, got ${JSON.stringify(first)}`,
    );
  }
  const types = m.type;
  const names = Array.isArray(types) ? types : [types];
  if (!names.includes('VerifiableCredential')) {
    throw new Error(`credential type must include VerifiableCredential, got ${JSON.stringify(types)}`);
  }
}

function requireV2Context(context: unknown[] | undefined): unknown[] {
  if (!context || context.length === 0) return [CREDENTIALS_V2_CONTEXT];
  const first = context[0];
  if (first !== CREDENTIALS_V2_CONTEXT) {
    throw new Error(
      `credential must name "${CREDENTIALS_V2_CONTEXT}" first in @context, got ${JSON.stringify(first)}`,
    );
  }
  return context;
}

export class JOSECredential implements SignableCredential {
  private signingInput: string;
  private payloadData: CredentialData;
  private signature: string;
  private disclosures: string[];
  private signingKey: SigningKey | null;

  constructor(
    signingInput: string,
    payloadData: CredentialData,
    signature: string,
    disclosures: string[],
    signingKey: SigningKey | null = null,
  ) {
    this.signingInput = signingInput;
    this.payloadData = payloadData;
    this.signature = signature;
    this.disclosures = disclosures;
    this.signingKey = signingKey;
  }

  static async create(
    vcc: CredentialContents,
    opts: CredentialOptions = {},
  ): Promise<JOSECredential> {
    vcc = { ...vcc, context: requireV2Context(vcc.context) };
    if (!vcc.types || vcc.types.length === 0) {
      vcc = { ...vcc, types: ['VerifiableCredential'] };
    }
    const m = serializeCredentialContents(vcc);
    let vcMap = normalizeCredentialData(m);
    requireJOSECredential(vcMap as CredentialData);
    const options = getOptions(opts);

    const result = buildDisclosures({
      vc: vcMap,
      selectivePaths: options.sdSelectivePaths,
      hashAlgorithm: options.sdAlg,
      shuffle: options.sdShuffle,
      decoys: options.sdDecoys,
    });
    vcMap = result.processedVC;
    const disclosures = [...result.disclosures, ...options.sdDisclosures];
    // Caller-built disclosures need the _sd_alg the digests were made under.
    if (options.sdDisclosures.length > 0 && !('_sd_alg' in vcMap)) {
      vcMap._sd_alg = options.sdAlg || 'sha-256';
    }
    requireDisclosableAtTopLevel(vcMap, true);
    // Validate rather than trust: every disclosure must match a digest, once.
    try {
      reconstruct(vcMap, disclosures, true);
    } catch (err) {
      throw new Error(`invalid SD-JWT disclosures: ${(err as Error).message}`);
    }
    delete vcMap.vc;
    delete vcMap.vp;
    // iat gives the verifier a signing time to compare a soft revocation against.
    vcMap.iat = Math.floor(Date.now() / 1000);

    if (!vcc.issuer) throw new Error('issuer is required to resolve VM');
    const signingKey = await resolveSigningKey(
      vcc.issuer,
      'assertionMethod',
      options.verificationMethodKey,
      options.resolver,
    );

    // typ follows the payload (decoy-only credentials count): vc+sd-jwt when _sd_alg is present.
    const disclosable = '_sd_alg' in vcMap;
    const header = {
      typ: disclosable ? TypeVCSDJWT : TypeVCJWT,
      alg: signingKey.alg,
      kid: signingKey.id,
    };
    const headerEncoded = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const payloadEncoded = Buffer.from(JSON.stringify(vcMap), 'utf8').toString('base64url');
    const cred = new JOSECredential(
      headerEncoded + '.' + payloadEncoded,
      vcMap as CredentialData,
      '',
      disclosures,
      signingKey,
    );
    await cred.executeOptions(opts);
    return cred;
  }

  static async parse(rawJWT: string, opts: CredentialOptions = {}): Promise<JOSECredential> {
    let trimmed = rawJWT.trim();
    if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
      trimmed = trimmed.slice(1, -1);
    }

    let issuerJWT: string;
    let disclosures: string[] = [];
    const combinedSD = isSDJWT(trimmed);
    if (combinedSD) {
      const parsed = parseSDJWT(trimmed); // refuses a key binding JWT
      issuerJWT = parsed.baseJWT;
      disclosures = parsed.disclosures;
    } else {
      if (!isJWTCredentialString(trimmed)) {
        throw new Error('invalid JWT or SD-JWT format');
      }
      issuerJWT = trimmed;
    }

    const parts = issuerJWT.split('.');
    let headerMap: JSONMap;
    try {
      headerMap = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as JSONMap;
    } catch (err) {
      throw new Error(`failed to decode header: ${(err as Error).message}`);
    }
    const typ = typeof headerMap.typ === 'string' ? headerMap.typ : '';
    if (!isJOSECredentialTyp(typ)) {
      throw new Error(`invalid typ header for JOSECredential: got ${JSON.stringify(typ)}, want "${TypeVCJWT}" or "${TypeVCSDJWT}"`);
    }
    let payloadMap: JSONMap;
    try {
      payloadMap = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as JSONMap;
    } catch (err) {
      throw new Error(`failed to decode payload: ${(err as Error).message}`);
    }
    if (!payloadMap || typeof payloadMap !== 'object' || Array.isArray(payloadMap)) {
      throw new Error('failed to unmarshal payload: not an object');
    }
    if ('vc' in payloadMap || 'vp' in payloadMap) {
      throw new Error('vc+jwt payload must not contain vc or vp claims');
    }

    // Whether this is an SD-JWT is answered by the media type and the combined
    // format, not only by a claim inside the payload (_sd_alg is optional in RFC 9901).
    const declaredSD = typ.replace(/^application\//, '') === TypeVCSDJWT;
    const hasSDAlg = '_sd_alg' in payloadMap;
    // A header typed vc+jwt means plain JWS to every other verifier.
    if (!declaredSD && (combinedSD || hasSDAlg)) {
      throw new Error(`typ "${typ}" does not match the SD-JWT format`);
    }
    // The issuer must not have made anything outside credentialSubject
    // disclosable; runs before reconstruct, which removes the evidence.
    requireDisclosableAtTopLevel(payloadMap, declaredSD);

    let vcMap = payloadMap;
    // Reconstruct also strips _sd and _sd_alg, so it runs whenever the token is
    // an SD-JWT (or digests are present), not only when a disclosure arrived.
    const disclosable = declaredSD || combinedSD || hasSDAlg || carriesSDMachinery(payloadMap);
    if (disclosable || disclosures.length > 0) {
      vcMap = reconstruct(payloadMap, disclosures, true);
    }
    requireSecuredClaimsSigned(payloadMap, vcMap);
    requireJOSECredential(vcMap as CredentialData);

    const cred = new JOSECredential(
      parts[0] + '.' + parts[1],
      vcMap as CredentialData,
      parts.length === 3 ? parts[2] : '',
      disclosures,
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
    this.signature = acceptSignature(this.signingKey, this.signingInput, raw);
  }

  async getSigningInput(): Promise<Uint8Array> {
    return new Uint8Array(Buffer.from(this.signingInput, 'utf8'));
  }

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
    let base = this.signingInput;
    if (this.signature) base = base + '.' + this.signature;
    if (!this.isDisclosable()) return base;
    let out = base;
    for (const d of this.disclosures) {
      if (!d) continue;
      out += '~' + d;
    }
    out += '~';
    return out;
  }

  getContents(): Uint8Array {
    return new Uint8Array(Buffer.from(JSON.stringify(this.payloadData), 'utf8'));
  }

  getType(): 'JOSE' {
    return 'JOSE';
  }

  extractField(path: string): unknown {
    if (!this.payloadData) return null;
    return extractFieldFromMap(this.payloadData, path);
  }

  decodedDisclosures(): DecodedDisclosure[] {
    return decodeDisclosures(this.disclosures);
  }

  isDisclosable(): boolean {
    const typ = peekJwtTyp(this.signingInput);
    return typ === TypeVCSDJWT || typ === `application/${TypeVCSDJWT}`;
  }

  async present(selectedDisclosures: string[]): Promise<JOSECredential> {
    if (!this.signature) {
      throw new CredentialError(ErrorCode.Unsigned, 'cannot present an unsigned credential');
    }
    if (!this.isDisclosable()) {
      throw new CredentialError(
        ErrorCode.NoDisclosures,
        'credential carries no disclosures; nothing to present selectively',
      );
    }
    const issuerJWT = `${this.signingInput}.${this.signature}`;
    return JOSECredential.parse(buildSDJWTPresentation(issuerJWT, selectedDisclosures));
  }

  async hash(): Promise<string> {
    if (!this.signature) {
      throw new CredentialError(ErrorCode.Unsigned, 'credential must be signed before hashing');
    }
    const serialized = await this.serialize();
    if (typeof serialized !== 'string') {
      throw new Error(`unexpected serialized credential type ${typeof serialized}`);
    }
    return bytesToHex(sha256(Buffer.from(serialized, 'utf8')));
  }

  async executeOptions(opts: CredentialOptions = {}): Promise<void> {
    const options = getOptions(opts);
    const tasks: Promise<void>[] = [];
    if (options.validateSchema) {
      tasks.push(validateCredential(this.payloadData, options).then(
        () => undefined,
        (err) => {
          throw new Error(`validate credential: ${(err as Error).message}`);
        },
      ));
    }
    if (options.checkRevocation) {
      tasks.push(checkRevocation(this.payloadData).then(
        () => undefined,
        (err) => {
          throw new Error(`check revocation: ${(err as Error).message}`);
        },
      ));
    }
    if (options.verifyProof) {
      tasks.push(
        (async () => {
          if (!this.signature) throw new Error('credential is not signed');
          const baseJWS = `${this.signingInput}.${this.signature}`;
          const verifier = new JWTVerifier(options.resolver);
          try {
            await verifier.verifyJWT(baseJWS);
            // exp and nbf bound the signature, so they belong to proof verification.
            checkJwtTimeClaims(this.payloadData, options.clockSkewLeewayMs);
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
      checkExpiration(this.payloadData, options.clockSkewLeewayMs);
    }
  }
}
