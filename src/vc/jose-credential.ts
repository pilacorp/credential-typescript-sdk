/**
 * VC-JOSE (vc+jwt / vc+sd-jwt) — Node port of vc/jose_credential.go.
 * The unsecured VC is the JWS payload (no nested `vc` claim).
 */
import { newJWTSigner, JWTVerifier } from '../common/jwt';
import { DefaultProvider } from '../common/signer/default-provider';
import { P256Provider } from '../common/signer/p256-provider';
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
import { resolveSigningVM } from '../common/verification-method';
import { JSONMap } from '../common/util/json';
import { getOptions } from './options';
import {
  checkExpiration,
  checkJwtTimeClaims,
  checkRevocation,
  extractFieldFromMap,
  normalizeCredentialData,
  serializeCredentialContents,
  validateCredential,
} from './credential-helper';
import type {
  Credential,
  CredentialContents,
  CredentialData,
  CredentialOptions,
} from './types';
import { isJWTCredentialString } from './jwt-credential';

export const TypeVCJWT = 'vc+jwt';
export const TypeVCSDJWT = 'vc+sd-jwt';
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

function requireJOSECredential(m: CredentialData): void {
  const types = m.type;
  const names = Array.isArray(types) ? types : types ? [types] : [];
  if (!names.includes('VerifiableCredential')) {
    throw new Error('vc+jwt payload must include type VerifiableCredential');
  }
  if (!m.issuer) throw new Error('vc+jwt payload is missing issuer');
  if (!m.credentialSubject) throw new Error('vc+jwt payload is missing credentialSubject');
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

export class JOSECredential implements Credential {
  private signingInput: string;
  private payloadData: CredentialData;
  private signature: string;
  private disclosures: string[];

  constructor(
    signingInput: string,
    payloadData: CredentialData,
    signature: string,
    disclosures: string[],
  ) {
    this.signingInput = signingInput;
    this.payloadData = payloadData;
    this.signature = signature;
    this.disclosures = disclosures;
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
    delete vcMap.vc;
    delete vcMap.vp;

    if (!vcc.issuer) throw new Error('issuer is required to resolve VM');
    const { url: kid } = await resolveSigningVM(
      vcc.issuer,
      'assertionMethod',
      options.verificationMethodKey,
      options.resolver,
    );

    const disclosable = '_sd_alg' in vcMap;
    const header = {
      typ: disclosable || disclosures.length > 0 ? TypeVCSDJWT : TypeVCJWT,
      alg: 'ES256K',
      kid,
    };
    const headerEncoded = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const payloadEncoded = Buffer.from(JSON.stringify(vcMap), 'utf8').toString('base64url');
    const cred = new JOSECredential(
      headerEncoded + '.' + payloadEncoded,
      vcMap as CredentialData,
      '',
      disclosures,
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
    if (isSDJWT(trimmed)) {
      const segments = trimmed.split('~');
      const tail = segments[segments.length - 1];
      if (tail && isJWT(tail)) throw new Error('key binding JWT is not supported');
      const parsed = parseSDJWT(trimmed);
      issuerJWT = parsed.baseJWT;
      disclosures = parsed.disclosures;
    } else {
      if (!isJWTCredentialString(trimmed)) {
        throw new Error('invalid JWT or SD-JWT format');
      }
      issuerJWT = trimmed;
    }

    const parts = issuerJWT.split('.');
    const headerMap = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as JSONMap;
    if (!isJOSECredentialTyp(typeof headerMap.typ === 'string' ? headerMap.typ : undefined)) {
      throw new Error(`invalid vc-jose typ: ${String(headerMap.typ)}`);
    }
    const payloadMap = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as JSONMap;
    if ('vc' in payloadMap || 'vp' in payloadMap) {
      throw new Error('vc+jwt payload must not contain vc or vp claims');
    }
    requireJOSECredential(payloadMap as CredentialData);
    let vcMap = payloadMap;
    if ('_sd_alg' in vcMap || disclosures.length > 0) {
      vcMap = reconstruct(vcMap, disclosures, true);
    }

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
    if (opts.resolver || opts.verificationMethodKey) {
      const options = getOptions(opts);
      const issuer = this.payloadData.issuer;
      if (typeof issuer === 'string' && issuer) {
        const header = JSON.parse(
          Buffer.from(this.signingInput.split('.')[0], 'base64url').toString('utf8'),
        ) as JSONMap;
        await resolveSigningVM(
          issuer,
          'assertionMethod',
          options.verificationMethodKey || (typeof header.kid === 'string' ? header.kid : ''),
          options.resolver,
        );
      }
    }
    if (signer instanceof P256Provider) {
      const parts = this.signingInput.split('.');
      const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as JSONMap;
      header.alg = 'ES256';
      const headerEncoded = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
      this.signingInput = headerEncoded + '.' + parts[1];
    }
    const jwtSigner = newJWTSigner(signer);
    const signature = await jwtSigner.signString(this.signingInput);
    await this.executeOptions(opts);
    this.signature = signature;
  }

  async getSigningInput(): Promise<Uint8Array> {
    return new Uint8Array(Buffer.from(this.signingInput, 'utf8'));
  }

  async addCustomProof(proof: Proof, opts: CredentialOptions = {}): Promise<void> {
    if (!proof) throw new Error('proof cannot be nil');
    if (!proof.signature || proof.signature.length === 0) {
      throw new Error('proof signature cannot be empty');
    }
    await this.executeOptions(opts);
    this.signature = Buffer.from(proof.signature).toString('base64url');
  }

  async verify(opts: CredentialOptions = {}): Promise<void> {
    await this.executeOptions({ ...opts, verifyProof: true });
  }

  async serialize(): Promise<string> {
    let base = this.signingInput;
    if (this.signature || this.disclosures.length > 0 || this.isDisclosable()) {
      base = base + '.' + this.signature;
    }
    if (!this.isDisclosable() && this.disclosures.length === 0) return base;
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

  async addSelectiveDisclosures(_selectivePaths: string[]): Promise<Credential> {
    throw new Error('use JOSECredential.create with sdSelectivePaths');
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
          const baseJWS = `${this.signingInput}.${this.signature}`;
          const verifier = new JWTVerifier(options.resolver);
          try {
            await verifier.verifyJWT(baseJWS);
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
      checkJwtTimeClaims(this.payloadData, options.clockSkewLeewayMs);
      checkExpiration(this.payloadData, options.clockSkewLeewayMs);
    }
  }
}
