/**
 * JWT (or SD-JWT) verifiable credential — Node port of vc/jwt_credential.go.
 */
import { newJWTSigner, JWTVerifier } from '../common/jwt';
import { DefaultProvider } from '../common/signer/default-provider';
import type { SignerProvider } from '../common/signer/signer';
import type { Proof } from '../common/dto/proof';
import {
  buildDisclosures,
  isJWT,
  isSDJWT,
  parse as parseSDJWT,
  reconstruct,
} from '../common/sdjwt';
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

const JWT_REGEX = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$/;

export function isJWTCredentialString(valStr: string): boolean {
  return JWT_REGEX.test(valStr.replace(/^"|"$/g, ''));
}

export class JWTCredential implements Credential {
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
  ): Promise<JWTCredential> {
    const m = serializeCredentialContents(vcc);
    let vcMap = normalizeCredentialData(m);
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
    const { url: kid } = await resolveSigningVM(
      vcc.issuer,
      'assertionMethod',
      options.verificationMethodKey,
      options.resolver,
    );

    const header = { typ: disclosures.length > 0 ? 'vc+sd-jwt' : 'JWT', alg: 'ES256K', kid };
    const headerEncoded = Buffer.from(JSON.stringify(header), 'utf8').toString('base64url');
    const payloadEncoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');

    const cred = new JWTCredential(
      headerEncoded + '.' + payloadEncoded,
      vcMap as CredentialData,
      '',
      disclosures,
    );
    await cred.executeOptions(opts);
    return cred;
  }

  static async parse(rawJWT: string, opts: CredentialOptions = {}): Promise<JWTCredential> {
    let trimmed = rawJWT.trim();
    if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
      trimmed = trimmed.slice(1, -1);
    }

    let issuerJWT: string;
    let disclosures: string[] = [];
    let sdJwtEnvelope = false;
    if (isSDJWT(trimmed)) {
      const segments = trimmed.split('~');
      const tail = segments[segments.length - 1];
      if (tail && isJWT(tail)) throw new Error('key binding JWT is not supported');
      const parsed = parseSDJWT(trimmed);
      issuerJWT = parsed.baseJWT;
      disclosures = parsed.disclosures;
      sdJwtEnvelope = true;
    } else {
      if (!isJWTCredentialString(trimmed)) {
        throw new Error('invalid JWT or SD-JWT format');
      }
      issuerJWT = trimmed;
    }

    const parts = issuerJWT.split('.');
    const headerEncoded = parts[0];
    const payloadEncoded = parts[1];
    const signature = parts.length === 3 ? parts[2] : '';

    let payloadMap: JSONMap;
    let headerMap: JSONMap;
    try {
      headerMap = JSON.parse(Buffer.from(headerEncoded, 'base64url').toString('utf8'));
      payloadMap = JSON.parse(
        Buffer.from(payloadEncoded, 'base64url').toString('utf8'),
      );
    } catch (err) {
      throw new Error(`failed to decode payload: ${(err as Error).message}`);
    }
    sdJwtEnvelope ||= headerMap.typ === 'vc+sd-jwt';
    const vcData = payloadMap.vc;
    if (vcData === undefined) {
      throw new Error('vc claim not found in JWT payload');
    }
    if (!vcData || typeof vcData !== 'object' || Array.isArray(vcData)) {
      throw new Error('vc claim is not a valid JSON object');
    }
    let vcMap = vcData as JSONMap;

    if (sdJwtEnvelope) vcMap = reconstruct(vcMap, disclosures, true);

    const cred = new JWTCredential(
      headerEncoded + '.' + payloadEncoded,
      vcMap as CredentialData,
      signature,
      disclosures,
    );
    await cred.executeOptions(opts);
    return cred;
  }

  async addProof(priv: string, opts: CredentialOptions = {}): Promise<void> {
    const signer = new DefaultProvider(priv);
    await this.addProofByProvider(signer, opts);
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
    if (this.signature || this.disclosures.length > 0) {
      base = base + '.' + this.signature;
    }
    if (this.disclosures.length === 0) return base;
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

  getType(): 'JWT' {
    return 'JWT';
  }

  extractField(path: string): unknown {
    if (!this.payloadData) return null;
    return extractFieldFromMap(this.payloadData, path);
  }

  async addSelectiveDisclosures(selectivePaths: string[]): Promise<JWTCredential> {
    if (!selectivePaths || selectivePaths.length === 0) {
      throw new Error('selective paths cannot be empty');
    }
    const { payload, header } = this.extractPayload();

    const vcRaw = payload.vc;
    if (!vcRaw || typeof vcRaw !== 'object' || Array.isArray(vcRaw)) {
      throw new Error('vc claim not found in payload');
    }
    let vcMap = vcRaw as JSONMap;

    let allPaths = selectivePaths;
    if (this.disclosures.length > 0) {
      const original = reconstruct(vcMap, this.disclosures, true);
      const existing = findDisclosedPaths(original, vcMap);
      allPaths = unique([...existing, ...selectivePaths]);
      vcMap = original;
    }

    const result = buildDisclosures({
      vc: vcMap,
      selectivePaths: allPaths,
    });
    return this.buildCredential(payload, header, result.processedVC, result.disclosures);
  }

  // ---- internal ----

  private extractPayload(): { payload: JSONMap; header: string } {
    const parts = this.signingInput.split('.');
    if (parts.length !== 2) throw new Error('invalid signing input format');
    const payloadBytes = Buffer.from(parts[1], 'base64url');
    let payload: JSONMap;
    try {
      payload = JSON.parse(payloadBytes.toString('utf8'));
    } catch (err) {
      throw new Error(`failed to decode payload: ${(err as Error).message}`);
    }
    return { payload, header: parts[0] };
  }

  private buildCredential(
    payload: JSONMap,
    header: string,
    vc: JSONMap,
    disc: string[],
  ): JWTCredential {
    payload.vc = vc;
    const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const cred = new JWTCredential(header + '.' + encoded, vc as CredentialData, '', disc);
    return cred;
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

function unique(paths: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const p of paths) {
    if (!seen.has(p)) {
      seen.add(p);
      out.push(p);
    }
  }
  return out;
}

function findDisclosedPaths(original: JSONMap, processed: JSONMap): string[] {
  const paths: string[] = [];
  for (const key of Object.keys(original)) {
    if (key === '_sd' || key === '_sd_alg') continue;
    const origVal = original[key];
    const procVal = processed[key];
    if (procVal === undefined) continue;
    if (
      origVal &&
      typeof origVal === 'object' &&
      !Array.isArray(origVal) &&
      procVal &&
      typeof procVal === 'object' &&
      !Array.isArray(procVal)
    ) {
      paths.push(...compareObjects(origVal as JSONMap, procVal as JSONMap, key));
    }
  }
  return paths;
}

function compareObjects(orig: JSONMap, proc: JSONMap, prefix: string): string[] {
  const out: string[] = [];
  for (const [key, origVal] of Object.entries(orig)) {
    if (key === '_sd' || key === '_sd_alg') continue;
    const procVal = proc[key];
    if (procVal === undefined) {
      out.push(`${prefix}.${key}`);
      continue;
    }
    if (
      origVal &&
      typeof origVal === 'object' &&
      !Array.isArray(origVal) &&
      procVal &&
      typeof procVal === 'object' &&
      !Array.isArray(procVal)
    ) {
      out.push(...compareObjects(origVal as JSONMap, procVal as JSONMap, `${prefix}.${key}`));
    }
    if (Array.isArray(origVal) && Array.isArray(procVal)) {
      out.push(...compareArrays(origVal, procVal, `${prefix}.${key}`));
    }
  }
  return out;
}

function compareArrays(orig: unknown[], proc: unknown[], prefix: string): string[] {
  const out: string[] = [];
  const maxLen = Math.max(orig.length, proc.length);
  for (let i = 0; i < maxLen; i++) {
    if (i >= proc.length) {
      out.push(`${prefix}[${i}]`);
      continue;
    }
    if (i >= orig.length) {
      out.push(`${prefix}[${i}]`);
      continue;
    }
    const procElem = proc[i];
    if (
      procElem &&
      typeof procElem === 'object' &&
      !Array.isArray(procElem) &&
      '...' in (procElem as JSONMap)
    ) {
      out.push(`${prefix}[${i}]`);
      continue;
    }
    const origElem = orig[i];
    if (
      origElem &&
      typeof origElem === 'object' &&
      !Array.isArray(origElem) &&
      procElem &&
      typeof procElem === 'object' &&
      !Array.isArray(procElem)
    ) {
      out.push(...compareObjects(origElem as JSONMap, procElem as JSONMap, `${prefix}[${i}]`));
    }
  }
  return out;
}
