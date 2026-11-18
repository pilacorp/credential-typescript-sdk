import { anyDisclosed, isArrayPlaceholder, parseDisclosures, reconstructIssued } from '../common/sdjwt';
import { hasOwn, type JSONMap } from '../common/util/json';
import { Credential } from './credential';
import { Code, DigitalCredentialError, neverDisclosable, PolicyError, TypDCSDJWT, TypKBJWT } from './errors';
import { decodeJSONSegment, isNumericDate, JSONDepthError, isUnsupportedHeader, peekHeader, typIs, verifyCompactJWS } from './jws-compact';
import { CnfError, cnfKey } from './cnf';
import { ErrIssuerNotSupported, ErrNoUsableKey, selectKey, type Resolver } from './issuerkey';
import { sdHash, splitSDJWT } from './split';
import { ErrIndexOutOfBounds, refFromStatus, type Checker, type Ref } from './statuslist';
import * as typemeta from './typemeta';
import { wellFormed } from './typemeta';
import { checkAkaVCTs } from './aka';

export { checkAkaVCTs };

export interface StatusChecker {
  status(ref: Ref, iss: string, signal?: AbortSignal): Promise<number>;
}

export interface VerifyOptions {
  audience?: string;
  nonce?: string;
  now?: Date;
  clockSkewSeconds?: number;
  requireKeyBinding?: boolean;
  ignoreUncheckedKBJWT?: boolean;
  credentialAudience?: string;
  status?: StatusChecker | Checker;
  skipStatus?: boolean;
  acceptedStatus?: number[];
  acceptedIssuers?: string[];
  acceptedVCTs?: string[];
  types?: typemeta.Resolver;
  typesOptional?: boolean;
  allowedAlgs?: string[];
  rejectFutureIAT?: boolean;
  /**
   * Asked about iat after the checks above; undefined when the credential
   * shows none. Throwing refuses the credential as IAT_CHECK_FAILED. An iat
   * outside the dates a Date holds (±8.64e12 s) is IAT_CHECK_FAILED without
   * a call.
   */
  iatCheck?: (iat: Date | undefined) => void | Promise<void>;
  maxKBAgeSeconds?: number;
  extendedVCTMatch?: boolean;
}

export interface Result {
  issuer?: string;
  vct?: string;
  akaVcts?: string[];
  claims: Record<string, unknown>;
  keyBound: boolean;
  status?: number;
  statusSkipped?: boolean;
  typeMetadata?: typemeta.Metadata;
  typeMetadataSkipped?: unknown;
}

// Follows cause, and the errors of an AggregateError, as Go's errors.Is
// follows Unwrap() error and Unwrap() []error.
function errorIs(err: unknown, target: unknown, depth = 0): boolean {
  for (let e = err, i = 0; e !== undefined && e !== null && i < 16; i++) {
    if (e === target) return true;
    const errors = (e as { errors?: unknown }).errors;
    if (depth < 4 && Array.isArray(errors) && errors.slice(0, 16).some((x) => errorIs(x, target, depth + 1))) {
      return true;
    }
    e = (e as { cause?: unknown }).cause;
  }
  return false;
}

const maxDateSeconds = 8.64e12;

function dropUndisclosedElements(v: unknown): unknown {
  if (Array.isArray(v)) {
    return v
      .filter((e) => !isArrayPlaceholder(e))
      .map(dropUndisclosedElements);
  }
  if (v && typeof v === 'object') {
    for (const k of Object.keys(v)) (v as JSONMap)[k] = dropUndisclosedElements((v as JSONMap)[k]);
  }
  return v;
}

export async function verifyCredential(
  c: Credential,
  resolver: Resolver,
  opts: VerifyOptions = {},
): Promise<Result> {
  if (opts.status && opts.skipStatus) throw new PolicyError('WithStatus and WithoutStatusCheck are both passed');
  if (opts.extendedVCTMatch && (!opts.acceptedVCTs || !opts.types)) {
    throw new PolicyError(
      'WithExtendedVCTMatch needs WithAcceptedVCTs, the types it matches, and WithTypeMetadata or WithOptionalTypeMetadata, the extends chain it matches them on',
    );
  }
  const skew = opts.clockSkewSeconds ?? 60;
  if (!(skew >= 0) || !Number.isFinite(skew)) {
    throw new PolicyError(`clockSkewSeconds ${skew} is negative or not a number`);
  }
  const maxAge = opts.maxKBAgeSeconds ?? 300;
  if (!(maxAge > 0) || !Number.isFinite(maxAge)) throw new PolicyError(`maxKBAgeSeconds ${maxAge} is not positive`);
  const algs = opts.allowedAlgs?.length ? opts.allowedAlgs : ['ES256', 'ES256K'];
  const { issuerJWT, disclosures, kbJWT } = splitSDJWT(c.compact);
  let header: Record<string, unknown>;
  try {
    header = peekHeader(issuerJWT);
  } catch (err) {
    if (isUnsupportedHeader(err)) {
      throw new DigitalCredentialError(
        Code.Malformed,
        'the Issuer-signed JWT header uses crit or b64, which this SDK does not implement',
        err,
      );
    }
    throw new DigitalCredentialError(Code.Malformed, (err as Error).message, err);
  }
  if (!typIs(header.typ, TypDCSDJWT)) {
    throw new DigitalCredentialError(Code.TypInvalid, `typ ${JSON.stringify(header.typ)} is not ${TypDCSDJWT}`);
  }
  if (header.alg && !algs.includes(String(header.alg))) {
    throw new DigitalCredentialError(Code.AlgNotAllowed, `alg ${String(header.alg)} is not allowed`);
  }
  let payload: JSONMap;
  try {
    payload = decodeJSONSegment(issuerJWT.split('.')[1], 'Issuer-signed JWT payload', false);
  } catch (err) {
    throw new DigitalCredentialError(Code.Malformed, (err as Error).message, err);
  }
  if (payload.iss !== undefined && typeof payload.iss !== 'string') {
    throw new DigitalCredentialError(Code.Malformed, 'iss is not a string');
  }
  for (const k of ['iat', 'nbf', 'exp'] as const) {
    const v = payload[k];
    if (v !== undefined && (typeof v !== 'number' || !Number.isFinite(v))) {
      throw new DigitalCredentialError(Code.Malformed, `${k} is not a NumericDate`);
    }
  }
  const iss = typeof payload.iss === 'string' ? payload.iss : '';
  if (opts.acceptedIssuers && !opts.acceptedIssuers.includes(iss)) {
    throw new DigitalCredentialError(Code.IssuerNotAccepted, 'iss is not an issuer in WithAcceptedIssuers');
  }
  let keys;
  try {
    keys = await resolver.keys(iss);
  } catch (err) {
    if (errorIs(err, ErrIssuerNotSupported)) {
      throw new DigitalCredentialError(Code.IssuerNotSupported, (err as Error).message, err);
    }
    if (errorIs(err, ErrNoUsableKey)) {
      throw new DigitalCredentialError(Code.IssuerKeyNotFound, (err as Error).message, err);
    }
    throw new DigitalCredentialError(Code.IssuerKeyUnavailable, (err as Error).message, err);
  }
  let pub;
  try {
    if (header.kid !== undefined && (typeof header.kid !== 'string' || header.kid === '')) {
      throw new Error('kid is not a non-empty string');
    }
    pub = selectKey(keys, header.kid as string | undefined);
  } catch (err) {
    throw new DigitalCredentialError(Code.IssuerKeyNotFound, (err as Error).message, err);
  }
  try {
    verifyCompactJWS(issuerJWT, pub.publicKey, algs);
  } catch (err) {
    if (isUnsupportedHeader(err)) {
      throw new DigitalCredentialError(
        Code.Malformed,
        'the Issuer-signed JWT header uses crit or b64, which this SDK does not implement',
        err,
      );
    }
    // Raised only once the signature has passed.
    if (err instanceof JSONDepthError) throw new DigitalCredentialError(Code.Malformed, err.message, err);
    throw new DigitalCredentialError(Code.SignatureInvalid, 'Issuer-signed JWT signature invalid');
  }

  if ('_sd_alg' in payload && payload._sd_alg !== 'sha-256') {
    throw new DigitalCredentialError(Code.Malformed, '_sd_alg must be "sha-256"');
  }
  try {
    for (const d of parseDisclosures(disclosures)) {
      if (d.fieldName === '_sd' || d.fieldName === '...' || d.fieldName === '_sd_alg') {
        throw new DigitalCredentialError(
          Code.DisclosureInvalid,
          `disclosure claim name ${JSON.stringify(d.fieldName)} is reserved`,
        );
      }
    }
  } catch (err) {
    if (err instanceof DigitalCredentialError) throw err;
    throw new DigitalCredentialError(Code.DisclosureInvalid, (err as Error).message, err);
  }

  let reconstructed: JSONMap;
  let issued;
  try {
    ({ claims: reconstructed, issued } = reconstructIssued(payload, disclosures, true, true));
  } catch (err) {
    throw new DigitalCredentialError(Code.DisclosureInvalid, (err as Error).message, err);
  }
  const claims = dropUndisclosedElements(reconstructed) as JSONMap;
  // Read on how each value was issued, so a decoy digest inside one of these
  // claims is not taken for a Disclosure.
  for (const name of neverDisclosable) {
    if (issued.fields && hasOwn(issued.fields, name) && anyDisclosed(issued.fields[name])) {
      throw new DigitalCredentialError(
        Code.DisclosureInvalid,
        `claim ${JSON.stringify(name)}, or a sub-claim of it, came in a Disclosure, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids`,
      );
    }
  }

  // Not rounded: a NumericDate may carry a fraction (RFC 7519 §2).
  const now = (opts.now ?? new Date()).getTime() / 1000;
  // Read on the claims as disclosed: iat may come in a Disclosure. A value
  // that is not a NumericDate is malformed, never read as an absent claim.
  const date = (name: 'exp' | 'nbf' | 'iat'): number | undefined => {
    if (!hasOwn(claims, name)) return undefined;
    const v = claims[name];
    if (!isNumericDate(v)) throw new DigitalCredentialError(Code.Malformed, `${name} is not a NumericDate`);
    return v;
  };
  const exp = date('exp');
  if (exp !== undefined && now >= exp + skew) {
    throw new DigitalCredentialError(Code.Expired, 'credential is expired');
  }
  const nbf = date('nbf');
  if (nbf !== undefined && now < nbf - skew) {
    throw new DigitalCredentialError(Code.NotYetValid, 'credential is not yet valid');
  }
  const iatClaim = date('iat');
  if (iatClaim !== undefined && opts.rejectFutureIAT && iatClaim > now + skew) {
    throw new DigitalCredentialError(Code.NotYetValid, 'credential iat is in the future');
  }
  if (opts.iatCheck) {
    // A Date holds ±8.64e15 ms; past that the function would get an Invalid
    // Date, which compares false with everything.
    if (iatClaim !== undefined && Math.abs(iatClaim) > maxDateSeconds) {
      throw new DigitalCredentialError(Code.IATCheckFailed, 'iat is outside the dates a Date holds, so iatCheck cannot be asked');
    }
    try {
      await opts.iatCheck(iatClaim === undefined ? undefined : new Date(iatClaim * 1000));
    } catch (err) {
      if (err instanceof DigitalCredentialError) throw err;
      throw new DigitalCredentialError(Code.IATCheckFailed, (err as Error).message, err);
    }
  }
  if (claims.aud !== undefined) {
    if (!opts.credentialAudience) {
      throw new DigitalCredentialError(Code.AudienceMismatch, 'credential has aud and WithCredentialAudience was not passed');
    }
    const aud = claims.aud;
    const ok = aud === opts.credentialAudience || (Array.isArray(aud) && aud.includes(opts.credentialAudience));
    if (!ok) throw new DigitalCredentialError(Code.AudienceMismatch, 'credential aud mismatch');
  }

  const vct = claims.vct;
  if (typeof vct !== 'string' || !vct) {
    throw new DigitalCredentialError(Code.Malformed, 'vct is absent or not a non-empty string');
  }
  let akaVcts: string[] | undefined;
  if (claims.aka_vcts !== undefined) {
    akaVcts = checkAkaVCTs(claims.aka_vcts, vct);
  }
  if (claims['vct#integrity'] !== undefined) {
    if (typeof claims['vct#integrity'] !== 'string' || !wellFormed(claims['vct#integrity'] as string)) {
      throw new DigitalCredentialError(Code.Malformed, 'vct#integrity is not integrity metadata');
    }
  }

  if (opts.acceptedVCTs && !opts.types) {
    const types = [vct, ...(akaVcts ?? [])];
    if (!types.some((t) => opts.acceptedVCTs!.includes(t))) {
      throw new DigitalCredentialError(Code.VCTNotAccepted, 'neither vct nor aka_vcts is a type in WithAcceptedVCTs');
    }
  }

  const hasCnf = hasOwn(payload, 'cnf');
  let keyBound = false;
  // The credential first: when its cnf gives no key, no presentation of it
  // passes, whatever the Holder sent.
  let holder: Uint8Array | undefined;
  if (hasCnf || opts.requireKeyBinding) {
    if (!hasCnf) {
      throw new DigitalCredentialError(
        Code.KBUnsupported,
        'Key Binding is required and the credential has no cnf claim, the key a Key Binding JWT is checked with',
      );
    }
    try {
      holder = cnfKey(payload.cnf);
    } catch (err) {
      const code = err instanceof CnfError && err.unsupported ? Code.KBUnsupported : Code.Malformed;
      throw new DigitalCredentialError(code, (err as Error).message, err);
    }
  }
  if (kbJWT) {
    if (!holder) {
      if (!opts.ignoreUncheckedKBJWT) {
        throw new DigitalCredentialError(Code.KBUnexpected, 'unexpected Key Binding JWT');
      }
    } else {
      let kbPayload: Record<string, unknown>;
      try {
        kbPayload = verifyCompactJWS(kbJWT, holder, algs);
      } catch (err) {
        if (isUnsupportedHeader(err)) {
          throw new DigitalCredentialError(
            Code.Malformed,
            'the KB-JWT header uses crit or b64, which this SDK does not implement',
            err,
          );
        }
        throw new DigitalCredentialError(Code.KBInvalid, (err as Error).message, err);
      }
      const kbHeader = peekHeader(kbJWT);
      if (!typIs(kbHeader.typ, TypKBJWT)) {
        throw new DigitalCredentialError(Code.KBInvalid, 'KB JWT typ must be kb+jwt');
      }
      const presented = c.compact.endsWith(kbJWT) ? c.compact.slice(0, -kbJWT.length) : `${issuerJWT}~`;
      const expectedHash = sdHash(presented);
      if (kbPayload.sd_hash !== expectedHash) {
        throw new DigitalCredentialError(Code.KBSDHashMismatch, 'sd_hash mismatch');
      }
      if (!opts.audience || !opts.nonce) {
        throw new PolicyError('this credential has a Key Binding JWT: pass audience and nonce to check it');
      }
      if (kbPayload.aud !== opts.audience) {
        throw new DigitalCredentialError(Code.KBAudienceMismatch, 'KB aud mismatch');
      }
      if (kbPayload.nonce !== opts.nonce) {
        throw new DigitalCredentialError(Code.KBNonceMismatch, 'KB nonce mismatch');
      }
      for (const name of ['exp', 'nbf'] as const) {
        if (kbPayload[name] !== undefined && !isNumericDate(kbPayload[name])) {
          throw new DigitalCredentialError(Code.KBInvalid, `KB JWT ${name} is not a NumericDate`);
        }
      }
      const iat = kbPayload.iat;
      if (typeof iat !== 'number' || iat > now + skew || iat < now - maxAge - skew) {
        throw new DigitalCredentialError(Code.KBInvalid, 'KB JWT iat is missing or outside the accepted window');
      }
      if (typeof kbPayload.exp === 'number' && now >= kbPayload.exp + skew) {
        throw new DigitalCredentialError(Code.KBInvalid, 'KB JWT is expired');
      }
      if (typeof kbPayload.nbf === 'number' && now < kbPayload.nbf - skew) {
        throw new DigitalCredentialError(Code.KBInvalid, 'KB JWT is not yet valid');
      }
      keyBound = true;
    }
  } else if (holder) {
    throw new DigitalCredentialError(Code.KBMissing, 'Key Binding JWT is required');
  }

  const res: Result = {
    issuer: typeof claims.iss === 'string' ? claims.iss : undefined,
    vct,
    akaVcts,
    claims,
    keyBound,
  };

  if (opts.types) {
    const integrityVal = typeof claims['vct#integrity'] === 'string' ? (claims['vct#integrity'] as string) : '';
    try {
      if (claims['vct#integrity'] === '') {
        throw Object.assign(
          new Error('vct#integrity is present and empty, so no hash can check the Type Metadata document'),
          { cause: typemeta.ErrInvalid },
        );
      }
      const m = await typemeta.load(opts.types, { vct, integrity: integrityVal || undefined });
      m.validateClaims(reconstructed, { issued });
      res.typeMetadata = m;
    } catch (err) {
      const cause = (err as { cause?: unknown }).cause;
      if (opts.typesOptional && cause !== typemeta.ErrClaims && cause !== typemeta.ErrCycle && cause !== typemeta.ErrViolated) {
        res.typeMetadataSkipped = err;
      } else if (cause === typemeta.ErrNotFound) {
        throw new DigitalCredentialError(Code.TypeMetadataNotFound, (err as Error).message, err);
      } else if (cause === typemeta.ErrViolated) {
        throw new DigitalCredentialError(Code.TypeMetadataViolated, (err as Error).message, err);
      } else if (cause === typemeta.ErrInvalid || cause === typemeta.ErrClaims || cause === typemeta.ErrCycle) {
        throw new DigitalCredentialError(Code.TypeMetadataInvalid, (err as Error).message, err);
      } else if (!opts.typesOptional) {
        throw new DigitalCredentialError(Code.TypeMetadataUnavailable, (err as Error).message, err);
      } else {
        res.typeMetadataSkipped = err;
      }
    }
  }

  if (opts.acceptedVCTs && opts.types) {
    const chain = opts.extendedVCTMatch ? (res.typeMetadata?.chain ?? []) : [];
    const types = [vct, ...(akaVcts ?? []), ...chain];
    if (!types.some((t) => opts.acceptedVCTs!.includes(t))) {
      throw new DigitalCredentialError(Code.VCTNotAccepted, 'neither vct nor aka_vcts is a type in WithAcceptedVCTs');
    }
  }

  let st: Ref | undefined;
  try {
    st = claims.status !== undefined ? refFromStatus(claims.status) : undefined;
    if (claims.status !== undefined && !st && !opts.skipStatus) {
      if (!('status_list' in (claims.status as object))) {
        throw new DigitalCredentialError(
          Code.StatusUnavailable,
          'status has no status_list, the one mechanism this SDK checks',
        );
      }
    }
  } catch (err) {
    if (err instanceof DigitalCredentialError) throw err;
    const cause = (err as { cause?: unknown }).cause;
    if (cause === ErrIndexOutOfBounds) {
      throw new DigitalCredentialError(Code.Malformed, (err as Error).message, err);
    }
    throw new DigitalCredentialError(Code.Malformed, (err as Error).message, err);
  }

  if (claims.status !== undefined && opts.skipStatus) {
    res.statusSkipped = true;
    return res;
  }
  if (st) {
    if (!opts.status) {
      throw new PolicyError('the credential has a status_list: pass status or skipStatus');
    }
    let v: number;
    try {
      v = await opts.status.status(st, iss);
    } catch (err) {
      const cause = (err as { cause?: unknown }).cause;
      if (cause === ErrIndexOutOfBounds || (err as Error).message.includes('index out of bounds')) {
        throw new DigitalCredentialError(Code.Malformed, (err as Error).message, err);
      }
      throw new DigitalCredentialError(Code.StatusUnavailable, (err as Error).message, err);
    }
    const accepted = opts.acceptedStatus ?? [0];
    if (!accepted.includes(v)) {
      if (v === 0x01) throw new DigitalCredentialError(Code.Revoked, 'the issuer revoked the credential (status 0x01)');
      if (v === 0x02) throw new DigitalCredentialError(Code.Suspended, 'the issuer suspended the credential (status 0x02)');
      throw new DigitalCredentialError(Code.StatusNotAccepted, `status 0x${v.toString(16)} is not in WithAcceptedStatus`);
    }
    res.status = v;
  }
  return res;
}
