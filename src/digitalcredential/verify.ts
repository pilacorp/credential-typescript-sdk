import { parseDisclosures, reconstruct } from '../common/sdjwt';
import { hasOwn, type JSONMap } from '../common/util/json';
import { Credential } from './credential';
import { Code, DigitalCredentialError, neverDisclosable, PolicyError, TypDCSDJWT, TypKBJWT } from './errors';
import { decodeJSONSegment, isUnsupportedHeader, peekHeader, p256FromJWK, typIs, verifyCompactJWS } from './jws-compact';
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
  iatCheck?: (iat: Date) => void | Promise<void>;
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

function dropUndisclosedElements(v: unknown): unknown {
  if (Array.isArray(v)) {
    return v
      .filter((e) => !(e && typeof e === 'object' && !Array.isArray(e) && Object.keys(e).length === 1 && hasOwn(e as object, '...')))
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
  if (header.crit !== undefined || header.b64 !== undefined) {
    throw new DigitalCredentialError(
      Code.Malformed,
      'the Issuer-signed JWT header uses crit or b64, which this SDK does not implement',
    );
  }
  let payload: JSONMap;
  try {
    payload = decodeJSONSegment(issuerJWT.split('.')[1], 'Issuer-signed JWT payload');
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
    const cause = (err as { cause?: unknown }).cause;
    if (cause === ErrIssuerNotSupported) {
      throw new DigitalCredentialError(Code.IssuerNotSupported, (err as Error).message, err);
    }
    if (cause === ErrNoUsableKey) {
      throw new DigitalCredentialError(Code.IssuerKeyNotFound, (err as Error).message, err);
    }
    throw new DigitalCredentialError(Code.IssuerKeyUnavailable, (err as Error).message, err);
  }
  let pub;
  try {
    pub = selectKey(keys, typeof header.kid === 'string' ? header.kid : undefined);
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
    throw new DigitalCredentialError(Code.SignatureInvalid, 'Issuer-signed JWT signature invalid');
  }

  if ('_sd_alg' in payload && payload._sd_alg !== 'sha-256') {
    throw new DigitalCredentialError(Code.Malformed, '_sd_alg must be "sha-256"');
  }
  try {
    for (const d of parseDisclosures(disclosures)) {
      if (d.fieldName === '_sd' || d.fieldName === '...') {
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

  let claims: JSONMap;
  try {
    claims = dropUndisclosedElements(reconstruct(payload, disclosures, true)) as JSONMap;
  } catch (err) {
    throw new DigitalCredentialError(Code.DisclosureInvalid, (err as Error).message, err);
  }
  for (const name of neverDisclosable) {
    if (claimCameFromDisclosure(payload, claims, name)) {
      throw new DigitalCredentialError(
        Code.DisclosureInvalid,
        `claim ${JSON.stringify(name)} came in a Disclosure, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids`,
      );
    }
  }
  if (claims.status !== undefined && JSON.stringify(payload.status) !== JSON.stringify(claims.status)) {
    throw new DigitalCredentialError(
      Code.DisclosureInvalid,
      'status or one of its sub-claims came in a Disclosure, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 forbids',
    );
  }

  const now = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  const skew = opts.clockSkewSeconds ?? 60;
  if (typeof claims.exp === 'number' && now >= claims.exp + skew) {
    throw new DigitalCredentialError(Code.Expired, 'credential is expired');
  }
  if (typeof claims.nbf === 'number' && now < claims.nbf - skew) {
    throw new DigitalCredentialError(Code.NotYetValid, 'credential is not yet valid');
  }
  if (typeof claims.iat === 'number') {
    if (opts.rejectFutureIAT && claims.iat > now + skew) {
      throw new DigitalCredentialError(Code.NotYetValid, 'credential iat is in the future');
    }
    if (opts.iatCheck) {
      try {
        await opts.iatCheck(new Date(claims.iat * 1000));
      } catch (err) {
        if (err instanceof DigitalCredentialError) throw err;
        throw new DigitalCredentialError(Code.IATCheckFailed, (err as Error).message, err);
      }
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

  const hasCnf = Boolean(payload.cnf);
  let keyBound = false;
  if (kbJWT) {
    if (!hasCnf && !opts.requireKeyBinding) {
      if (!opts.ignoreUncheckedKBJWT) {
        throw new DigitalCredentialError(Code.KBUnexpected, 'unexpected Key Binding JWT');
      }
    } else {
      const cnf = payload.cnf as { jwk?: { kty?: string; crv?: string; x?: string; y?: string } };
      if (!cnf?.jwk) throw new DigitalCredentialError(Code.KBUnsupported, 'no cnf.jwk to check Key Binding');
      let kbPayload: Record<string, unknown>;
      try {
        kbPayload = verifyCompactJWS(kbJWT, p256FromJWK(cnf.jwk), algs);
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
      const maxAge = opts.maxKBAgeSeconds ?? 300;
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
  } else if (hasCnf || opts.requireKeyBinding) {
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
      const m = await typemeta.load(opts.types, { vct, integrity: integrityVal || undefined });
      m.validateClaims(claims, { issued: payload });
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

function claimCameFromDisclosure(issued: JSONMap, reconstructed: JSONMap, name: string): boolean {
  return !Object.prototype.hasOwnProperty.call(issued, name) && Object.prototype.hasOwnProperty.call(reconstructed, name);
}
