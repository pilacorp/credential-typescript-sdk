import { reconstruct } from '../common/sdjwt';
import type { JSONMap } from '../common/util/json';
import { Credential } from './credential';
import { Code, DigitalCredentialError, neverDisclosable, PolicyError, TypDCSDJWT, TypKBJWT } from './errors';
import { peekHeader, verifyCompactJWS } from './jws-compact';
import { ErrIssuerNotSupported, ErrNoUsableKey, selectKey, type Resolver } from './issuerkey';
import { sdHash, splitSDJWT } from './split';
import { ErrIndexOutOfBounds, refFromStatus, type Checker, type Ref } from './statuslist';
import * as typemeta from './typemeta';
import { wellFormed } from './typemeta';

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

export async function verifyCredential(
  c: Credential,
  resolver: Resolver,
  opts: VerifyOptions = {},
): Promise<Result> {
  if (opts.status && opts.skipStatus) throw new PolicyError('WithStatus and WithoutStatusCheck are both passed');
  const algs = opts.allowedAlgs?.length ? opts.allowedAlgs : ['ES256'];
  const { issuerJWT, disclosures, kbJWT } = splitSDJWT(c.compact);
  const header = peekHeader(issuerJWT);
  if (header.typ !== TypDCSDJWT) {
    throw new DigitalCredentialError(Code.TypInvalid, `typ ${JSON.stringify(header.typ)} is not ${TypDCSDJWT}`);
  }
  if (header.alg && !algs.includes(String(header.alg))) {
    throw new DigitalCredentialError(Code.AlgNotAllowed, `alg ${String(header.alg)} is not allowed`);
  }
  const payload = JSON.parse(Buffer.from(issuerJWT.split('.')[1], 'base64url').toString('utf8')) as JSONMap;
  const iss = typeof payload.iss === 'string' ? payload.iss : '';
  if (opts.acceptedIssuers && !opts.acceptedIssuers.includes(iss)) {
    throw new DigitalCredentialError(Code.IssuerNotAccepted, 'iss is not an issuer in WithAcceptedIssuers');
  }
  let keys;
  try {
    keys = await resolver.keys(iss);
  } catch (err) {
    const cause = (err as { cause?: unknown }).cause;
    if (cause === ErrIssuerNotSupported || (err as Error).message.includes('not supported')) {
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
  } catch {
    throw new DigitalCredentialError(Code.SignatureInvalid, 'Issuer-signed JWT signature invalid');
  }

  let claims: JSONMap;
  try {
    claims = reconstruct(payload, disclosures, true);
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

  const now = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  const skew = opts.clockSkewSeconds ?? 60;
  if (typeof claims.exp === 'number' && now >= claims.exp + skew) {
    throw new DigitalCredentialError(Code.Expired, 'credential is expired');
  }
  if (typeof claims.nbf === 'number' && now < claims.nbf - skew) {
    throw new DigitalCredentialError(Code.NotYetValid, 'credential is not yet valid');
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
    if (!Array.isArray(claims.aka_vcts) || claims.aka_vcts.some((x) => typeof x !== 'string')) {
      throw new DigitalCredentialError(Code.Malformed, 'aka_vcts is not an array of strings');
    }
    akaVcts = claims.aka_vcts as string[];
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
      const { p256FromJWK } = await import('./jws-compact');
      let kbPayload: Record<string, unknown>;
      try {
        kbPayload = verifyCompactJWS(kbJWT, p256FromJWK(cnf.jwk), algs);
      } catch (err) {
        throw new DigitalCredentialError(Code.KBInvalid, (err as Error).message, err);
      }
      const kbHeader = peekHeader(kbJWT);
      if (kbHeader.typ !== TypKBJWT) {
        throw new DigitalCredentialError(Code.KBInvalid, 'KB JWT typ must be kb+jwt');
      }
      const presented = c.compact.endsWith(kbJWT) ? c.compact.slice(0, -kbJWT.length) : `${issuerJWT}~`;
      const expectedHash = sdHash(presented);
      if (kbPayload.sd_hash !== expectedHash) {
        throw new DigitalCredentialError(Code.KBSDHashMismatch, 'sd_hash mismatch');
      }
      if (opts.audience && kbPayload.aud !== opts.audience) {
        throw new DigitalCredentialError(Code.KBAudienceMismatch, 'KB aud mismatch');
      }
      if (opts.nonce && kbPayload.nonce !== opts.nonce) {
        throw new DigitalCredentialError(Code.KBNonceMismatch, 'KB nonce mismatch');
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
      m.validateClaims(claims);
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
    const types = [vct, ...(akaVcts ?? []), ...(res.typeMetadata?.chain ?? [])];
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
  return !(name in issued) && name in reconstructed;
}
