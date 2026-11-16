import { buildDisclosures } from '../common/sdjwt';
import { hasOwn, type JSONMap } from '../common/util/json';
import { neverDisclosable, TypDCSDJWT } from './errors';
import { Credential } from './credential';
import { checkJSONDepth, jsonForm, encodeJWKFromP256Uncompressed, isNumericDate, isValidDate, signCompactJWS, verifyCompactJWS } from './jws-compact';
import { CnfError, cnfKey } from './cnf';
import { refFromStatus, validateRef } from './statuslist';
import type { SigningKey } from './issuerkey';
import { checkAkaVCTs } from './aka';
import { checkIntegrity, wellFormed, type Metadata } from './typemeta';

export type Path = Array<string | number | null>;

export interface StatusRef {
  idx: number;
  uri: string;
}

export interface IssueRequest {
  issuer?: string;
  vct: string;
  issuedAt?: Date;
  notBefore?: Date;
  expiry?: Date;
  holderKey?: Uint8Array;
  holderKeyAlg?: 'ES256' | 'ES256K';
  status?: StatusRef;
  claims?: Record<string, unknown>;
  disclose?: Path[];
  /**
   * Pads every object and array of the concealable claims, and the top level,
   * with decoy digests up to this count: an integer in [0, 1000], and 0 when
   * disclose is empty. The claims that are never selectively disclosable
   * (iss, nbf, exp, cnf, vct, vct#integrity, aka_vcts, status) get no decoy.
   */
  minDigests?: number;
  /**
   * The Type Metadata of vct, made by typemeta.load. issue then checks the
   * claims against its claim metadata before concealing anything
   * (validateIssuance, SD-JWT VC draft 19 §5.6), and adds no decoy to any
   * array: §5.6 counts array elements as issued, and a decoy would move every
   * index after it.
   */
  typeMetadata?: Metadata;
}

const owned: Record<string, keyof IssueRequest> = {
  iss: 'issuer',
  vct: 'vct',
  iat: 'issuedAt',
  nbf: 'notBefore',
  exp: 'expiry',
  cnf: 'holderKey',
  status: 'status',
};

// A Verifier reads at most this many disclosures (split.ts).
const maxPaths = 1000;

/** Refuses a request Issue must not sign: what a Verifier reads as malformed, and what the request states twice. */
function check(req: IssueRequest, claims: JSONMap | undefined): void {
  if (!req.vct) throw new Error('VCT is required');
  const minDigests = req.minDigests ?? 0;
  if (!Number.isInteger(minDigests) || minDigests < 0 || minDigests > 1000) {
    throw new Error(`MinDigests ${minDigests} is not an integer in [0, 1000]`);
  }
  if (minDigests > 0 && !(req.disclose && req.disclose.length)) {
    throw new Error('MinDigests requires at least one Disclose path');
  }
  for (const [claim, field] of Object.entries(owned)) {
    if (!claims || !hasOwn(claims, claim)) continue;
    if (claim === 'iss' || claim === 'vct') {
      throw new Error(`claims holds ${claim}, which only IssueRequest.${field} may set`);
    }
    if (req[field] !== undefined) {
      throw new Error(`claims holds ${claim} and IssueRequest.${field} is set; give it in one place`);
    }
  }
  refuseReserved(claims);
  if (claims) {
    for (const name of ['iat', 'nbf', 'exp']) {
      const v = claims[name];
      if (hasOwn(claims, name) && !isNumericDate(v)) {
        throw new Error(`claims ${name} is not a NumericDate; give a number of seconds, or set the field`);
      }
    }
    if (hasOwn(claims, 'status')) {
      try {
        const ref = refFromStatus(claims.status);
        if (ref && ref.index >= 2 ** 63) throw new Error('status.status_list.idx is past every status list');
      } catch (err) {
        throw Object.assign(new Error(`claims ${(err as Error).message}; set status for a Status List entry`), {
          cause: err,
        });
      }
    }
    if (hasOwn(claims, 'aud')) {
      // RFC 7519 §4.1.3: aud is a string or an array of strings.
      const aud = claims.aud;
      if (typeof aud !== 'string' && !(Array.isArray(aud) && aud.every((a) => typeof a === 'string'))) {
        throw new Error('claims aud is not a string or an array of strings');
      }
    }
    if (hasOwn(claims, 'cnf')) {
      try {
        cnfKey(claims.cnf);
      } catch (err) {
        // A cnf this SDK does not bind to may be valid for another Verifier;
        // only one a Verifier reads as malformed is refused.
        if (!(err instanceof CnfError && err.unsupported)) {
          throw Object.assign(new Error(`claims ${(err as Error).message}; set holderKey for a cnf.jwk`), {
            cause: err,
          });
        }
      }
    }
    if (hasOwn(claims, 'aka_vcts')) checkAkaVCTs(claims.aka_vcts, req.vct);
    if (hasOwn(claims, 'vct#integrity')) {
      const v = claims['vct#integrity'];
      if (typeof v !== 'string' || !wellFormed(v)) {
        throw new Error('claims vct#integrity is not integrity metadata');
      }
    }
  }
  if ((req.disclose?.length ?? 0) > maxPaths) {
    throw new Error(`${req.disclose!.length} Disclose paths, at most ${maxPaths}`);
  }
  for (const p of req.disclose ?? []) {
    if (p.some((seg) => seg === null)) {
      throw new Error(`Disclose path ${JSON.stringify(p)} holds null; name each array element by its index`);
    }
    const first = p[0];
    if (typeof first === 'string' && neverDisclosable.has(first)) {
      throw new Error(`claim ${first} MUST NOT be concealed`);
    }
  }

  for (const field of ['issuedAt', 'notBefore', 'expiry'] as const) {
    const d = req[field];
    if (d !== undefined && !isValidDate(d)) {
      throw new Error(`${field} is not a valid Date`);
    }
  }
  if (req.status) {
    if (!Number.isSafeInteger(req.status.idx) || typeof req.status.uri !== 'string' || !req.status.uri) {
      throw new Error('status ref is invalid: idx is a non-negative integer and uri a URI');
    }
    validateRef({ uri: req.status.uri, index: req.status.idx });
  }
}

/**
 * The claims of the payload in two parts: those Issue may conceal or pad with
 * decoys, and those that are never selectively disclosable (SD-JWT VC draft
 * 19 §2.2.2.3), which stay apart so that minDigests writes no decoy into them.
 */
function prepare(req: IssueRequest, claims: JSONMap | undefined): { concealable: JSONMap; plain: JSONMap } {
  const concealable: JSONMap = { ...(claims ?? {}) };
  if (req.issuedAt) concealable.iat = Math.floor(req.issuedAt.getTime() / 1000);
  const plain: JSONMap = {};
  for (const name of neverDisclosable) {
    if (!hasOwn(concealable, name)) continue;
    plain[name] = concealable[name];
    delete concealable[name];
  }
  if (req.issuer) plain.iss = req.issuer;
  plain.vct = req.vct;
  if (req.notBefore) plain.nbf = Math.floor(req.notBefore.getTime() / 1000);
  if (req.expiry) plain.exp = Math.floor(req.expiry.getTime() / 1000);
  if (req.holderKey) {
    const holderAlg = req.holderKeyAlg ?? 'ES256';
    try {
      plain.cnf = { jwk: encodeJWKFromP256Uncompressed(req.holderKey, holderAlg) };
    } catch (err) {
      const curve = holderAlg === 'ES256K' ? 'secp256k1' : 'P-256';
      throw Object.assign(new Error(`holderKey is not a ${curve} public key; set holderKeyAlg to the curve of the key`), {
        cause: err,
      });
    }
  }
  if (req.status) {
    plain.status = { status_list: { idx: req.status.idx, uri: req.status.uri } };
  }
  return { concealable, plain };
}

/** Checks the claims to be signed, none concealed yet, against the Type Metadata of the request. */
function checkTypeMetadata(req: IssueRequest, typeMetadata: Metadata, claims: JSONMap): void {
  if (typeMetadata.vct !== req.vct) {
    throw new Error('typeMetadata is not the Type Metadata of vct made by typemeta.load');
  }
  const integrity = claims['vct#integrity'];
  if (typeof integrity === 'string') {
    try {
      checkIntegrity(typeMetadata.documents[0], integrity);
    } catch (err) {
      throw Object.assign(
        new Error('claims vct#integrity does not match the document typeMetadata was loaded from'),
        { cause: err },
      );
    }
  }
  typeMetadata.validateIssuance(claims, req.disclose ?? []);
}

export async function issue(req: IssueRequest, key: SigningKey): Promise<Credential> {
  // Claims are the first level of the payload, which no reader takes deeper than 64.
  const claims = req.claims ? jsonForm(req.claims, 'claims') : undefined;
  check(req, claims);
  const { concealable, plain } = prepare(req, claims);
  if (req.typeMetadata) checkTypeMetadata(req, req.typeMetadata, { ...concealable, ...plain });

  const selectivePathSegments = ([...(req.disclose ?? [])] as Array<Array<string | number>>).sort(
    (a, b) => b.length - a.length,
  );
  const { processedVC, disclosures } = buildDisclosures({
    vc: concealable,
    selectivePathSegments,
    shuffle: true,
    minDigests: req.minDigests ?? 0,
    noArrayDecoys: Boolean(req.typeMetadata),
  });

  const payload: JSONMap = { ...processedVC, ...plain };
  if (payload.cnf && !payload.iss && !payload.sub) {
    throw new Error('a credential with cnf needs iss or sub');
  }

  // A concealed array element or an _sd array adds one level to what the caller gave.
  checkJSONDepth(payload, 'claims, with the level that concealing a claim or minDigests adds');

  const alg = key.alg ?? 'ES256';
  const header: Record<string, unknown> = { alg, typ: TypDCSDJWT };
  if (key.kid) header.kid = key.kid;
  const issuerJWT = await signCompactJWS(header, payload, key.signer);
  try {
    verifyCompactJWS(issuerJWT, key.publicKey, [alg]);
  } catch (err) {
    throw Object.assign(new Error(`the signer's signature does not verify as ${alg} under SigningKey.publicKey`), {
      cause: err,
    });
  }
  let compact = issuerJWT + '~';
  for (const d of disclosures) compact += d + '~';
  return new Credential(compact);
}


const reserved = new Set(['_sd', '_sd_alg', '...']);

function refuseReserved(v: unknown): void {
  if (Array.isArray(v)) {
    v.forEach(refuseReserved);
    return;
  }
  if (!v || typeof v !== 'object') return;
  for (const [k, val] of Object.entries(v)) {
    if (reserved.has(k)) throw new Error(`claims holds ${k}, a name SD-JWT reserves`);
    refuseReserved(val);
  }
}
