import { buildDisclosures } from '../common/sdjwt';
import { hasOwn, type JSONMap } from '../common/util/json';
import { neverDisclosable, TypDCSDJWT } from './errors';
import { Credential } from './credential';
import { encodeJWKFromP256Uncompressed, signCompactJWS, verifyCompactJWS } from './jws-compact';
import type { SigningKey } from './issuerkey';
import { checkAkaVCTs } from './aka';
import { wellFormed } from './typemeta';

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
  minDigests?: number;
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

export async function issue(req: IssueRequest, key: SigningKey): Promise<Credential> {
  if (!req.vct) throw new Error('VCT is required');
  if ((req.minDigests ?? 0) > 0 && !(req.disclose && req.disclose.length)) {
    throw new Error('MinDigests requires at least one Disclose path');
  }
  for (const [claim, field] of Object.entries(owned)) {
    if (!req.claims || !hasOwn(req.claims, claim)) continue;
    if (claim === 'iss' || claim === 'vct') {
      throw new Error(`claims holds ${claim}, which only IssueRequest.${field} may set`);
    }
    if (req[field] !== undefined) {
      throw new Error(`claims holds ${claim} and IssueRequest.${field} is set; give it in one place`);
    }
  }
  refuseReserved(req.claims);
  if (req.claims) {
    if (hasOwn(req.claims, 'aka_vcts')) checkAkaVCTs(req.claims.aka_vcts, req.vct);
    if (hasOwn(req.claims, 'vct#integrity')) {
      const v = req.claims['vct#integrity'];
      if (typeof v !== 'string' || !wellFormed(v)) {
        throw new Error('claims vct#integrity is not integrity metadata');
      }
    }
  }
  for (const p of req.disclose ?? []) {
    const first = p[0];
    if (typeof first === 'string' && neverDisclosable.has(first)) {
      throw new Error(`claim ${first} MUST NOT be concealed`);
    }
  }

  const concealable: JSONMap = { ...(req.claims ?? {}) };
  if (req.issuedAt) concealable.iat = Math.floor(req.issuedAt.getTime() / 1000);

  const selectivePathSegments = [...(req.disclose ?? [])]
    .sort((a, b) => b.length - a.length)
    .map((p) => p.filter((seg): seg is string | number => seg !== null));
  const { processedVC, disclosures } = buildDisclosures({
    vc: concealable,
    selectivePathSegments,
    shuffle: false,
    minDigests: req.minDigests,
  });

  const payload: JSONMap = { ...processedVC };
  if (req.issuer) payload.iss = req.issuer;
  payload.vct = req.vct;
  if (req.notBefore) payload.nbf = Math.floor(req.notBefore.getTime() / 1000);
  if (req.expiry) payload.exp = Math.floor(req.expiry.getTime() / 1000);
  if (req.holderKey) payload.cnf = { jwk: encodeJWKFromP256Uncompressed(req.holderKey, req.holderKeyAlg ?? 'ES256') };
  if (req.status) {
    if (req.status.idx < 0 || !req.status.uri) throw new Error('status ref is invalid');
    payload.status = { status_list: { idx: req.status.idx, uri: req.status.uri } };
  }
  if (payload.cnf && !payload.iss && !payload.sub) {
    throw new Error('a credential with cnf needs iss or sub');
  }

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
