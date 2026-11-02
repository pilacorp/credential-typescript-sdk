import { buildDisclosures } from '../common/sdjwt';
import type { JSONMap } from '../common/util/json';
import { neverDisclosable, TypDCSDJWT } from './errors';
import { Credential } from './credential';
import { encodeJWKFromP256Uncompressed, signCompactJWS } from './jws-compact';
import type { SigningKey } from './issuerkey';

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
  status?: StatusRef;
  claims?: Record<string, unknown>;
  disclose?: Path[];
  minDigests?: number;
}

export async function issue(req: IssueRequest, key: SigningKey): Promise<Credential> {
  if (!req.vct) throw new Error('VCT is required');
  if ((req.minDigests ?? 0) > 0 && !(req.disclose && req.disclose.length)) {
    throw new Error('MinDigests requires at least one Disclose path');
  }
  for (const p of req.disclose ?? []) {
    const first = p[0];
    if (typeof first === 'string' && neverDisclosable.has(first)) {
      throw new Error(`claim ${first} MUST NOT be concealed`);
    }
  }

  const concealable: JSONMap = { ...(req.claims ?? {}) };
  if (req.issuedAt) concealable.iat = Math.floor(req.issuedAt.getTime() / 1000);

  const paths = (req.disclose ?? []).map((p) => p.filter((seg) => typeof seg === 'string').join('.'));
  const { processedVC, disclosures } = buildDisclosures({
    vc: concealable,
    selectivePaths: paths,
    shuffle: false,
  });

  const payload: JSONMap = { ...processedVC };
  if (req.issuer) payload.iss = req.issuer;
  payload.vct = req.vct;
  if (req.notBefore) payload.nbf = Math.floor(req.notBefore.getTime() / 1000);
  if (req.expiry) payload.exp = Math.floor(req.expiry.getTime() / 1000);
  if (req.holderKey) payload.cnf = { jwk: encodeJWKFromP256Uncompressed(req.holderKey) };
  if (req.status) {
    if (req.status.idx < 0 || !req.status.uri) throw new Error('status ref is invalid');
    payload.status = { status_list: { idx: req.status.idx, uri: req.status.uri } };
  }
  if (payload.cnf && !payload.iss && !payload.sub) {
    throw new Error('a credential with cnf needs iss or sub');
  }

  const header: Record<string, unknown> = { alg: 'ES256', typ: TypDCSDJWT };
  if (key.kid) header.kid = key.kid;
  const issuerJWT = await signCompactJWS(header, payload, key.signer);
  let compact = issuerJWT + '~';
  for (const d of disclosures) compact += d + '~';
  return new Credential(compact);
}
