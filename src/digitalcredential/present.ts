import { reconstruct } from '../common/sdjwt';
import { hasOwn, type JSONMap } from '../common/util/json';
import { decodeDisclosures, hashDisclosure } from '../common/sdjwt';
import type { SignerProvider } from '../common/signer/signer';
import { Credential } from './credential';
import { TypKBJWT } from './errors';
import { algForECJWK, decodeJSONSegment, p256FromJWK, signCompactJWS, verifyCompactJWS } from './jws-compact';
import { sdHash, splitSDJWT } from './split';
import type { Path } from './issue';

export interface KeyBinding {
  signer: SignerProvider;
  audience: string;
  nonce: string;
  issuedAt: Date;
  claims?: Record<string, unknown>;
}

export interface PresentRequest {
  reveal?: Path[];
  keyBinding?: KeyBinding;
}

export async function presentCredential(c: Credential, req: PresentRequest): Promise<Credential> {
  if (!c.compact) throw new Error('Present on a nil or zero Credential');
  const { issuerJWT, disclosures, kbJWT } = splitSDJWT(c.compact);
  if (kbJWT) throw new Error('Present takes an SD-JWT, not an SD-JWT+KB');
  const payload = decodeJSONSegment(issuerJWT.split('.')[1], 'Issuer-signed JWT payload') as JSONMap;
  const selected = selectDisclosures(payload, disclosures, req.reveal ?? []);
  let compact = issuerJWT + '~';
  for (const d of selected) compact += d + '~';

  if (req.keyBinding) {
    reconstruct(payload, disclosures, true);
    const cnf = payload.cnf as { jwk?: { kty?: string; crv?: string; x?: string; y?: string } } | undefined;
    if (!cnf?.jwk) throw new Error('credential has no cnf.jwk for Key Binding');
    const holderKey = p256FromJWK(cnf.jwk);
    const kbAlg = algForECJWK(cnf.jwk);
    const kb = req.keyBinding;
    if (!kb.audience || !kb.nonce) throw new Error('KeyBinding audience and nonce are required');
    const extra = { ...(kb.claims ?? {}) };
    for (const forbidden of ['iat', 'aud', 'nonce', 'sd_hash']) {
      if (forbidden in extra) throw new Error(`KeyBinding claims must not hold ${forbidden}`);
    }
    const kbPayload = {
      ...extra,
      iat: Math.floor(kb.issuedAt.getTime() / 1000),
      aud: kb.audience,
      nonce: kb.nonce,
      sd_hash: sdHash(compact),
    };
    const kbToken = await signCompactJWS({ alg: kbAlg, typ: TypKBJWT }, kbPayload, kb.signer);
    try {
      verifyCompactJWS(kbToken, holderKey, [kbAlg]);
    } catch (err) {
      throw Object.assign(
        new Error(`KeyBinding signer's signature does not verify as ${kbAlg} under the credential's cnf.jwk`),
        { cause: err },
      );
    }
    compact += kbToken;
  }
  return new Credential(compact);
}

function selectDisclosures(payload: JSONMap, disclosures: string[], reveal: Path[]): string[] {
  const alg = typeof payload._sd_alg === 'string' ? payload._sd_alg : 'sha-256';
  const decoded = decodeDisclosures(disclosures);
  const byDigest = new Map(decoded.map((d) => [hashDisclosure(alg, d.disclosure), d]));
  const picked = new Set<string>();
  const openDigest = (digest: unknown, path: Path): unknown => {
    const d = typeof digest === 'string' ? byDigest.get(digest) : undefined;
    if (!d) throw new Error(`reveal path ${JSON.stringify(path)} is not in the credential`);
    picked.add(d.disclosure);
    return d.value;
  };
  const notIn = (path: Path) => new Error(`reveal path ${JSON.stringify(path)} is not in the credential`);
  const walk = (node: unknown, path: Path, at: number): number => {
    if (at === path.length) return 1;
    const seg = path[at];
    if (typeof seg === 'string') {
      if (!node || typeof node !== 'object' || Array.isArray(node)) throw notIn(path);
      const obj = node as JSONMap;
      if (hasOwn(obj, seg)) return walk(obj[seg], path, at + 1);
      for (const h of Array.isArray(obj._sd) ? obj._sd : []) {
        const d = typeof h === 'string' ? byDigest.get(h) : undefined;
        if (d && d.fieldName === seg) {
          picked.add(d.disclosure);
          return walk(d.value, path, at + 1);
        }
      }
      return 0;
    }
    if (seg !== null && (!Number.isInteger(seg) || (seg as number) < 0)) throw notIn(path);
    if (!Array.isArray(node)) throw notIn(path);
    const elems: Array<() => unknown> = [];
    for (const el of node) {
      const concealed = el && typeof el === 'object' && !Array.isArray(el) && hasOwn(el as object, '...');
      if (!concealed) elems.push(() => el);
      else if (byDigest.has((el as JSONMap)['...'] as string)) {
        elems.push(() => openDigest((el as JSONMap)['...'], path));
      }
    }
    let n = 0;
    const picks = seg === null ? elems : elems.slice(seg as number, (seg as number) + 1);
    for (const open of picks) n += walk(open(), path, at + 1);
    return n;
  };
  for (const path of reveal) {
    if (path.length === 0 || walk(payload, path, 0) === 0) throw notIn(path);
  }
  return [...picked];
}
