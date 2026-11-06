import { reconstruct } from '../common/sdjwt';
import type { JSONMap } from '../common/util/json';
import { decodeDisclosures } from '../common/sdjwt';
import type { SignerProvider } from '../common/signer/signer';
import { Credential } from './credential';
import { TypKBJWT } from './errors';
import { p256FromJWK, signCompactJWS } from './jws-compact';
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
  const payload = JSON.parse(Buffer.from(issuerJWT.split('.')[1], 'base64url').toString('utf8')) as JSONMap;
  const names = new Set(
    (req.reveal ?? []).map((p) => (typeof p[0] === 'string' ? p[0] : '')).filter(Boolean),
  );
  const selected = names.size
    ? decodeDisclosures(disclosures)
        .filter((d) => names.has(d.fieldName))
        .map((d) => d.disclosure)
    : [];
  let compact = issuerJWT + '~';
  for (const d of selected) compact += d + '~';

  if (req.keyBinding) {
    reconstruct(payload, disclosures, true);
    const cnf = payload.cnf as { jwk?: { kty?: string; crv?: string; x?: string; y?: string } } | undefined;
    if (!cnf?.jwk) throw new Error('credential has no cnf.jwk for Key Binding');
    p256FromJWK(cnf.jwk);
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
    const kbToken = await signCompactJWS({ alg: 'ES256', typ: TypKBJWT }, kbPayload, kb.signer);
    compact += kbToken;
  }
  return new Credential(compact);
}
