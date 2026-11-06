import type { SignerProvider } from '../common/signer/signer';

export interface SigningKey {
  signer: SignerProvider;
  publicKey: Uint8Array;
  kid?: string;
}

export interface PublicKey {
  kid?: string;
  publicKey: Uint8Array;
}

export const ErrIssuerNotSupported = Object.assign(new Error('issuerkey: issuer not supported'), {
  name: 'IssuerKeyError',
});
export const ErrNoUsableKey = Object.assign(new Error('issuerkey: issuer published no usable key'), {
  name: 'IssuerKeyError',
});

export interface Resolver {
  keys(iss: string, signal?: AbortSignal): Promise<PublicKey[]>;
}

export class StaticResolver implements Resolver {
  constructor(private readonly iss: string, private readonly published: PublicKey[]) {}
  async keys(iss: string): Promise<PublicKey[]> {
    if (iss !== this.iss) {
      throw Object.assign(new Error('issuerkey: issuer not supported'), { cause: ErrIssuerNotSupported });
    }
    return this.published;
  }
}

export function selectKey(keys: PublicKey[], kid?: string): PublicKey {
  if (kid) {
    const hits = keys.filter((k) => k.kid === kid);
    if (hits.length !== 1) throw new Error('issuer key not found for kid');
    return hits[0];
  }
  if (keys.length !== 1) throw new Error('issuer key not found: no kid and not exactly one key');
  return keys[0];
}
