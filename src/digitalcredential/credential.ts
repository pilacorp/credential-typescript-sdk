import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '../common/crypto/hex';
import { DigitalCredentialError, Code } from './errors';
import { splitSDJWT } from './split';
import type { PresentRequest } from './present';
import type { VerifyOptions, Result } from './verify';
import type { Resolver } from './issuerkey';

export class Credential {
  constructor(readonly compact: string) {}

  serialize(): string {
    return this.compact;
  }

  hash(): string {
    if (!this.compact) throw new Error('Hash of a nil or zero Credential');
    const jwt = this.compact.split('~')[0];
    return bytesToHex(sha256(Buffer.from(jwt, 'utf8')));
  }

  async present(req: PresentRequest): Promise<Credential> {
    const { presentCredential } = await import('./present');
    return presentCredential(this, req);
  }

  async verify(resolver: Resolver, opts: VerifyOptions = {}): Promise<Result> {
    const { verifyCredential } = await import('./verify');
    return verifyCredential(this, resolver, opts);
  }
}

export function parse(compact: string): Credential {
  try {
    splitSDJWT(compact);
  } catch (err) {
    if (err instanceof DigitalCredentialError) throw err;
    throw new DigitalCredentialError(Code.Malformed, (err as Error).message, err);
  }
  return new Credential(compact);
}
