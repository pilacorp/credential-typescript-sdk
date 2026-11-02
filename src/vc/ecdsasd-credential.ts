import { addECDSASDBaseProof, deriveECDSASD } from '../common/jsonmap/jsonmap';
import { P256Provider } from '../common/signer/p256-provider';
import type { SignerProvider } from '../common/signer/signer';
import { hexToBytes } from '../common/crypto/hex';
import { publicKeyHexFromVM, resolveSigningVM } from '../common/verification-method';
import { JSONCredential } from './json-credential';
import { getOptions } from './options';
import type { Credential, CredentialContents, CredentialOptions } from './types';

export function dotPathsToPointers(paths: string[]): string[] {
  return paths
    .filter(Boolean)
    .map((p) => {
      if (p.startsWith('/')) return p;
      return (
        '/' +
        p
          .split('.')
          .map((seg) => seg.replace(/~/g, '~0').replace(/\//g, '~1'))
          .join('/')
      );
    });
}

export class ECDSASDCredential {
  constructor(readonly base: JSONCredential) {}

  static async create(vcc: CredentialContents, opts: CredentialOptions = {}): Promise<ECDSASDCredential> {
    return new ECDSASDCredential(await JSONCredential.create(vcc, opts));
  }

  static async parse(rawJSON: Uint8Array | string, opts: CredentialOptions = {}): Promise<ECDSASDCredential> {
    return new ECDSASDCredential(await JSONCredential.parse(rawJSON, opts));
  }

  async addProofByProvider(
    signerProvider: SignerProvider,
    mandatoryPaths: string[],
    opts: CredentialOptions = {},
  ): Promise<void> {
    if (!signerProvider) throw new Error('signer provider cannot be nil');
    if (!(signerProvider instanceof P256Provider)) {
      throw new Error('unsupported key kind for ecdsa-sd-2023 credential');
    }
    await this.base.executeOptions(opts);
    const data = this.base.getInternalData();
    const issuer = data.issuer;
    if (typeof issuer !== 'string' || !issuer) throw new Error('issuer is missing or invalid');
    const options = getOptions(opts);
    const { vm, url: resolved } = await resolveSigningVM(
      issuer,
      'assertionMethod',
      options.verificationMethodKey,
      options.resolver,
    );
    const issuerPub = hexToBytes(publicKeyHexFromVM(vm));
    await addECDSASDBaseProof(
      data,
      signerProvider,
      resolved,
      'assertionMethod',
      dotPathsToPointers(mandatoryPaths),
      issuerPub,
    );
  }

  async derive(selectivePaths: string[]): Promise<JSONCredential> {
    const derived = await deriveECDSASD(this.base.getInternalData(), dotPathsToPointers(selectivePaths));
    return new JSONCredential(derived);
  }

  verify(opts?: CredentialOptions): Promise<void> {
    return this.base.verify(opts);
  }

  serialize(): Promise<unknown> {
    return this.base.serialize();
  }

  getContents(): Uint8Array {
    return this.base.getContents();
  }

  getType(): 'JSON' {
    return this.base.getType();
  }

  extractField(path: string): unknown {
    return this.base.extractField(path);
  }

  async hash(): Promise<string> {
    return this.base.hash();
  }
}

export type { Credential };
