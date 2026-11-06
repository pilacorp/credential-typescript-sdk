import { addECDSASDBaseProof, deriveECDSASD } from '../common/jsonmap/jsonmap';
import type { SignerProvider } from '../common/signer/signer';
import { hexToBytes } from '../common/crypto/hex';
import { publicKeyHexFromVM, vmKeyKind } from '../common/verification-method';
import { JSONCredential } from './json-credential';
import { refuseReplaceOnJSONLD, signingOptions } from './options';
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

export class ECDSASDCredential implements Credential {
  constructor(readonly base: JSONCredential) {}

  static async create(vcc: CredentialContents, opts: CredentialOptions = {}): Promise<ECDSASDCredential> {
    return new ECDSASDCredential(await JSONCredential.create(vcc, opts));
  }

  static async parse(rawJSON: Uint8Array | string, opts: CredentialOptions = {}): Promise<ECDSASDCredential> {
    return new ECDSASDCredential(await JSONCredential.parse(rawJSON, opts));
  }

  /**
   * Signs into an ecdsa-sd-2023 base proof. mandatoryPaths are always disclosed;
   * every other claim becomes selectively disclosable. The proof is bound to the
   * VM the options pin (or the default one), which must hold a P-256 key; the
   * gate is the VM's key kind, not the signer's class, so a callback-backed
   * P-256 signer works too.
   */
  async addProofByProvider(
    signerProvider: SignerProvider,
    mandatoryPaths: string[],
    opts: CredentialOptions = {},
  ): Promise<void> {
    if (!signerProvider) throw new Error('signer provider cannot be nil');
    refuseReplaceOnJSONLD(opts);
    await this.base.executeOptions(signingOptions(opts));
    const { vm, url: resolved } = await this.base.resolveSigningVMEntry(opts);
    const kind = vmKeyKind(vm);
    if (!kind) throw new Error(`verification method '${resolved}' has an unrecognized key type`);
    if (kind !== 'P-256') {
      throw new Error(`unsupported key kind ${kind} for ecdsa-sd-2023 credential`);
    }
    await addECDSASDBaseProof(
      this.base.getInternalData(),
      signerProvider,
      resolved,
      'assertionMethod',
      dotPathsToPointers(mandatoryPaths),
      hexToBytes(publicKeyHexFromVM(vm)),
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

/** Free-function constructors (go NewECDSASDCredential / ParseECDSASDCredential). */
export function newECDSASDCredential(
  vcc: CredentialContents,
  opts: CredentialOptions = {},
): Promise<ECDSASDCredential> {
  return ECDSASDCredential.create(vcc, opts);
}

export function parseECDSASDCredential(
  rawJSON: Uint8Array | string,
  opts: CredentialOptions = {},
): Promise<ECDSASDCredential> {
  return ECDSASDCredential.parse(rawJSON, opts);
}
