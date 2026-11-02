/**
 * JSON-LD verifiable credential — Node port of vc/json_credential.go.
 */
import type { Proof } from '../common/dto/proof';
import {
  addCustomProof,
  addECDSAProof,
  canonicalize,
  toMap,
  verifyProof,
} from '../common/jsonmap/jsonmap';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '../common/crypto/hex';
import { canonicalizeRDF, computeDigest } from '../common/processor/processor';
import { DefaultProvider } from '../common/signer/default-provider';
import type { SignerProvider } from '../common/signer/signer';
import { resolveSigningVM } from '../common/verification-method';
import { getOptions } from './options';
import {
  checkExpiration,
  checkRevocation,
  extractFieldFromMap,
  serializeCredentialContents,
  validateCredential,
} from './credential-helper';
import type {
  Credential,
  CredentialContents,
  CredentialData,
  CredentialOptions,
} from './types';

export class JSONCredential implements Credential {
  private credentialData: CredentialData;
  private verificationMethodKey: string;

  constructor(credentialData: CredentialData, verificationMethodKey = '') {
    this.credentialData = credentialData;
    this.verificationMethodKey = verificationMethodKey;
  }

  static async create(
    vcc: CredentialContents,
    opts: CredentialOptions = {},
  ): Promise<JSONCredential> {
    const m = serializeCredentialContents(vcc);
    const options = getOptions(opts);
    const cred = new JSONCredential(m, options.verificationMethodKey);
    await cred.executeOptions(opts);
    return cred;
  }

  static async parse(rawJSON: Uint8Array | string, opts: CredentialOptions = {}): Promise<JSONCredential> {
    const buf = typeof rawJSON === 'string' ? Buffer.from(rawJSON, 'utf8') : Buffer.from(rawJSON);
    if (buf.length === 0) throw new Error('JSON string is empty');
    let parsed: unknown;
    try {
      parsed = JSON.parse(buf.toString('utf8'));
    } catch (err) {
      throw new Error(`failed to unmarshal credential: ${(err as Error).message}`);
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('invalid JSON format');
    }
    const cred = new JSONCredential(parsed as CredentialData);
    await cred.executeOptions(opts);
    return cred;
  }

  async addProof(priv: string, opts: CredentialOptions = {}): Promise<void> {
    const signer = new DefaultProvider(priv);
    await this.addProofByProvider(signer, opts);
  }

  async addProofByProvider(
    signer: SignerProvider,
    opts: CredentialOptions = {},
  ): Promise<void> {
    if (!signer) throw new Error('signer provider cannot be nil');
    await this.executeOptions(opts);

    const issuer = this.credentialData.issuer;
    if (typeof issuer !== 'string' || !issuer) {
      throw new Error('issuer is missing or invalid');
    }

    const options = getOptions(opts);
    let vmKey = this.verificationMethodKey;
    if (options.verificationMethodKey) vmKey = options.verificationMethodKey;
    const { url: vmURL } = await resolveSigningVM(
      issuer,
      'assertionMethod',
      vmKey,
      options.resolver,
    );

    await addECDSAProof(this.credentialData, signer, vmURL, 'assertionMethod');
  }

  async getSigningInput(): Promise<Uint8Array> {
    return canonicalize(this.credentialData);
  }

  async addCustomProof(proof: Proof, opts: CredentialOptions = {}): Promise<void> {
    if (!proof) throw new Error('proof cannot be nil');
    await this.executeOptions({
      ...opts,
      verifyProof: opts.verifyProof || Boolean(this.credentialData.proof),
    });
    addCustomProof(this.credentialData, proof);
  }

  async verify(opts: CredentialOptions = {}): Promise<void> {
    await this.executeOptions({ ...opts, verifyProof: true });
  }

  async serialize(): Promise<CredentialData> {
    if (!this.credentialData.proof) {
      throw new Error('credential must have proof before serialization');
    }
    return toMap(this.credentialData) as CredentialData;
  }

  getContents(): Uint8Array {
    return new Uint8Array(Buffer.from(JSON.stringify(this.credentialData), 'utf8'));
  }

  getType(): 'JSON' {
    return 'JSON';
  }

  extractField(path: string): unknown {
    if (!this.credentialData) return null;
    return extractFieldFromMap(this.credentialData, path);
  }

  async hash(): Promise<string> {
    if (!this.credentialData.proof) {
      throw new Error('credential must have proof before hashing');
    }
    const raw = this.credentialData.proof;
    const first = (Array.isArray(raw) ? raw[0] : raw) as { proofValue?: string };
    const pv = typeof first?.proofValue === 'string' ? first.proofValue : '';
    if (pv.startsWith('z') || pv.startsWith('u')) {
      return bytesToHex(computeDigest(await canonicalizeRDF(this.credentialData)));
    }
    return bytesToHex(sha256(Buffer.from(JSON.stringify(this.credentialData), 'utf8')));
  }

  async addSelectiveDisclosures(_selectivePaths: string[]): Promise<Credential> {
    throw new Error('JSON credential does not support selective disclosures');
  }

  async executeOptions(opts: CredentialOptions = {}): Promise<void> {
    const options = getOptions(opts);
    const tasks: Promise<void>[] = [];

    if (options.validateSchema) {
      tasks.push(
        (async () => {
          try {
            await validateCredential(this.credentialData, options);
          } catch (err) {
            throw new Error(`validate credential: ${(err as Error).message}`);
          }
        })(),
      );
    }
    if (options.checkRevocation) {
      tasks.push(
        (async () => {
          try {
            await checkRevocation(this.credentialData);
          } catch (err) {
            throw new Error(`check revocation: ${(err as Error).message}`);
          }
        })(),
      );
    }
    if (options.verifyProof) {
      tasks.push(
        (async () => {
          let ok: boolean;
          try {
            ok = await verifyProof(this.credentialData, options.resolver);
          } catch (err) {
            throw new Error(`verify proof: ${(err as Error).message}`);
          }
          if (!ok) throw new Error('verify proof: invalid proof');
        })(),
      );
    }

    if (tasks.length > 0) {
      const results = await Promise.allSettled(tasks);
      for (const r of results) {
        if (r.status === 'rejected') {
          throw new Error(`credential verification failed: ${(r.reason as Error).message}`);
        }
      }
    }

    if (options.checkExpiration) {
      try {
        checkExpiration(this.credentialData, options.clockSkewLeewayMs);
      } catch (err) {
        throw new Error(`failed to check expiration: ${(err as Error).message}`);
      }
    }
  }

  /** Exposed for tests / VP serialization. */
  getInternalData(): CredentialData {
    return this.credentialData;
  }
}
