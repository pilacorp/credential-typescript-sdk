/**
 * Status list revocation client — Node port of
 * credential/common/credential-status/credential_status.go
 *
 * Fetches the published StatusList2021 credential, decompresses the gzipped
 * bitstring, and tests whether the bit at the given position is set.
 */
import { decompressFromBase64URL } from '../util/compress';
import {
  StatusListCredentialResponse,
  StatusListCredentialSubject,
} from './model';

export interface ClientOptions {
  fetchFn?: typeof fetch;
  timeoutMs?: number;
}

export class StatusListClient {
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;

  constructor(opts: ClientOptions = {}) {
    this.fetchFn = opts.fetchFn ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
  }

  async fetchStatusListCredential(
    statusListCredentialURL: string,
  ): Promise<StatusListCredentialResponse> {
    if (!statusListCredentialURL) {
      throw new Error('statusListCredential URL is empty');
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const resp = await this.fetchFn(statusListCredentialURL, {
        signal: controller.signal,
      });
      if (!resp.ok) {
        throw new Error(
          `status list credential API returned non-200 status: ${resp.status} ${resp.statusText}`,
        );
      }
      const body = (await resp.json()) as StatusListCredentialResponse;
      return body;
    } finally {
      clearTimeout(timer);
    }
  }
}

/**
 * Convenience: fetch + check revocation in one call.
 */
export async function fetchAndCheckRevocation(
  statusListCredentialURL: string,
  position: number,
  opts: ClientOptions = {},
): Promise<boolean> {
  const client = new StatusListClient(opts);
  const resp = await client.fetchStatusListCredential(statusListCredentialURL);
  return isRevoked(position, resp.data.credentialSubject);
}

export function isRevoked(
  position: number,
  subject: StatusListCredentialSubject,
): boolean {
  if (subject.statusPurpose !== 'revocation') return false;

  const byteString = decompressFromBase64URL(subject.encodedList);
  const maxPosition = byteString.length * 8 - 1;
  if (position < 0 || position > maxPosition) {
    throw new Error(
      `position ${position} is out of range for bitstring of length ${byteString.length} (max position: ${maxPosition})`,
    );
  }
  const byteIndex = Math.floor(position / 8);
  const bitIndex = position % 8;
  return ((byteString[byteIndex] >> bitIndex) & 1) === 1;
}
