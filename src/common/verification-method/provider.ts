/**
 * DID resolver provider — Node port of
 * credential/common/verification-method/provider.go
 *
 * Higher-level helpers (selector, vm-lookup, resolve-vm-url) live in sibling
 * files so callers that already have a resolved document can reuse them.
 */
import { DIDDocument, parseDIDDocument } from './verification-method';

export interface ResolverProvider {
  resolveDocument(did: string): Promise<DIDDocument>;
}

export interface HTTPResolverOptions {
  fetchFn?: typeof fetch;
  /** Timeout in ms. Defaults to 10s. */
  timeoutMs?: number;
}

export class HTTPResolver implements ResolverProvider {
  private readonly baseURL: string;
  private readonly fetchFn: typeof fetch;
  private readonly timeoutMs: number;

  constructor(baseURL: string, opts: HTTPResolverOptions = {}) {
    this.baseURL = baseURL;
    this.fetchFn = opts.fetchFn ?? fetch;
    this.timeoutMs = opts.timeoutMs ?? 10_000;
  }

  async resolveDocument(did: string): Promise<DIDDocument> {
    if (!did) throw new Error('did is empty');
    const apiURL = `${this.baseURL}/${encodeURIComponent(did)}`;

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const resp = await this.fetchFn(apiURL, { signal: controller.signal });
      if (!resp.ok) {
        throw new Error(
          `DID resolver API returned non-200 status: ${resp.status} ${resp.statusText}`,
        );
      }
      const body = (await resp.json()) as Record<string, unknown>;
      return parseDIDDocument(body);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(`failed to resolve DID document for '${did}': ${message}`);
    } finally {
      clearTimeout(timer);
    }
  }
}

export function newHTTPResolver(
  baseURL: string,
  opts: HTTPResolverOptions = {},
): HTTPResolver {
  return new HTTPResolver(baseURL, opts);
}
