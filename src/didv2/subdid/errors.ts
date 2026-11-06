/**
 * Sentinel errors, Go-style: an error built by `wrapSentinel` matches its
 * sentinels under `errorIs` (Go's errors.Is) even though its message carries
 * extra detail.
 */
export class SubDIDError extends Error {
  constructor(
    message: string,
    readonly sentinels: readonly Error[],
    cause?: unknown,
  ) {
    super(message);
    this.name = 'SubDIDError';
    if (cause !== undefined) (this as { cause?: unknown }).cause = cause;
  }
}

export function wrapSentinel(detail: string, cause?: unknown, ...sentinels: Error[]): SubDIDError {
  return new SubDIDError(`${sentinels.map((s) => s.message).join(': ')}: ${detail}`, sentinels, cause);
}

/** errors.Is: true when `err` is `target`, wraps it, or has it in its cause chain. */
export function errorIs(err: unknown, target: Error): boolean {
  for (let e: unknown = err, i = 0; e && i < 16; i++) {
    if (e === target) return true;
    if (e instanceof SubDIDError && e.sentinels.includes(target)) return true;
    e = (e as { cause?: unknown }).cause;
  }
  return false;
}
