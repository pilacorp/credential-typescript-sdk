/**
 * Time helpers — Node port of credential/common/util/time.go
 *
 * Go's time.RFC3339 = "2006-01-02T15:04:05Z07:00".
 * Node's Date.toISOString() always emits ".sssZ"; this module exposes helpers
 * that round to seconds to match Go's RFC3339 output unless the caller asked
 * to keep sub-second precision.
 */

/** Format date in RFC3339 — seconds precision, always UTC ("Z"). */
export function formatRFC3339(date: Date): string {
  const pad = (n: number, w = 2) => n.toString().padStart(w, '0');
  return (
    `${date.getUTCFullYear()}-` +
    `${pad(date.getUTCMonth() + 1)}-` +
    `${pad(date.getUTCDate())}T` +
    `${pad(date.getUTCHours())}:` +
    `${pad(date.getUTCMinutes())}:` +
    `${pad(date.getUTCSeconds())}Z`
  );
}

/**
 * Format a date the way Go's time.Time.MarshalJSON does (RFC3339Nano): UTC "Z",
 * with trailing zeros trimmed from the fractional seconds and the dot dropped
 * when there is no fraction. Matches the bytes Go hashes, unlike Date.toISOString
 * which always emits exactly ".sssZ". JS Date is millisecond-precision, so this
 * cannot reproduce sub-millisecond nanoseconds a Go document might carry.
 */
export function formatRFC3339Nano(date: Date): string {
  const iso = date.toISOString(); // YYYY-MM-DDTHH:mm:ss.sssZ
  const m = iso.match(/^(.*)\.(\d+)Z$/);
  if (!m) return iso;
  const frac = m[2].replace(/0+$/, '');
  return frac ? `${m[1]}.${frac}Z` : `${m[1]}Z`;
}

const RFC3339 =
  /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d+))?(?:Z|([+-])(\d{2}):(\d{2}))$/;

/**
 * Strict RFC 3339 (Go `time.Parse(time.RFC3339, ...)`): `T` separator, a
 * mandatory zone, real calendar values. Returns nanoseconds since the epoch,
 * which `Date` (milliseconds) cannot hold. Throws if invalid.
 */
export function parseRFC3339Nanos(value: string): bigint {
  const m = typeof value === 'string' ? RFC3339.exec(value) : null;
  if (!m) throw new Error(`invalid RFC3339 time: ${value}`);
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number);
  const ms = Date.UTC(y, mo - 1, d, h, mi, s);
  const check = new Date(ms);
  if (
    mo < 1 || mo > 12 || h > 23 || mi > 59 || s > 59 ||
    check.getUTCMonth() !== mo - 1 || check.getUTCDate() !== d ||
    (m[9] !== undefined && (Number(m[9]) > 23 || Number(m[10]) > 59))
  ) {
    throw new Error(`invalid RFC3339 time: ${value}`);
  }
  const offsetSec = m[8] ? (m[8] === '-' ? -1 : 1) * (Number(m[9]) * 3600 + Number(m[10]) * 60) : 0;
  const frac = BigInt((m[7] ?? '').slice(0, 9).padEnd(9, '0'));
  return (BigInt(ms / 1000 - offsetSec)) * 1_000_000_000n + frac;
}

/** Strict RFC 3339 as a Date (millisecond precision; see parseRFC3339Nanos). Throws if invalid. */
export function parseRFC3339(value: string): Date {
  return new Date(Number(parseRFC3339Nanos(value) / 1_000_000n));
}
