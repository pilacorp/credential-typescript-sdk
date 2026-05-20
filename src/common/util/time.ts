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

/** Parse an RFC3339 string. Throws if invalid. */
export function parseRFC3339(value: string): Date {
  const date = new Date(value);
  if (isNaN(date.getTime())) {
    throw new Error(`invalid RFC3339 time: ${value}`);
  }
  return date;
}
