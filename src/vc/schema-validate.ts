/**
 * JSON-schema validation that mimics github.com/xeipuuv/gojsonschema v1.2.0 (what the Go SDK's
 * validateCredential uses) on top of Ajv draft-07:
 *  - draft picked from `$schema` exactly like gojsonschema (draft-04/06/07 URL, a trailing '#'
 *    ignored; anything else, or none, is "Hybrid" mode, never an error);
 *  - `$ref` overrides its siblings; draft-gated keywords dropped; exclusive{Min,Max}imum bool/number
 *    forms per draft; 2019-09/2020-12 keywords are unknown and ignored;
 *  - gojsonschema's own format checkers (unknown formats pass, known ones also reject numbers);
 *  - all errors aggregated and rendered with gojsonschema's wording, "(root)" / "a.b.0" paths.
 *
 * Known gaps (cannot be reproduced on Ajv): error order (gojsonschema's is map-order random),
 * Go's `contains` per-item sub-errors, anyOf/oneOf "closest branch" is fewest-errors here but
 * score-based there, RE2-vs-ECMAScript regex dialect, net/mail + net/url parsing nuances.
 */
import Ajv, { ErrorObject } from 'ajv';
import { isIP } from 'node:net';

type Draft = 4 | 6 | 7 | 'hybrid';
type Obj = Record<string, unknown>;

const DRAFT_URLS: Record<string, Draft> = {
  'http://json-schema.org/draft-04/schema': 4,
  'http://json-schema.org/draft-06/schema': 6,
  'http://json-schema.org/draft-07/schema': 7,
};

const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

// ---- gojsonschema format checkers ----

const TIME_ZONE = '(?:Z|[+-](?:[01]\\d|2[0-3]):[0-5]\\d)';
const HMS = '(?:[01]\\d|2[0-3]):[0-5]\\d:[0-5]\\d(?:[.,]\\d+)?';
const rxPartialTime = new RegExp(`^${HMS}$`);
const rxFullTime = new RegExp(`^${HMS}${TIME_ZONE}$`);
const rxDateTime = new RegExp(`^\\d{4}-\\d{2}-\\d{2}T${HMS}${TIME_ZONE}$`);

function isDate(s: string): boolean {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(s);
  if (!m) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const dt = new Date(Date.UTC(2000, mo - 1, d));
  dt.setUTCFullYear(y);
  return mo >= 1 && mo <= 12 && dt.getUTCMonth() === mo - 1 && dt.getUTCDate() === d;
}

function validDateTime(s: string): boolean {
  // Go tries "15:04:05", "15:04:05Z07:00", "2006-01-02", RFC3339 and RFC3339Nano.
  if (rxPartialTime.test(s) || rxFullTime.test(s) || isDate(s)) return true;
  return rxDateTime.test(s) && isDate(s.slice(0, 10));
}

const rxScheme = /^[A-Za-z][A-Za-z0-9+.-]*:/;
// url.Parse failures we can detect cheaply: control chars, bad %-escapes.
const urlParses = (s: string) => !/[\u0000-\u001f\u007f]/.test(s) && !/%(?![0-9A-Fa-f]{2})/.test(s);

const rxEmailAddr = /^[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+)*@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)*$/;
function validEmail(s: string): boolean {
  // net/mail.ParseAddress: "addr" or "Display Name <addr>".
  const m = /^\s*(?:"[^"]*"|[^<>"@]*?)\s*<([^<>]+)>\s*$/.exec(s);
  return rxEmailAddr.test((m ? m[1] : s).trim());
}

const rxHostname = /^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]))*$/;

function validRegex(s: string): boolean {
  if (s === '') return true;
  if (/\(\?<?[=!]|\\[1-9]/.test(s)) return false; // RE2 has no lookaround / backreferences
  try {
    new RegExp(s, 'u');
    return true;
  } catch {
    return false;
  }
}

export const GO_FORMATS: Record<string, (s: string) => boolean> = {
  date: isDate,
  time: (s) => rxFullTime.test(s) || rxPartialTime.test(s),
  'date-time': validDateTime,
  hostname: (s) => rxHostname.test(s) && s.length < 256,
  email: validEmail,
  'idn-email': validEmail,
  ipv4: (s) => isIP(s) !== 0 && s.includes('.'),
  ipv6: (s) => isIP(s) !== 0 && s.includes(':'),
  uri: (s) => urlParses(s) && rxScheme.test(s) && !s.includes('\\'),
  iri: (s) => urlParses(s) && rxScheme.test(s) && !s.includes('\\'),
  'uri-reference': (s) => urlParses(s) && !s.includes('\\'),
  'iri-reference': (s) => urlParses(s) && !s.includes('\\'),
  'uri-template': (s) => urlParses(s) && !s.includes('\\') && /^([^{]*({[^}]*})?)*$/.test(s.split(/[?#]/)[0]),
  uuid: (s) => /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/.test(s),
  regex: validRegex,
  'json-pointer': (s) => /^(?:\/(?:[^~/]|~0|~1)*)*$/.test(s),
  'relative-json-pointer': (s) => /^(?:0|[1-9][0-9]*)(?:#|(?:\/(?:[^~/]|~0|~1)*)*)$/.test(s),
};

// ---- schema normalisation (gojsonschema semantics -> Ajv draft-07) ----

const SUB_SINGLE = ['additionalItems', 'additionalProperties', 'items', 'contains', 'propertyNames', 'not', 'if', 'then', 'else'];
const SUB_ARRAY = ['allOf', 'anyOf', 'oneOf', 'items'];
const SUB_MAP = ['properties', 'patternProperties', 'definitions', '$defs', 'dependencies'];
const KEEP_WITH_REF = new Set(['$ref', '$id', 'id', 'definitions', '$defs']);

export function detectDraft(schema: unknown): Draft {
  if (isObj(schema) && typeof schema.$schema === 'string') {
    let url = schema.$schema.endsWith('#') ? schema.$schema.slice(0, -1) : schema.$schema;
    url = url.replace(/^[A-Za-z][A-Za-z0-9+.-]*:/, (sch) => sch.toLowerCase()); // url.Parse lower-cases the scheme
    return DRAFT_URLS[url] ?? 'hybrid';
  }
  return 'hybrid';
}

function normalize(node: unknown, draft: Draft, root: boolean): unknown {
  if (typeof node === 'boolean') {
    if (draft === 4 && !root) throw new Error('Expected: valid schema, given: Invalid JSON');
    return node;
  }
  if (!isObj(node)) return node;
  // $ref returns directly in gojsonschema: siblings other than containers are ignored.
  const out: Obj = {};
  const hasRef = typeof node.$ref === 'string';
  for (const [k, v] of Object.entries(node)) {
    if (hasRef && !KEEP_WITH_REF.has(k)) continue;
    out[k] = v;
  }
  if (root) delete out.$schema;
  // `id` is the draft-04 spelling; Hybrid prefers it when present.
  if ((draft === 4 || draft === 'hybrid') && typeof out.id === 'string') {
    out.$id = out.id;
    delete out.id;
  }
  if (draft === 4) for (const k of ['const', 'contains', 'propertyNames', 'if', 'then', 'else']) delete out[k];
  if (draft === 6) for (const k of ['if', 'then', 'else']) delete out[k];

  for (const [excl, bound] of [['exclusiveMinimum', 'minimum'], ['exclusiveMaximum', 'maximum']] as const) {
    if (!(excl in out)) continue;
    const v = out[excl];
    if (draft === 4 && typeof v !== 'boolean') throw new Error(`Invalid type. Expected: boolean, given: ${excl}`);
    if (draft !== 4 && draft !== 'hybrid' && typeof v !== 'number') throw new Error(`Invalid type. Expected: number, given: ${excl}`);
    if (typeof v === 'boolean') {
      delete out[excl];
      if (v) {
        if (typeof out[bound] !== 'number') throw new Error(`${excl} cannot be used without ${bound}`);
        out[excl] = out[bound];
        delete out[bound];
      }
    }
  }

  for (const k of SUB_SINGLE) {
    if (k in out && (isObj(out[k]) || typeof out[k] === 'boolean')) {
      out[k] = k === 'additionalItems' || k === 'additionalProperties' ? normalizeAllowBool(out[k], draft) : normalize(out[k], draft, false);
    }
  }
  for (const k of SUB_ARRAY) {
    if (Array.isArray(out[k])) out[k] = (out[k] as unknown[]).map((s) => normalize(s, draft, false));
  }
  for (const k of SUB_MAP) {
    if (!isObj(out[k])) continue;
    const m: Obj = {};
    for (const [name, sub] of Object.entries(out[k] as Obj)) {
      m[name] = k === 'dependencies' && Array.isArray(sub) ? sub : normalize(sub, draft, false);
    }
    out[k] = m;
  }
  // Known formats are asserted on numbers too (gojsonschema rejects them), Ajv only checks strings.
  if (typeof out.format === 'string' && out.format in GO_FORMATS) out['x-gojs-numfmt'] = out.format;
  return out;
}

const normalizeAllowBool = (v: unknown, draft: Draft) => (typeof v === 'boolean' ? v : normalize(v, draft, false));

/** Normalise raw schema JSON for Ajv. Throws gojsonschema's wording for invalid schemas. */
export function prepareSchema(schema: unknown): Obj | boolean {
  if (typeof schema !== 'boolean' && !isObj(schema)) throw new Error('schema is invalid');
  if (typeof schema === 'boolean') return schema;
  return normalize(schema, detectDraft(schema), true) as Obj;
}

// ---- Ajv factory ----

export function newGoAjv(loadSchema: (uri: string) => Promise<unknown>): Ajv {
  const ajv = new Ajv({
    strict: false,
    allErrors: true,
    verbose: true,
    logger: false,
    validateFormats: true,
    multipleOfPrecision: 12,
    loadSchema: async (uri: string) => {
      const json = await loadSchema(uri);
      const prepared = prepareSchema(json);
      if (isObj(prepared) && !('$id' in prepared)) prepared.$id = uri;
      return prepared as Obj;
    },
  });
  for (const [name, fn] of Object.entries(GO_FORMATS)) ajv.addFormat(name, { type: 'string', validate: fn });
  ajv.addKeyword({ keyword: 'x-gojs-numfmt', type: 'number', schemaType: 'string', validate: () => false });
  return ajv;
}

// ---- error rendering (gojsonschema locale wording) ----

const goPath = (instancePath: string) =>
  instancePath === ''
    ? '(root)'
    : instancePath.slice(1).split('/').map((s) => s.replace(/~1/g, '/').replace(/~0/g, '~')).join('.');

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (isObj(v)) return Object.fromEntries(Object.keys(v).sort().map((k) => [k, sortKeys(v[k])]));
  return v;
}
/** json.Marshal: sorted keys, HTML-escaped <, >, &. */
const goJSON = (v: unknown) =>
  JSON.stringify(sortKeys(v)).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026');

function goType(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  if (typeof v === 'number') return Number.isInteger(v) ? 'integer' : 'number';
  return typeof v; // string | boolean | object
}

function message(e: ErrorObject): string {
  const p = e.params as Record<string, any>;
  const field = goPath(e.instancePath);
  switch (e.keyword) {
    case 'required': return `${p.missingProperty} is required`;
    case 'type': {
      const t = String(p.type).split(',');
      return `Invalid type. Expected: ${t.length > 1 ? `[${t.join(',')}]` : t[0]}, given: ${goType(e.data)}`;
    }
    case 'enum': return `${field} must be one of the following: ${(p.allowedValues as unknown[]).map(goJSON).join(', ')}`;
    case 'const': return `${field} does not match: ${goJSON(p.allowedValue)}`;
    case 'additionalProperties': return `Additional property ${p.additionalProperty} is not allowed`;
    case 'pattern': return `Does not match pattern '${p.pattern}'`;
    case 'minLength': return `String length must be greater than or equal to ${p.limit}`;
    case 'maxLength': return `String length must be less than or equal to ${p.limit}`;
    case 'minimum': return `Must be greater than or equal to ${p.limit}`;
    case 'exclusiveMinimum': return `Must be greater than ${p.limit}`;
    case 'maximum': return `Must be less than or equal to ${p.limit}`;
    case 'exclusiveMaximum': return `Must be less than ${p.limit}`;
    case 'multipleOf': return `Must be a multiple of ${p.multipleOf}`;
    case 'minItems': return `Array must have at least ${p.limit} items`;
    case 'maxItems': return `Array must have at most ${p.limit} items`;
    case 'uniqueItems': return `array items[${Math.min(p.i, p.j)},${Math.max(p.i, p.j)}] must be unique`;
    case 'minProperties': return `Must have at least ${p.limit} properties`;
    case 'maxProperties': return `Must have at most ${p.limit} properties`;
    case 'additionalItems': return 'No additional items allowed on array';
    case 'contains': return 'At least one of the items must match';
    case 'dependencies': return `Has a dependency on ${p.missingProperty}`;
    case 'propertyNames': return `Property name of "${p.propertyName}" does not match`;
    case 'format': return `Does not match format '${p.format}'`;
    case 'x-gojs-numfmt': return `Does not match format '${e.schema}'`;
    case 'not': return 'Must not validate the schema (not)';
    case 'anyOf': return 'Must validate at least one schema (anyOf)';
    case 'oneOf': return 'Must validate one and only one schema (oneOf)';
    case 'if': return p.failingKeyword === 'else' ? 'Must validate "else" as "if" was not valid' : 'Must validate "then" as "if" was valid';
    case 'false schema': return 'False always fails validation';
    default: return e.message ?? e.keyword;
  }
}

/** Go's `{{field}}: {{description}}` list from Ajv's flat error list. */
export function renderGoErrors(errors: ErrorObject[]): string[] {
  const dropped = new Set<ErrorObject>();
  const lines: string[] = [];
  const allOfSeen = new Set<string>();
  for (const e of errors) {
    if (dropped.has(e)) continue;
    if (e.keyword === 'anyOf' || e.keyword === 'oneOf') {
      // Keep only the closest branch (fewest errors, first on ties) and none when oneOf matched twice.
      const prefix = `${e.schemaPath}/`;
      const branches = new Map<number, ErrorObject[]>();
      for (const s of errors) {
        if (s === e || !s.schemaPath.startsWith(prefix)) continue;
        dropped.add(s);
        const idx = Number(s.schemaPath.slice(prefix.length).split('/')[0]);
        (branches.get(idx) ?? branches.set(idx, []).get(idx)!).push(s);
      }
      lines.push(`${goPath(e.instancePath)}: ${message(e)}`);
      const multi = e.keyword === 'oneOf' && (e.params as any).passingSchemas;
      const best = [...branches.entries()].sort((a, b) => a[1].length - b[1].length || a[0] - b[0])[0];
      if (best && !multi) for (const s of best[1]) lines.push(`${goPath(s.instancePath)}: ${message(s)}`);
      continue;
    }
    const m = /^(.*\/allOf)\/\d+\//.exec(e.schemaPath);
    lines.push(`${goPath(e.instancePath)}: ${message(e)}`);
    if (m) {
      // gojsonschema adds the allOf summary once, at the allOf node's own position.
      const rest = e.schemaPath.slice(m[0].length);
      const depth = (rest.match(/(^|\/)(properties|items|additionalItems)(\/|$)/g) ?? []).length;
      const segs = e.instancePath === '' ? [] : e.instancePath.slice(1).split('/');
      const path = goPath(segs.length >= depth ? segs.slice(0, segs.length - depth).map((s) => `/${s}`).join('') : '');
      const key = `${m[1]}@${path}`;
      if (!allOfSeen.has(key)) {
        allOfSeen.add(key);
        lines.push(`${path}: Must validate all the schemas (allOf)`);
      }
    }
  }
  return lines;
}
