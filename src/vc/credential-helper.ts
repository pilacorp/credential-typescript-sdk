/**
 * Credential helpers — Node port of credential/vc/credential_helper.go
 *
 * Serialization helpers between CredentialContents (structured) and
 * CredentialData (JSON map), plus schema/revocation/expiration checks.
 */
import Ajv2020 from 'ajv/dist/2020';
import addFormats from 'ajv-formats';
import { fetchAndCheckRevocation } from '../common/credential-status';
import { copyExcept, JSONMap, shallowCopyObj, splitJSONObj } from '../common/util/json';
import { formatRFC3339 } from '../common/util/time';
import { checkValidityPeriod, serializeContexts, serializeTypes } from '../common/util/vc';
import type { ResolvedCredentialOptions } from './options';
import type {
  CredentialContents,
  CredentialData,
  Schema,
  Status,
  Subject,
  TermsOfUse,
} from './types';

/** Extract a dot-notation field from a nested JSON map. */
export function extractFieldFromMap(m: JSONMap, path: string): unknown {
  if (!m) return null;
  const parts = path.split('.');
  let current: unknown = m;
  for (const p of parts) {
    if (current == null) return null;
    if (typeof current !== 'object' || Array.isArray(current)) return null;
    const obj = current as JSONMap;
    if (!(p in obj)) return null;
    current = obj[p];
  }
  return current;
}

export function serializeCredentialContents(
  vcc: CredentialContents | null,
): CredentialData {
  if (!vcc) throw new Error('credential contents is nil');

  if (
    (!vcc.context || vcc.context.length === 0) &&
    !vcc.id &&
    !vcc.issuer
  ) {
    throw new Error(
      'credential contents must have at least one of: context, ID, or issuer',
    );
  }

  const vcJSON: CredentialData = {};
  if (vcc.context && vcc.context.length > 0) {
    vcJSON['@context'] = serializeContexts(vcc.context);
  }
  if (vcc.id) vcJSON.id = vcc.id;
  if (vcc.types && vcc.types.length > 0) {
    vcJSON.type = serializeTypes(vcc.types);
  }
  if (vcc.subject && vcc.subject.length > 0) {
    vcJSON.credentialSubject = serializeSubjects(vcc.subject);
  }
  if (vcc.issuer) vcJSON.issuer = vcc.issuer;
  if (vcc.schemas && vcc.schemas.length > 0) {
    vcJSON.credentialSchema = serializeSchemas(vcc.schemas);
  }
  if (vcc.credentialStatus && vcc.credentialStatus.length > 0) {
    vcc.credentialStatus.forEach((st, i) => {
      if (!st.type) throw new Error(`credentialStatus[${i}].type is required`);
    });
    vcJSON.credentialStatus = serializeStatuses(vcc.credentialStatus);
  }
  if (vcc.termsOfUse && vcc.termsOfUse.length > 0) {
    vcc.termsOfUse.forEach((term, i) => {
      if (!term.type) throw new Error(`termsOfUse[${i}].type is required`);
    });
    vcJSON.termsOfUse = vcc.termsOfUse.map(serializeTermsOfUse);
  }
  if (vcc.validFrom) {
    vcJSON.validFrom = formatRFC3339(vcc.validFrom);
  }
  if (vcc.validUntil) {
    vcJSON.validUntil = formatRFC3339(vcc.validUntil);
  }
  return vcJSON;
}

export function normalizeCredentialData(cd: CredentialData): JSONMap {
  return normalizeMap(cd);
}

function normalizeMap(input: JSONMap): JSONMap {
  const out: JSONMap = {};
  for (const [k, v] of Object.entries(input)) {
    out[k] = normalizeValue(v);
  }
  return out;
}

function normalizeValue(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(normalizeValue);
  if (v && typeof v === 'object' && (v as object).constructor === Object) {
    return normalizeMap(v as JSONMap);
  }
  return v;
}

function serializeSubjects(subjects: Subject[]): unknown {
  if (subjects.length === 0) return null;
  if (subjects.length === 1) return serializeSubject(subjects[0]);
  return subjects.map(serializeSubject);
}

function serializeSubject(subject: Subject): CredentialData {
  const obj: CredentialData = subject.customFields
    ? shallowCopyObj(subject.customFields)
    : {};
  if (subject.id) obj.id = subject.id;
  return obj;
}

function serializeSchemas(schemas: Schema[]): unknown {
  if (schemas.length === 0) return null;
  if (schemas.length === 1) return serializeSchema(schemas[0]);
  return schemas.map(serializeSchema);
}

function serializeSchema(schema: Schema): CredentialData {
  const out: CredentialData = {};
  if (schema.id) out.id = schema.id;
  if (schema.type) out.type = schema.type;
  return out;
}

function serializeStatuses(statuses: Status[]): unknown {
  if (statuses.length === 0) return null;
  if (statuses.length === 1) return serializeStatus(statuses[0]);
  return statuses.map(serializeStatus);
}

function serializeStatus(status: Status): CredentialData {
  const out: CredentialData = {};
  if (status.id) out.id = status.id;
  if (status.type) out.type = status.type;
  if (status.statusPurpose) out.statusPurpose = status.statusPurpose;
  if (status.statusListIndex) out.statusListIndex = status.statusListIndex;
  if (status.statusListCredential) out.statusListCredential = status.statusListCredential;
  return out;
}

/** Serialize a termsOfUse entry; type is required by the W3C data model. */
function serializeTermsOfUse(term: TermsOfUse): CredentialData {
  const out: CredentialData = { type: term.type };
  if (term.id) out.id = term.id;
  return out;
}

export function subjectFromJSON(subjectObj: CredentialData): Subject {
  const [flds, rest] = splitJSONObj(subjectObj, 'id');
  let id = '';
  if (flds.id !== undefined) {
    if (typeof flds.id !== 'string') {
      throw new Error(`failed to parse subject id: field "id" must be a string`);
    }
    id = flds.id;
  }
  return { id, customFields: rest };
}

function isEmptyValue(v: unknown): boolean {
  if (v === undefined || v === null || v === '') return true;
  if (Array.isArray(v)) return v.length === 0;
  if (typeof v === 'object') return Object.keys(v as object).length === 0;
  return false;
}

/** Required on every credential by VCDM 2.0 (go requireCredentialProperties). */
export function requireCredentialProperties(m: CredentialData): void {
  for (const p of ['@context', 'type', 'issuer', 'credentialSubject']) {
    if (isEmptyValue(m[p])) throw new Error(`credential is missing ${p}`);
  }
}

// ---- Validation ----

export async function validateCredential(
  m: CredentialData,
  opts: ResolvedCredentialOptions,
): Promise<void> {
  const copyMap = shallowCopyObj(m);
  // credentialSchema is optional per VCDM 2.0 §4.11, but this path exists to
  // validate against it, so here it is required (go validateCredential).
  for (const key of ['credentialSchema', '@context', 'type', 'issuer', 'credentialSubject']) {
    if (isEmptyValue(copyMap[key])) throw new Error(`${key} is required`);
  }
  const schemaList = convertToArray(copyMap.credentialSchema);

  // The whole document is validated, proof included, like Go.
  const validationDoc = copyMap;

  // Mirror Go SDK's gojsonschema.NewReferenceLoader: identify each fetched
  // schema by its URL and resolve any `$ref` (including cross/self refs)
  // by re-fetching through the same loader.
  const ajv = new Ajv2020({
    strict: false,
    allErrors: true,
    loadSchema: async (uri: string) => {
      const bytes = await loadSchemaBytes(uri, opts);
      const json = JSON.parse(Buffer.from(bytes).toString('utf8'));
      if (typeof json === 'object' && json !== null && !('$id' in json)) {
        json.$id = uri;
      }
      return json;
    },
  });
  addFormats(ajv);

  for (const schema of schemaList) {
    if (typeof schema !== 'object' || schema === null) {
      throw new Error('credentialSchema entry must be an object');
    }
    const schemaMap = schema as JSONMap;
    const id = schemaMap.id;
    if (typeof id !== 'string' || id === '') {
      throw new Error('credentialSchema.id must be a non-empty string');
    }
    const schemaBytes = await loadSchemaBytes(id, opts);
    const schemaJSON = JSON.parse(Buffer.from(schemaBytes).toString('utf8'));
    if (typeof schemaJSON === 'object' && schemaJSON !== null && !('$id' in schemaJSON)) {
      schemaJSON.$id = id;
    }
    let validator;
    try {
      validator = ajv.getSchema(id) ?? (await ajv.compileAsync(schemaJSON));
    } catch (err) {
      throw new Error(
        `failed to compile schema: ${(err as Error).message}`,
      );
    }
    const valid = validator(validationDoc);
    if (!valid) {
      const message = validator.errors
        ? validator.errors.map((e) => `${e.instancePath} ${e.message}`).join(', ')
        : 'unknown';
      throw new Error(`credential validation failed: ${message}`);
    }
  }
}

async function loadSchemaBytes(
  id: string,
  opts: ResolvedCredentialOptions,
): Promise<Uint8Array> {
  if (opts.schemaLoader) {
    const bytes = await opts.schemaLoader(id);
    if (!bytes || bytes.length === 0) {
      throw new Error('failed to load schema via custom loader: schema is empty');
    }
    return bytes;
  }
  const resp = await fetch(id);
  if (!resp.ok) {
    throw new Error(`failed to fetch schema: ${resp.status} ${resp.statusText}`);
  }
  const buf = Buffer.from(await resp.arrayBuffer());
  return new Uint8Array(buf);
}

// ---- Expiration ----

export function checkExpiration(c: CredentialData, leewayMs = 0): void {
  checkValidityPeriod(c, 'credential', leewayMs);
}

export { checkJwtTimeClaims } from '../common/util/vc';

// ---- Revocation ----

export async function checkRevocation(c: CredentialData): Promise<void> {
  const raw = c.credentialStatus;
  if (raw === undefined || raw === null) return;
  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new Error('credentialStatus must be an object');
  }
  const statusMap = raw as JSONMap;
  if (Object.keys(statusMap).length === 0) return;

  const statusListCredential = statusMap.statusListCredential;
  if (typeof statusListCredential !== 'string' || !statusListCredential) {
    throw new Error('credentialStatus.statusListCredential is required');
  }
  const statusListIndex = statusMap.statusListIndex;
  if (typeof statusListIndex !== 'string' || !statusListIndex) {
    throw new Error('credentialStatus.statusListIndex is required');
  }
  const position = parseInt(statusListIndex, 10);
  if (!Number.isInteger(position)) {
    throw new Error('invalid credentialStatus.statusListIndex');
  }
  const isRevoked = await fetchAndCheckRevocation(statusListCredential, position);
  if (isRevoked) throw new Error('credential is revoked');
}

// ---- Parsing ----

export function parseCredentialContents(c: CredentialData): CredentialContents {
  const contents: CredentialContents = {};

  if (Array.isArray(c['@context'])) {
    contents.context = [];
    for (const ctx of c['@context'] as unknown[]) {
      if (typeof ctx === 'string' || (ctx && typeof ctx === 'object' && !Array.isArray(ctx))) {
        contents.context.push(ctx);
      } else {
        throw new Error(`unsupported context type`);
      }
    }
  }
  if (typeof c.id === 'string') contents.id = c.id;

  if (typeof c.type === 'string') contents.types = [c.type];
  else if (Array.isArray(c.type)) {
    contents.types = (c.type as unknown[]).filter((t): t is string => typeof t === 'string');
  } else if (c.type !== undefined) {
    throw new Error('unsupported type field');
  }

  if (typeof c.issuer === 'string') contents.issuer = c.issuer;

  if (typeof c.validFrom === 'string') {
    contents.validFrom = new Date(c.validFrom);
    if (isNaN(contents.validFrom.getTime())) {
      throw new Error(`failed to parse validFrom`);
    }
  }
  if (typeof c.validUntil === 'string') {
    contents.validUntil = new Date(c.validUntil);
    if (isNaN(contents.validUntil.getTime())) {
      throw new Error(`failed to parse validUntil`);
    }
  }

  if (c.credentialSubject !== undefined) {
    contents.subject = parseSubject(c.credentialSubject);
  }
  if (c.credentialSchema !== undefined) {
    contents.schemas = parseSchemas(c.credentialSchema);
  }
  if (c.credentialStatus !== undefined) {
    contents.credentialStatus = parseStatuses(c.credentialStatus);
  }

  return contents;
}

function parseSubject(raw: unknown): Subject[] {
  if (typeof raw === 'string') return [{ id: raw }];
  if (Array.isArray(raw)) {
    return raw.map((entry) => {
      if (!entry || typeof entry !== 'object') {
        throw new Error('unsupported subject format');
      }
      return subjectFromJSON(entry as CredentialData);
    });
  }
  if (raw && typeof raw === 'object') {
    return [subjectFromJSON(raw as CredentialData)];
  }
  throw new Error('unsupported subject format');
}

function parseSchemas(raw: unknown): Schema[] {
  if (Array.isArray(raw)) {
    return raw.map((entry) => parseSchemaID(entry));
  }
  if (raw && typeof raw === 'object') {
    return [parseSchemaID(raw)];
  }
  throw new Error('unsupported schema format');
}

function parseSchemaID(value: unknown): Schema {
  if (typeof value === 'string') return { id: value };
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const v = value as JSONMap;
    const out: Schema = {};
    if (typeof v.id === 'string') out.id = v.id;
    if (typeof v.type === 'string') out.type = v.type;
    return out;
  }
  throw new Error('invalid schema format');
}

function parseStatuses(raw: unknown): Status[] {
  if (Array.isArray(raw)) {
    return raw.map((entry) => {
      if (!entry || typeof entry !== 'object') {
        throw new Error('unsupported status format');
      }
      return parseStatusEntry(entry as JSONMap);
    });
  }
  if (raw && typeof raw === 'object') {
    return [parseStatusEntry(raw as JSONMap)];
  }
  throw new Error('unsupported status format');
}

function parseStatusEntry(status: JSONMap): Status {
  const s: Status = { type: '' };
  if (typeof status.id === 'string') s.id = status.id;
  if (typeof status.type === 'string') s.type = status.type;
  if (typeof status.statusPurpose === 'string') s.statusPurpose = status.statusPurpose;
  if (typeof status.statusListIndex === 'string') s.statusListIndex = status.statusListIndex;
  if (typeof status.statusListCredential === 'string') {
    s.statusListCredential = status.statusListCredential;
  }
  return s;
}

function parseStringField(obj: CredentialData, name: string): string {
  const value = obj[name];
  if (value === undefined) return '';
  if (typeof value !== 'string') {
    throw new Error(`field "${name}" must be a string`);
  }
  return value;
}

function convertToArray(value: unknown): unknown[] {
  if (value == null) return [];
  if (Array.isArray(value)) return value;
  return [value];
}
