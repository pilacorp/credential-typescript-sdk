/**
 * VC serialization helpers — Node port of credential/common/util/vc.go
 */
import type { Proof } from '../dto/proof';
import type { JSONMap } from './json';
import { parseRFC3339Nanos } from './time';

export function serializeTypes(types: string[]): unknown {
  if (types.length === 0) return null;
  if (types.length === 1) return types[0];
  return [...types];
}

/** Checks VC/VP `validFrom` / `validUntil` against the current clock. */
export function checkValidityPeriod(
  data: JSONMap,
  entity: 'credential' | 'presentation',
  leewayMs = 0,
): void {
  const now = BigInt(Date.now()) * 1_000_000n;
  const leeway = BigInt(Math.trunc(Math.max(leewayMs, 0))) * 1_000_000n;
  for (const [field, kind] of [['validFrom', 'start'], ['validUntil', 'end']] as const) {
    const value = data[field];
    if (value === undefined || value === null || value === '') continue;
    if (typeof value !== 'string') throw new Error(`field "${field}" must be a string`);
    let time: bigint;
    try {
      time = parseRFC3339Nanos(value);
    } catch {
      throw new Error(`failed to parse ${field}`);
    }
    if (kind === 'start' && now + leeway < time) throw new Error(`${entity} is not valid yet`);
    if (kind === 'end' && now - leeway > time) throw new Error(`${entity} is expired`);
  }
}

/** Validates JWT envelope `nbf` / `exp` claims (JWT credentials and presentations only). */
export function checkJwtTimeClaims(claims: JSONMap, leewayMs = 0): void {
  const now = Date.now();
  const leeway = Math.max(leewayMs, 0);
  for (const [claim, kind] of [['nbf', 'start'], ['exp', 'end']] as const) {
    const value = claims[claim];
    if (value === undefined || value === null) continue;
    if (typeof value !== 'number' || !Number.isFinite(value) || Math.trunc(value) <= 0) {
      throw new Error(`invalid JWT ${claim} claim`);
    }
    const time = Math.trunc(value) * 1000;
    if (kind === 'start' && now + leeway < time) throw new Error('JWT is not valid yet');
    // RFC 7519 §4.1.4: not acceptable on or after exp (Go: !now.Before(exp)).
    if (kind === 'end' && now - leeway >= time) throw new Error('JWT is expired');
  }
}

export function serializeContexts(contexts: unknown[]): unknown[] {
  const validated: unknown[] = [];
  for (let i = 0; i < contexts.length; i++) {
    const ctx = contexts[i];
    if (ctx === null || ctx === undefined) {
      throw new Error(
        `failed to validate context: context entry at index ${i} is nil`,
      );
    }
    if (typeof ctx === 'string') {
      if (ctx === '') {
        throw new Error(
          `failed to validate context: context string at index ${i} is empty`,
        );
      }
      validated.push(ctx);
      continue;
    }
    if (typeof ctx === 'object' && !Array.isArray(ctx)) {
      const obj = ctx as JSONMap;
      if ('@context' in obj) {
        throw new Error(
          `failed to validate context: context object at index ${i} must not contain nested @context`,
        );
      }
      for (const [key, val] of Object.entries(obj)) {
        if (key === '') {
          throw new Error(
            `failed to validate context: context object at index ${i} has empty key`,
          );
        }
        if (typeof val === 'string' && val === '') {
          throw new Error(
            `failed to validate context: context object at index ${i} has empty string value for key "${key}"`,
          );
        }
      }
      validated.push(obj);
      continue;
    }
    throw new Error(
      `failed to validate context: invalid context entry at index ${i}: must be string or map`,
    );
  }
  return validated;
}

/**
 * Serializes a slice of proofs to a JSON-LD compatible form.
 * Returns the lone proof object directly when the array has length 1 (matches Go behavior).
 */
export function serializeProofs(proofs: Proof[]): unknown {
  if (proofs.length === 0) return null;
  const result: JSONMap[] = proofs.map((proof) => {
    const out: JSONMap = {};
    if (proof.type) out.type = proof.type;
    if (proof.created) out.created = proof.created;
    if (proof.verificationMethod)
      out.verificationMethod = proof.verificationMethod;
    if (proof.proofPurpose) out.proofPurpose = proof.proofPurpose;
    if (proof.proofValue) out.proofValue = proof.proofValue;
    if (proof.cryptosuite) out.cryptosuite = proof.cryptosuite;
    if (proof.challenge) out.challenge = proof.challenge;
    if (proof.domain) out.domain = proof.domain;
    if (proof.jws) out.jws = proof.jws;
    return out;
  });
  if (result.length === 1) return result[0];
  return result;
}

export function parseProof(proof: JSONMap): Proof {
  const required = ['type', 'created', 'verificationMethod', 'proofPurpose'];
  for (const f of required) {
    if (typeof proof[f] !== 'string' || proof[f] === '') {
      throw new Error(`failed to parse proof: invalid or missing ${f} field`);
    }
  }
  const result: Proof = {
    type: proof.type as string,
    created: proof.created as string,
    verificationMethod: proof.verificationMethod as string,
    proofPurpose: proof.proofPurpose as string,
  };
  if (typeof proof.proofValue === 'string') result.proofValue = proof.proofValue;
  if (typeof proof.jws === 'string') result.jws = proof.jws;
  if (Array.isArray(proof.disclosures)) {
    result.disclosures = (proof.disclosures as unknown[]).filter(
      (d): d is string => typeof d === 'string',
    );
  }
  if (typeof proof.cryptosuite === 'string') result.cryptosuite = proof.cryptosuite;
  if (typeof proof.challenge === 'string') result.challenge = proof.challenge;
  if (typeof proof.domain === 'string') result.domain = proof.domain;
  return result;
}
