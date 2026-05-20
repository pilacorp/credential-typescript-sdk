/**
 * VC serialization helpers — Node port of credential/common/util/vc.go
 */
import type { Proof } from '../dto/proof';
import type { JSONMap } from './json';

export function serializeTypes(types: string[]): unknown {
  if (types.length === 0) return null;
  if (types.length === 1) return types[0];
  return [...types];
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
