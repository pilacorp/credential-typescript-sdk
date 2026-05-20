/**
 * SD-JWT types — Node port of credential/common/sdjwt/types.go
 */

export enum TargetKind {
  ObjectField = 'objectField',
  ArrayContainer = 'arrayContainer',
  ArrayElem = 'arrayElem',
}

export interface PathSegment {
  key: string;
  index?: number;
}

export interface DisclosureInfo {
  raw: string;
  salt: string;
  array: unknown[];
  objectField: string;
  value: unknown;
  isArrayElem: boolean;
}

export interface ResolvedTarget {
  parent: unknown;
  parentMap?: Record<string, unknown>;
  parentKey?: string;
  kind: TargetKind;
  fieldName: string;
  index: number;
  value: unknown;
}

export interface DecodedDisclosure {
  disclosure: string;
  salt: string;
  fieldName: string;
  value: unknown;
  isArrayElem: boolean;
}

export interface ParsedSDJWT {
  baseJWT: string;
  disclosures: string[];
  decodedDisclosures: DecodedDisclosure[];
}

export interface DecoyConfig {
  path: string;
  count: number;
}
