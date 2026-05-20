/**
 * StatusList2021Credential models — Node port of
 * credential/common/credential-status/model.go
 */
export interface StatusListCredentialResponse {
  data: StatusListCredential;
}

export interface StatusListCredential {
  '@context': string[];
  credentialSubject: StatusListCredentialSubject;
  id: string;
  issuer: string;
  proof: Record<string, unknown>;
  type: string[];
  validFrom: string;
  validUntil: string;
}

export interface StatusListCredentialSubject {
  encodedList: string;
  id: string;
  statusPurpose: string;
  type: string;
}
