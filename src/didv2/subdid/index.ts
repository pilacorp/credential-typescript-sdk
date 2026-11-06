export { MaxLeaves, merkleProof, merkleRoot, revokedLeaf, verifyProof } from './merkle';
export { deriveSubDIDKey } from './key';
export {
  checkDID,
  didAddress,
  didPrefix,
  docHash,
  parseSubID,
  subDIDFor,
  subIDKey,
  validateSubDID,
} from './document';
export {
  ErrConsentInvalid,
  ErrPossessionInvalid,
  getRootConsent,
  normalizeSignature,
  rootConsentDigest,
  rootConsentPrefix,
  setRootConsent,
  signDocument,
  signRootConsent,
  signatureDigest,
  verifyDocumentSignature,
  verifyRootConsent,
} from './signature';
export type { ChainProof, ProofResponse } from './proof';
export { generateSubDID, withSubDIDVerificationMethods } from './generate';
export type { SubDIDOption, SubDIDResult } from './generate';
export {
  ErrChainMismatch,
  ErrChainUnavailable,
  ErrDocumentRequired,
  ErrNotAnchored,
  Verifier,
} from './verifier';
export type { Chain, ChainClient, Reason } from './verifier';
export { SubDIDError, errorIs, wrapSentinel } from './errors';
