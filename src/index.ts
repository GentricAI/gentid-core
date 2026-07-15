/**
 * @gentid/core — the GentID protocol standard, as a library.
 * Zero runtime dependencies. Zero network calls. See spec/gentid-protocol-spec.md.
 */

export * from "./types";
export { canonicalize, canonicalBytes } from "./jcs";
export { b64urlEncode, b64urlDecode } from "./b64";
export {
  generateRootKeypair,
  generateDelegateKeypair,
  generateAgentKeypair,
  computeKid,
  importPublicKey,
  importPrivateKey,
  signObject,
  verifyObjectSig,
  hashPayload,
  randomNonce,
  type Keypair,
} from "./keys";
export {
  parseGentId,
  formatGentId,
  isLegacyId,
  toDidWeb,
  fromDidWeb,
  generateDidDocument,
  type ParsedGentId,
} from "./id";
export {
  scopeCovers,
  scopesSubset,
  narrowCeiling,
  narrowGrants,
  fitsCeiling,
  ROOT_GRANTS,
  type EffectiveGrants,
} from "./narrowing";
export {
  verifyRevocationList,
  checkRollback,
  checkFreshness,
  isRevoked,
  type FreshnessOpts,
} from "./revocations";
export {
  verifyChain,
  verifyMandate,
  type VerifyChainOpts,
  type VerifiedMandate,
} from "./verify";
export { verifyReceipt, verifyAttestation } from "./receipts";
export {
  createDelegation,
  createAgentCert,
  createBundle,
  createEnvelope,
  createMandate,
  createRevocationList,
  createAliasRecord,
  createWellKnown,
  effectiveGrantsOf,
  DEFAULT_AGENT_TTL_SECONDS,
  type SignerCtx,
} from "./builders";
