/** Protocol object types — spec §3–§9. Field semantics are normative in the spec. */

export interface PublicKeyJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string; // base64url raw 32-byte public key
  kid?: string;
}

export interface Sig {
  alg: "EdDSA";
  kid: string;
  sig: string; // base64url Ed25519 signature over JCS(object minus `sig`)
}

export interface MandateCeiling {
  currency: string;
  perTransaction?: number;
  perDay?: number;
  total?: number;
}

export interface Grants {
  scopes: string[];
  mandateCeiling?: MandateCeiling;
  maxDepth?: number;
}

/** spec §4.1 */
export interface Delegation {
  type: "gentid.delegation.v1";
  domain: string;
  name: string;
  path: string[];
  subject: PublicKeyJwk & { kid: string };
  grants: Grants;
  nbf: number;
  exp: number;
  sig: Sig;
}

/** spec §4.2 */
export interface AgentCert {
  type: "gentid.agent.v1";
  id: string;
  domain: string;
  path: string[];
  name: string;
  subject: PublicKeyJwk & { kid: string };
  grants: Grants;
  nbf: number;
  exp: number;
  sig: Sig;
}

/** spec §5.1 */
export interface Envelope {
  type: "gentid.msg.v1";
  id: string; // nonce, >=128-bit base64url
  ts: number;
  agent: string;
  kid: string;
  payloadHash: string;
  mandate?: Mandate | string | null;
  sig: Sig;
}

/** spec §5.1 */
export interface Bundle {
  type: "gentid.bundle.v1";
  agentCert: AgentCert;
  delegations: Delegation[]; // root-first
  attestations?: Attestation[];
  revocations?: RevocationList;
}

/** spec §6.1 */
export interface RevocationEntry {
  kid?: string;
  id?: string;
  at: number;
  reason?: string;
}

export interface RevocationList {
  type: "gentid.revocations.v1";
  domain: string;
  serial: number;
  issuedAt: number;
  nextUpdateBy: number;
  revoked: RevocationEntry[];
  sig: Sig;
}

/** spec §7.1 */
export interface Mandate {
  type: "gentid.mandate.v1";
  id: string;
  domain: string;
  agent: string;
  limits: MandateCeiling;
  scope?: { payees?: string[]; categories?: string[] };
  approval?: { aboveAmount?: number; method?: string };
  escrow?: { required?: boolean; releaseOn?: string };
  enforcers: string[];
  nbf: number;
  exp: number;
  sig: Sig;
}

/** spec §7.7 — parsed/verified by GentID, emitted only by enforcers. */
export interface Receipt {
  type: "gentid.receipt.v1";
  id: string;
  enforcer: string;
  mandate: string;
  agent: string;
  payee: string;
  amount: number;
  currency: string;
  outcome: "settled" | "refunded" | "disputed" | "failed";
  ts: number;
  sig: Sig;
}

/** spec §9 */
export interface Attestation {
  type: "gentid.attestation.v1";
  kind: string; // "org-verified" | ...
  subjectDomain: string;
  subjectKid: string;
  authority: string;
  claims?: Record<string, unknown>;
  issuedAt: number;
  exp: number;
  sig: Sig;
}

/** spec §10 */
export interface AliasRecord {
  type: "gentid.alias.v1";
  legacyId: string;
  id: string;
  issuedAt: number;
  sig: Sig;
}

/** spec §3.2 */
export interface WellKnownDoc {
  type: "gentid.node.v1";
  domain: string;
  protocolVersion: string;
  rootKeys: (PublicKeyJwk & { kid: string })[];
  endpoints: { agents: string; delegations: string; revocations: string };
  revocation: { maxAge: number; refreshInterval: number };
  policy: { mandateEnforcers: string[] };
  sig: Sig;
}

/** spec §6.4 */
export type OperationClass = "read" | "commit" | "financial";

/** Verification error codes — spec §5.2 / §6. */
export type VerifyErrorCode =
  | "E_PARSE"
  | "E_FRESHNESS"
  | "E_ANCHOR"
  | "E_CHAIN"
  | "E_LEAF"
  | "E_REVOKED"
  | "E_STALE"
  | "E_ROLLBACK";

export class VerifyError extends Error {
  constructor(
    public code: VerifyErrorCode,
    message: string,
    public linkIndex?: number
  ) {
    super(`${code}: ${message}`);
    this.name = "VerifyError";
  }
}

export interface VerifiedIdentity {
  id: string;
  domain: string;
  path: string[];
  name: string;
  /** Fully narrowed effective grants at the leaf. */
  grants: Grants;
  chain: (Delegation | AgentCert)[];
  /** Tiers 0–1 computed locally; 2–3 when recognized attestations/receipts presented. */
  assurance: 0 | 1 | 2 | 3;
  revocationChecked: boolean;
  legacy?: boolean;
}
