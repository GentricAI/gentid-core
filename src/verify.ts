/**
 * verifyChain — spec §5.2, and verifyMandate — spec §7.2.
 * Pure functions over their inputs: no I/O, no network. Anchors and revocation
 * state are resolved by the caller (e.g. @gentid/resolver) and passed in.
 */

import { formatGentId, parseGentId } from "./id";
import { verifyObjectSig } from "./keys";
import { EffectiveGrants, ROOT_GRANTS, fitsCeiling, narrowGrants } from "./narrowing";
import {
  checkFreshness,
  checkRollback,
  isRevoked,
  verifyRevocationList,
} from "./revocations";
import type {
  AgentCert,
  Bundle,
  Delegation,
  Envelope,
  Mandate,
  OperationClass,
  PublicKeyJwk,
  RevocationList,
  VerifiedIdentity,
  WellKnownDoc,
} from "./types";
import { VerifyError } from "./types";

export interface VerifyChainOpts {
  now?: number;
  operationClass?: OperationClass;
  /** The envelope under test. Omit to verify a bare bundle (no envelope binding). */
  envelope?: Envelope;
  /** Expected SHA-256 (base64url) of the request payload, to match envelope.payloadHash. */
  expectedPayloadHash?: string;
  /**
   * Nonce replay guard: return true if (agent, nonce) was already seen.
   * Callers own storage; core stays pure.
   */
  seenNonce?: (agent: string, nonce: string) => boolean;
  /** Freshest known revocation list for the domain (overrides bundle.revocations if newer). */
  revocationList?: RevocationList;
  /** Highest revocation serial previously seen for this domain (anti-rollback, §6.1). */
  highestSeenSerial?: number;
  /** From the domain's .well-known; needed for financial freshness + mandate enforcers. */
  wellKnown?: WellKnownDoc;
  /** Whether the anchors were corroborated via DNS/.well-known (tier 1 vs tier 0, §9). */
  anchorsCorroborated?: boolean;
  /** Attestation authorities this verifier recognizes (tier 2, §9). */
  trustedAuthorities?: string[];
  /** ±window for envelope ts, seconds. Normative default 300 (§5.1). */
  tsWindow?: number;
}

const TS_WINDOW = 300;

/** spec §5.2. Throws VerifyError; returns the verified identity. */
export async function verifyChain(
  bundle: Bundle,
  anchors: (PublicKeyJwk & { kid: string })[],
  opts: VerifyChainOpts = {}
): Promise<VerifiedIdentity> {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const operationClass = opts.operationClass ?? "read";

  // Step 1 — parse.
  if (!bundle || bundle.type !== "gentid.bundle.v1" || !bundle.agentCert) {
    throw new VerifyError("E_PARSE", "not a gentid.bundle.v1");
  }
  const agentCert = bundle.agentCert;
  if (agentCert.type !== "gentid.agent.v1") {
    throw new VerifyError("E_PARSE", "bundle.agentCert is not gentid.agent.v1");
  }
  const delegations = bundle.delegations ?? [];
  for (const d of delegations) {
    if (d.type !== "gentid.delegation.v1") {
      throw new VerifyError("E_PARSE", "bundle.delegations contains a non-delegation object");
    }
  }
  const parsedId = parseGentId(agentCert.id);
  if (parsedId.legacy) {
    throw new VerifyError("E_PARSE", "legacy IDs verify via the legacy compatibility node (§10)");
  }

  // Step 2 — envelope freshness.
  const envelope = opts.envelope;
  if (envelope) {
    if (envelope.type !== "gentid.msg.v1") {
      throw new VerifyError("E_PARSE", "envelope is not gentid.msg.v1");
    }
    const window = opts.tsWindow ?? TS_WINDOW;
    if (Math.abs(envelope.ts - now) > window) {
      throw new VerifyError("E_FRESHNESS", `envelope ts outside ±${window}s window`);
    }
    if (envelope.id.length < 22) {
      // 128 bits base64url = 22 chars
      throw new VerifyError("E_FRESHNESS", "envelope nonce shorter than 128 bits");
    }
    if (opts.seenNonce && opts.seenNonce(envelope.agent, envelope.id)) {
      throw new VerifyError("E_FRESHNESS", "envelope nonce replayed");
    }
    if (
      opts.expectedPayloadHash !== undefined &&
      envelope.payloadHash !== opts.expectedPayloadHash
    ) {
      throw new VerifyError("E_LEAF", "payloadHash does not match request payload");
    }
  }

  // Step 3 — anchor the chain root.
  const first: Delegation | AgentCert = delegations.length > 0 ? delegations[0]! : agentCert;
  const anchorKey = anchors.find((a) => a.kid === first.sig.kid);
  if (!anchorKey) {
    throw new VerifyError("E_ANCHOR", `chain root signed by unanchored kid ${first.sig.kid}`);
  }

  // Step 4 — walk root→leaf.
  let signerKey: PublicKeyJwk & { kid: string } = anchorKey;
  let effective: EffectiveGrants = ROOT_GRANTS;
  let expectedPath: string[] = [];
  const chain: (Delegation | AgentCert)[] = [...delegations, agentCert];
  for (let i = 0; i < chain.length; i++) {
    const link = chain[i]!;
    const isLeaf = i === chain.length - 1;

    if (link.sig.kid !== signerKey.kid || !(await verifyObjectSig(link, signerKey))) {
      throw new VerifyError("E_CHAIN", `link ${i}: signature invalid or wrong signer`, i);
    }
    if (!(link.nbf <= now && now <= link.exp)) {
      throw new VerifyError("E_CHAIN", `link ${i}: outside validity window`, i);
    }
    if (link.domain !== parsedId.domain) {
      throw new VerifyError("E_CHAIN", `link ${i}: domain mismatch`, i);
    }
    if (JSON.stringify(link.path) !== JSON.stringify(expectedPath)) {
      throw new VerifyError("E_CHAIN", `link ${i}: path inconsistent with chain position`, i);
    }
    try {
      effective = narrowGrants(effective, link.grants);
    } catch (e) {
      throw new VerifyError("E_CHAIN", `link ${i}: ${(e as Error).message}`, i);
    }
    if (!isLeaf) {
      const d = link as Delegation;
      expectedPath = [...expectedPath, d.name];
      signerKey = d.subject;
    }
  }

  // Step 5 — bind the leaf.
  if (
    agentCert.id !== formatGentId(agentCert.domain, agentCert.path, agentCert.name) ||
    agentCert.name !== parsedId.name
  ) {
    throw new VerifyError("E_LEAF", "agent cert id does not match its domain/path/name");
  }
  if (envelope) {
    if (envelope.agent !== agentCert.id) {
      throw new VerifyError("E_LEAF", "envelope.agent does not match agent cert id");
    }
    if (envelope.kid !== agentCert.subject.kid) {
      throw new VerifyError("E_LEAF", "envelope.kid does not match agent cert subject");
    }
    if (!(await verifyObjectSig(envelope, agentCert.subject))) {
      throw new VerifyError("E_LEAF", "envelope signature invalid");
    }
  }

  // Step 6 — revocation.
  let list = opts.revocationList ?? bundle.revocations;
  if (list) {
    await verifyRevocationList(list, anchors);
    checkRollback(list, opts.highestSeenSerial);
  }
  const { revocationChecked } = checkFreshness(list, {
    now,
    operationClass,
    revocationMaxAge: opts.wellKnown?.revocation?.maxAge,
    refreshInterval: opts.wellKnown?.revocation?.refreshInterval,
  });
  if (list) {
    const chainKids = [
      ...delegations.map((d) => d.subject.kid),
      agentCert.subject.kid,
      first.sig.kid,
    ];
    const r = isRevoked(list, chainKids, agentCert.id);
    if (r.revoked) {
      throw new VerifyError(
        "E_REVOKED",
        `revoked: ${r.entry?.kid ? "kid " + r.entry.kid : "id " + r.entry?.id}`
      );
    }
  }

  // Step 7 — output with assurance (§9).
  let assurance: 0 | 1 | 2 | 3 = opts.anchorsCorroborated === false ? 0 : 1;
  if (assurance >= 1 && bundle.attestations && opts.trustedAuthorities?.length) {
    for (const att of bundle.attestations) {
      if (
        att.type === "gentid.attestation.v1" &&
        att.kind === "org-verified" &&
        att.subjectDomain === parsedId.domain &&
        att.issuedAt <= now &&
        now <= att.exp &&
        opts.trustedAuthorities.includes(att.authority)
      ) {
        assurance = 2; // tier 3 requires receipt history — computed by callers holding receipts
        break;
      }
    }
  }

  return {
    id: agentCert.id,
    domain: parsedId.domain!,
    path: agentCert.path,
    name: agentCert.name,
    grants: {
      scopes: effective.scopes,
      ...(effective.mandateCeiling ? { mandateCeiling: effective.mandateCeiling } : {}),
    },
    chain,
    assurance,
    revocationChecked,
  };
}

export interface VerifiedMandate {
  valid: true;
  mandate: Mandate;
  identity: VerifiedIdentity;
  enforcers: string[];
}

/** spec §7.2. Forces financial operation class. Throws VerifyError on failure. */
export async function verifyMandate(
  mandate: Mandate,
  bundle: Bundle,
  anchors: (PublicKeyJwk & { kid: string })[],
  opts: VerifyChainOpts = {}
): Promise<VerifiedMandate> {
  // Step 1 — chain verifies at financial freshness.
  const identity = await verifyChain(bundle, anchors, {
    ...opts,
    operationClass: "financial",
  });
  const now = opts.now ?? Math.floor(Date.now() / 1000);

  if (mandate.type !== "gentid.mandate.v1") {
    throw new VerifyError("E_PARSE", "not a gentid.mandate.v1");
  }
  // Step 2 — subject binding.
  if (mandate.agent !== identity.id || mandate.domain !== identity.domain) {
    throw new VerifyError("E_LEAF", "mandate agent/domain does not match verified identity");
  }
  // Step 3 — signing key must sit in the verified chain (or be an anchor).
  const chainKeys: (PublicKeyJwk & { kid: string })[] = [
    ...anchors,
    ...identity.chain.map((l) => l.subject),
  ];
  const signer = chainKeys.find((k) => k.kid === mandate.sig.kid);
  if (!signer || !(await verifyObjectSig(mandate, signer))) {
    throw new VerifyError("E_CHAIN", "mandate not signed by a key in the verified chain");
  }
  // Step 4 — validity window.
  if (!(mandate.nbf <= now && now <= mandate.exp)) {
    throw new VerifyError("E_FRESHNESS", "mandate outside validity window");
  }
  // Step 5 — limits within the effective ceiling at the signer's chain position.
  const ceiling = effectiveCeilingAt(identity, anchors, mandate.sig.kid);
  if (!fitsCeiling(mandate.limits, ceiling)) {
    throw new VerifyError("E_CHAIN", "mandate limits exceed the chain's mandateCeiling");
  }
  // Step 6 — enforcers ⊆ the domain's published policy.
  const allowed = opts.wellKnown?.policy?.mandateEnforcers ?? [];
  for (const e of mandate.enforcers) {
    if (!allowed.includes(e)) {
      throw new VerifyError("E_CHAIN", `enforcer ${e} not in policy.mandateEnforcers`);
    }
  }
  // Step 7 — revocation of the mandate id rides on the same list as the chain
  // (verifyChain above already ran at financial freshness); check mandate id too.
  const list = opts.revocationList ?? bundle.revocations;
  if (list && list.revoked.some((r) => r.id === mandate.id)) {
    throw new VerifyError("E_REVOKED", "mandate id revoked");
  }

  return { valid: true, mandate, identity, enforcers: mandate.enforcers };
}

/** Effective ceiling at the position of `kid` in the verified chain (§7.2 step 5). */
function effectiveCeilingAt(
  identity: VerifiedIdentity,
  anchors: (PublicKeyJwk & { kid: string })[],
  kid: string
) {
  if (anchors.some((a) => a.kid === kid)) return ROOT_GRANTS.mandateCeiling; // unlimited
  let effective: EffectiveGrants = ROOT_GRANTS;
  for (const link of identity.chain) {
    effective = narrowGrants(effective, link.grants);
    if (link.subject.kid === kid) return effective.mandateCeiling;
  }
  // verifyMandate already established the kid is in the chain; defensive fallback.
  return effective.mandateCeiling;
}
