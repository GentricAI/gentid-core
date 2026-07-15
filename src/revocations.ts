/** Revocation list validation, anti-rollback, and freshness tiers — spec §6. */

import { verifyObjectSig } from "./keys";
import type {
  OperationClass,
  PublicKeyJwk,
  RevocationList,
} from "./types";
import { VerifyError } from "./types";

/** Verify a list's signature against the domain's anchors and basic shape. */
export async function verifyRevocationList(
  list: RevocationList,
  anchors: (PublicKeyJwk & { kid: string })[]
): Promise<void> {
  if (list.type !== "gentid.revocations.v1") {
    throw new VerifyError("E_PARSE", "not a gentid.revocations.v1");
  }
  const key = anchors.find((a) => a.kid === list.sig.kid);
  if (!key || !(await verifyObjectSig(list, key))) {
    throw new VerifyError("E_PARSE", "revocation list not signed by a domain anchor");
  }
  if (!Number.isInteger(list.serial) || list.serial < 0) {
    throw new VerifyError("E_PARSE", "revocation serial must be a non-negative integer");
  }
}

/**
 * Anti-rollback (spec §6.1): callers persist the highest serial seen per domain and
 * pass it here; a lower-serial list is rejected and MUST NOT replace the cache.
 */
export function checkRollback(list: RevocationList, highestSeenSerial: number | undefined): void {
  if (highestSeenSerial !== undefined && list.serial < highestSeenSerial) {
    throw new VerifyError(
      "E_ROLLBACK",
      `revocation list serial ${list.serial} < previously seen ${highestSeenSerial}`
    );
  }
}

export interface FreshnessOpts {
  now: number;
  operationClass: OperationClass;
  /** From the domain's .well-known (spec §3.2). Defaults: maxAge 300, refreshInterval 3600. */
  revocationMaxAge?: number;
  refreshInterval?: number;
}

/**
 * Freshness tiers (spec §6.4). Returns whether revocation was actually checked.
 * `financial` + missing/stale ⇒ throws E_STALE. Deliberately no bypass parameter.
 */
export function checkFreshness(
  list: RevocationList | undefined,
  opts: FreshnessOpts
): { revocationChecked: boolean } {
  const { now, operationClass } = opts;
  const maxAge = opts.revocationMaxAge ?? 300;
  const refreshInterval = opts.refreshInterval ?? 3600;

  switch (operationClass) {
    case "read":
      return { revocationChecked: list !== undefined };
    case "commit": {
      if (!list) throw new VerifyError("E_STALE", "commit-class check requires a revocation list");
      if (now > list.nextUpdateBy + refreshInterval) {
        throw new VerifyError("E_STALE", "revocation list past nextUpdateBy grace window");
      }
      return { revocationChecked: true };
    }
    case "financial": {
      if (!list) {
        throw new VerifyError("E_STALE", "financial-class check requires a fresh revocation list");
      }
      if (now - list.issuedAt > maxAge) {
        throw new VerifyError(
          "E_STALE",
          `revocation list age ${now - list.issuedAt}s exceeds revocation.maxAge ${maxAge}s`
        );
      }
      return { revocationChecked: true };
    }
  }
}

/** Is a kid or id revoked by this list? Revoking a kid kills its whole subtree (spec §6.1). */
export function isRevoked(
  list: RevocationList,
  chainKids: string[],
  agentId: string
): { revoked: boolean; entry?: { kid?: string; id?: string } } {
  for (const e of list.revoked) {
    if (e.kid && chainKids.includes(e.kid)) return { revoked: true, entry: e };
    if (e.id && e.id === agentId) return { revoked: true, entry: e };
  }
  return { revoked: false };
}
