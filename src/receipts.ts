/**
 * Receipt and attestation verification — spec §7.7 / §9.
 * GentID parses and verifies these; only enforcers/authorities emit them.
 */

import { verifyObjectSig } from "./keys";
import type { Attestation, PublicKeyJwk, Receipt } from "./types";
import { VerifyError } from "./types";

/** Verify a settlement receipt against the *enforcer's* domain anchors (spec §7.7). */
export async function verifyReceipt(
  receipt: Receipt,
  enforcerAnchors: (PublicKeyJwk & { kid: string })[],
  opts: { now?: number } = {}
): Promise<Receipt> {
  if (receipt.type !== "gentid.receipt.v1") {
    throw new VerifyError("E_PARSE", "not a gentid.receipt.v1");
  }
  const key = enforcerAnchors.find((a) => a.kid === receipt.sig.kid);
  if (!key || !(await verifyObjectSig(receipt, key))) {
    throw new VerifyError("E_ANCHOR", "receipt not signed by an enforcer anchor key");
  }
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (receipt.ts > now + 300) {
    throw new VerifyError("E_FRESHNESS", "receipt timestamp in the future");
  }
  return receipt;
}

/** Verify an attestation against the *authority's* anchor keys (spec §9). */
export async function verifyAttestation(
  attestation: Attestation,
  authorityAnchors: (PublicKeyJwk & { kid: string })[],
  opts: { now?: number } = {}
): Promise<Attestation> {
  if (attestation.type !== "gentid.attestation.v1") {
    throw new VerifyError("E_PARSE", "not a gentid.attestation.v1");
  }
  const key = authorityAnchors.find((a) => a.kid === attestation.sig.kid);
  if (!key || !(await verifyObjectSig(attestation, key))) {
    throw new VerifyError("E_ANCHOR", "attestation not signed by an authority anchor key");
  }
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (!(attestation.issuedAt <= now && now <= attestation.exp)) {
    throw new VerifyError("E_FRESHNESS", "attestation outside validity window");
  }
  return attestation;
}
