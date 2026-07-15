/** Identifier parsing and did:web projection — spec §2. */

import type { PublicKeyJwk } from "./types";

export interface ParsedGentId {
  id: string;
  legacy: boolean;
  /** Absent on legacy IDs. */
  domain?: string;
  path?: string[];
  name?: string;
}

const SEG = /^[A-Za-z0-9_-]{1,32}$/;
const NAME = /^[A-Za-z0-9_-]{1,64}$/;
const LEGACY_HEX = /^[0-9a-f]{6,64}$/;
const DOMAIN = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function parseGentId(id: string): ParsedGentId {
  if (!id.startsWith("gentic:agent:")) {
    throw new Error(`not a GentID identifier: ${id}`);
  }
  const rest = id.slice("gentic:agent:".length);
  const parts = rest.split(":");
  // Legacy: single hex component, no domain dot (spec §2.1 disambiguation rule).
  if (parts.length === 1 && LEGACY_HEX.test(parts[0]!)) {
    return { id, legacy: true };
  }
  if (parts.length < 2) throw new Error(`malformed GentID identifier: ${id}`);
  const domain = parts[0]!;
  if (!DOMAIN.test(domain)) throw new Error(`invalid domain in identifier: ${domain}`);
  const name = parts[parts.length - 1]!;
  if (!NAME.test(name)) throw new Error(`invalid agent name: ${name}`);
  const path = parts.slice(1, -1);
  for (const seg of path) {
    if (!SEG.test(seg)) throw new Error(`invalid path segment: ${seg}`);
  }
  return { id, legacy: false, domain, path, name };
}

export function formatGentId(domain: string, path: string[], name: string): string {
  return ["gentic:agent:" + domain, ...path, name].join(":");
}

export function isLegacyId(id: string): boolean {
  try {
    return parseGentId(id).legacy;
  } catch {
    return false;
  }
}

/** spec §2.2: gentic:agent:D:p…:n ⇄ did:web:D:gentid:p…:n */
export function toDidWeb(gentid: string): string {
  const p = parseGentId(gentid);
  if (p.legacy) throw new Error("legacy identifiers have no did:web projection");
  return ["did:web:" + p.domain, "gentid", ...p.path!, p.name!].join(":");
}

export function fromDidWeb(did: string): string {
  const parts = did.split(":");
  if (parts[0] !== "did" || parts[1] !== "web" || parts[3] !== "gentid" || parts.length < 5) {
    throw new Error(`not a GentID did:web projection: ${did}`);
  }
  return formatGentId(parts[2]!, parts.slice(4, -1), parts[parts.length - 1]!);
}

/** DID Document generator — spec §2.2. */
export function generateDidDocument(
  gentid: string,
  publicJwk: PublicKeyJwk & { kid: string },
  nodeEndpoint: string
): Record<string, unknown> {
  const did = toDidWeb(gentid);
  const vmId = `${did}#${publicJwk.kid}`;
  return {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/jws-2020/v1"],
    id: did,
    alsoKnownAs: [gentid],
    verificationMethod: [
      {
        id: vmId,
        type: "JsonWebKey2020",
        controller: did,
        publicKeyJwk: { kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x },
      },
    ],
    authentication: [vmId],
    assertionMethod: [vmId],
    service: [{ id: `${did}#gentid-node`, type: "GentIDNode", serviceEndpoint: nodeEndpoint }],
  };
}
