/**
 * Issuance builders — used by @gentid/node, the CLI, and tests.
 * Every builder enforces monotonic narrowing at issuance time (spec §4.1:
 * "fail loudly if a requested grant exceeds the parent").
 */

import { formatGentId } from "./id";
import { hashPayload, randomNonce, signObject } from "./keys";
import { EffectiveGrants, ROOT_GRANTS, narrowGrants } from "./narrowing";
import type {
  AgentCert,
  Bundle,
  Delegation,
  Envelope,
  Grants,
  Mandate,
  MandateCeiling,
  PublicKeyJwk,
  RevocationEntry,
  RevocationList,
  WellKnownDoc,
} from "./types";

export interface SignerCtx {
  privatePkcs8: string;
  kid: string;
}

/** Effective grants at a chain position, for issuance-time narrowing checks. */
export function effectiveGrantsOf(parentChain: (Delegation | AgentCert)[]): EffectiveGrants {
  let eff = ROOT_GRANTS;
  for (const link of parentChain) eff = narrowGrants(eff, link.grants);
  return eff;
}

export async function createDelegation(args: {
  domain: string;
  name: string;
  /** Delegations between the root and this one, root-first ([] for a root delegation). */
  parentChain: Delegation[];
  subject: PublicKeyJwk & { kid: string };
  grants: Grants;
  nbf: number;
  exp: number;
  signer: SignerCtx;
}): Promise<Delegation> {
  narrowGrants(effectiveGrantsOf(args.parentChain), args.grants); // throws on widening
  const parent = args.parentChain[args.parentChain.length - 1];
  if (parent) {
    if (args.exp > parent.exp) throw new Error("delegation exp exceeds parent exp");
    if (args.nbf < parent.nbf) throw new Error("delegation nbf precedes parent nbf");
    if (args.signer.kid !== parent.subject.kid) {
      throw new Error("signer is not the parent delegation's subject");
    }
  }
  const path = args.parentChain.map((d) => d.name);
  return signObject<Delegation>(
    {
      type: "gentid.delegation.v1",
      domain: args.domain,
      name: args.name,
      path,
      subject: args.subject,
      grants: args.grants,
      nbf: args.nbf,
      exp: args.exp,
    },
    args.signer.privatePkcs8,
    args.signer.kid
  );
}

export const DEFAULT_AGENT_TTL_SECONDS = 60 * 24 * 60 * 60; // 60 days (spec §4.2)

export async function createAgentCert(args: {
  domain: string;
  name: string;
  parentChain: Delegation[];
  subject: PublicKeyJwk & { kid: string };
  grants: Grants;
  nbf: number;
  exp?: number;
  signer: SignerCtx;
}): Promise<AgentCert> {
  narrowGrants(effectiveGrantsOf(args.parentChain), args.grants);
  const parent = args.parentChain[args.parentChain.length - 1];
  const exp = args.exp ?? args.nbf + DEFAULT_AGENT_TTL_SECONDS;
  if (parent) {
    if (exp > parent.exp) throw new Error("agent cert exp exceeds parent exp");
    if (args.signer.kid !== parent.subject.kid) {
      throw new Error("signer is not the parent delegation's subject");
    }
  }
  const path = args.parentChain.map((d) => d.name);
  return signObject<AgentCert>(
    {
      type: "gentid.agent.v1",
      id: formatGentId(args.domain, path, args.name),
      domain: args.domain,
      path,
      name: args.name,
      subject: args.subject,
      grants: args.grants,
      nbf: args.nbf,
      exp,
    },
    args.signer.privatePkcs8,
    args.signer.kid
  );
}

export function createBundle(
  agentCert: AgentCert,
  delegations: Delegation[],
  extras?: Pick<Bundle, "attestations" | "revocations">
): Bundle {
  return { type: "gentid.bundle.v1", agentCert, delegations, ...extras };
}

export async function createEnvelope(args: {
  agentId: string;
  agentKid: string;
  payload: Uint8Array | string;
  privatePkcs8: string;
  ts?: number;
  mandate?: Mandate | string;
}): Promise<Envelope> {
  return signObject<Envelope>(
    {
      type: "gentid.msg.v1",
      id: randomNonce(),
      ts: args.ts ?? Math.floor(Date.now() / 1000),
      agent: args.agentId,
      kid: args.agentKid,
      payloadHash: await hashPayload(args.payload),
      ...(args.mandate !== undefined ? { mandate: args.mandate } : {}),
    },
    args.privatePkcs8,
    args.agentKid
  );
}

export async function createMandate(args: {
  domain: string;
  agentId: string;
  limits: MandateCeiling;
  enforcers: string[];
  nbf: number;
  exp: number;
  scope?: Mandate["scope"];
  approval?: Mandate["approval"];
  escrow?: Mandate["escrow"];
  signer: SignerCtx;
}): Promise<Mandate> {
  return signObject<Mandate>(
    {
      type: "gentid.mandate.v1",
      id: randomNonce(),
      domain: args.domain,
      agent: args.agentId,
      limits: args.limits,
      ...(args.scope ? { scope: args.scope } : {}),
      ...(args.approval ? { approval: args.approval } : {}),
      ...(args.escrow ? { escrow: args.escrow } : {}),
      enforcers: args.enforcers,
      nbf: args.nbf,
      exp: args.exp,
    },
    args.signer.privatePkcs8,
    args.signer.kid
  );
}

export async function createRevocationList(args: {
  domain: string;
  serial: number;
  revoked: RevocationEntry[];
  issuedAt?: number;
  refreshInterval?: number;
  signer: SignerCtx;
}): Promise<RevocationList> {
  const issuedAt = args.issuedAt ?? Math.floor(Date.now() / 1000);
  return signObject<RevocationList>(
    {
      type: "gentid.revocations.v1",
      domain: args.domain,
      serial: args.serial,
      issuedAt,
      nextUpdateBy: issuedAt + (args.refreshInterval ?? 3600),
      revoked: args.revoked,
    },
    args.signer.privatePkcs8,
    args.signer.kid
  );
}

/** Alias record linking a legacy registry-era id to a domain-anchored id (spec §10). */
export async function createAliasRecord(args: {
  legacyId: string;
  id: string;
  signer: SignerCtx;
  issuedAt?: number;
}): Promise<import("./types").AliasRecord> {
  return signObject<import("./types").AliasRecord>(
    {
      type: "gentid.alias.v1",
      legacyId: args.legacyId,
      id: args.id,
      issuedAt: args.issuedAt ?? Math.floor(Date.now() / 1000),
    },
    args.signer.privatePkcs8,
    args.signer.kid
  );
}

export async function createWellKnown(args: {
  domain: string;
  rootKeys: (PublicKeyJwk & { kid: string })[];
  nodeBaseUrl: string;
  revocationMaxAge?: number;
  refreshInterval?: number;
  mandateEnforcers?: string[];
  signer: SignerCtx;
}): Promise<WellKnownDoc> {
  return signObject<WellKnownDoc>(
    {
      type: "gentid.node.v1",
      domain: args.domain,
      protocolVersion: "0.1",
      rootKeys: args.rootKeys,
      endpoints: {
        agents: `${args.nodeBaseUrl}/v1/agents/{id}`,
        delegations: `${args.nodeBaseUrl}/v1/delegations/{kid}`,
        revocations: `${args.nodeBaseUrl}/v1/revocations`,
      },
      revocation: {
        maxAge: args.revocationMaxAge ?? 300,
        refreshInterval: args.refreshInterval ?? 3600,
      },
      policy: { mandateEnforcers: args.mandateEnforcers ?? [] },
    },
    args.signer.privatePkcs8,
    args.signer.kid
  );
}
