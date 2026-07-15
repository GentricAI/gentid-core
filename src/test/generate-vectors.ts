/**
 * Generates spec/test-vectors/ — the protocol conformance suite (spec §12).
 * Vectors are a deliverable for third-party implementers, not just our tests.
 *
 * Each vector: { name, description, kind: "chain" | "mandate", input, expect }
 *   input  = { bundle, anchors, opts, mandate? }  (opts.now is fixed — vectors are deterministic)
 *   expect = "valid" | VerifyErrorCode
 */

import * as fs from "fs";
import * as path from "path";
import {
  createAgentCert,
  createBundle,
  createDelegation,
  createEnvelope,
  createMandate,
  createRevocationList,
  createWellKnown,
} from "../builders";
import { generateAgentKeypair, generateDelegateKeypair, generateRootKeypair } from "../keys";
import type { Envelope } from "../types";

const NOW = 1752600000; // fixed epoch for deterministic windows
const YEAR = 365 * 24 * 3600;

async function main() {
  const outDir = path.resolve(__dirname, "../../../spec/test-vectors");
  fs.mkdirSync(outDir, { recursive: true });

  // ---- build a realistic org: delta.com root → "ops" delegation → agent ----
  const root = await generateRootKeypair();
  const ops = await generateDelegateKeypair();
  const agent = await generateAgentKeypair();
  const domain = "delta.com";
  const anchors = [root.publicJwk];

  const opsDelegation = await createDelegation({
    domain,
    name: "ops",
    parentChain: [],
    subject: ops.publicJwk,
    grants: {
      scopes: ["booking:*", "support:read"],
      mandateCeiling: { currency: "USD", perTransaction: 500, perDay: 2000, total: 10000 },
      maxDepth: 2,
    },
    nbf: NOW - 3600,
    exp: NOW + YEAR,
    signer: { privatePkcs8: root.privatePkcs8, kid: root.kid },
  });

  const agentCert = await createAgentCert({
    domain,
    name: "rebooker-7",
    parentChain: [opsDelegation],
    subject: agent.publicJwk,
    grants: {
      scopes: ["booking:rebook"],
      mandateCeiling: { currency: "USD", perTransaction: 200 },
    },
    nbf: NOW - 3600,
    exp: NOW + 50 * 24 * 3600,
    signer: { privatePkcs8: ops.privatePkcs8, kid: ops.kid },
  });

  const envelope = await createEnvelope({
    agentId: agentCert.id,
    agentKid: agent.kid,
    payload: '{"action":"rebook","pnr":"ABC123"}',
    privatePkcs8: agent.privatePkcs8,
    ts: NOW,
  });

  const freshList = await createRevocationList({
    domain,
    serial: 7,
    revoked: [],
    issuedAt: NOW - 60,
    signer: { privatePkcs8: root.privatePkcs8, kid: root.kid },
  });

  const wellKnown = await createWellKnown({
    domain,
    rootKeys: [root.publicJwk],
    nodeBaseUrl: "https://gentid.delta.com",
    mandateEnforcers: ["atheries.com"],
    signer: { privatePkcs8: root.privatePkcs8, kid: root.kid },
  });

  const bundle = createBundle(agentCert, [opsDelegation]);
  const vectors: object[] = [];
  const add = (
    name: string,
    description: string,
    kind: "chain" | "mandate",
    input: object,
    expect: string
  ) => vectors.push({ name, description, kind, input, expect });

  const baseOpts = { now: NOW, envelope, wellKnown };

  // 1. valid 3-link chain (root → ops → agent), read class
  add(
    "valid-chain",
    "A valid root→delegation→agent chain with a fresh envelope.",
    "chain",
    { bundle, anchors, opts: { ...baseOpts, operationClass: "read" } },
    "valid"
  );

  // 2. grant-widening chain: agent claims a scope its delegation doesn't cover.
  //    (Built by tampering — the builder itself refuses to widen — so the sig also breaks;
  //    to isolate narrowing we re-sign honestly from the widened grants at the ops key.)
  const widenedAgentCert = await createAgentCert({
    domain,
    name: "rebooker-7",
    parentChain: [opsDelegation],
    subject: agent.publicJwk,
    grants: { scopes: ["booking:rebook"] },
    nbf: NOW - 3600,
    exp: NOW + 50 * 24 * 3600,
    signer: { privatePkcs8: ops.privatePkcs8, kid: ops.kid },
  });
  const widened = {
    ...widenedAgentCert,
    grants: { scopes: ["payments:send"] }, // outside booking:*/support:read — and breaks sig
  };
  add(
    "chain-widens-grants",
    "Agent cert scope 'payments:send' exceeds its delegation's grants (tamper also breaks sig).",
    "chain",
    {
      bundle: createBundle(widened as never, [opsDelegation]),
      anchors,
      opts: { now: NOW, operationClass: "read" },
    },
    "E_CHAIN"
  );

  // 2b. honestly-signed widening: ops key signs an over-broad cert. Sig is VALID;
  //     only the narrowing check can catch it. The sharpest vector in the suite.
  const { signObject } = await import("../keys");
  const widenedSigned = await signObject(
    { ...widenedAgentCert, grants: { scopes: ["payments:send"] }, sig: undefined } as never,
    ops.privatePkcs8,
    ops.kid
  );
  add(
    "chain-widens-grants-signed",
    "Delegation key legitimately signs an agent cert whose scopes exceed its own grants — narrowing MUST reject even though every signature is valid.",
    "chain",
    {
      bundle: createBundle(widenedSigned as never, [opsDelegation]),
      anchors,
      opts: { now: NOW, operationClass: "read" },
    },
    "E_CHAIN"
  );

  // 3. expired delegation link
  const expiredDelegation = await createDelegation({
    domain,
    name: "ops",
    parentChain: [],
    subject: ops.publicJwk,
    grants: { scopes: ["booking:*"] },
    nbf: NOW - YEAR,
    exp: NOW - 3600,
    signer: { privatePkcs8: root.privatePkcs8, kid: root.kid },
  });
  const agentUnderExpired = await createAgentCert({
    domain,
    name: "rebooker-7",
    parentChain: [expiredDelegation],
    subject: agent.publicJwk,
    grants: { scopes: ["booking:rebook"] },
    nbf: NOW - YEAR,
    exp: NOW - 3600,
    signer: { privatePkcs8: ops.privatePkcs8, kid: ops.kid },
  });
  add(
    "chain-expired-link",
    "Delegation link expired an hour before verification time.",
    "chain",
    {
      bundle: createBundle(agentUnderExpired, [expiredDelegation]),
      anchors,
      opts: { now: NOW, operationClass: "read" },
    },
    "E_CHAIN"
  );

  // 4. revoked delegation kid ⇒ whole subtree dies
  const listRevokingOps = await createRevocationList({
    domain,
    serial: 8,
    revoked: [{ kid: ops.kid, at: NOW - 300, reason: "key-compromise" }],
    issuedAt: NOW - 60,
    signer: { privatePkcs8: root.privatePkcs8, kid: root.kid },
  });
  add(
    "chain-revoked-kid",
    "The 'ops' delegation kid is revoked; the agent under it must be rejected.",
    "chain",
    {
      bundle,
      anchors,
      opts: { ...baseOpts, operationClass: "commit", revocationList: listRevokingOps },
    },
    "E_REVOKED"
  );

  // 5. rollback: older serial than previously seen
  add(
    "revocations-rollback",
    "Revocation list serial 7 presented after serial 9 was seen — anti-rollback must reject.",
    "chain",
    {
      bundle,
      anchors,
      opts: {
        ...baseOpts,
        operationClass: "commit",
        revocationList: freshList,
        highestSeenSerial: 9,
      },
    },
    "E_ROLLBACK"
  );

  // 6. tampered envelope: payloadHash altered after signing
  const tamperedEnvelope: Envelope = { ...envelope, payloadHash: "AAAA" + envelope.payloadHash.slice(4) };
  add(
    "envelope-tampered",
    "Envelope payloadHash modified after signing — leaf signature must fail.",
    "chain",
    {
      bundle,
      anchors,
      opts: { now: NOW, envelope: tamperedEnvelope, operationClass: "read" },
    },
    "E_LEAF"
  );

  // 7. stale financial: list older than revocation.maxAge (300s)
  const staleList = await createRevocationList({
    domain,
    serial: 9,
    revoked: [],
    issuedAt: NOW - 4000,
    signer: { privatePkcs8: root.privatePkcs8, kid: root.kid },
  });
  add(
    "financial-stale-list",
    "Financial-class verification with a 4000s-old revocation list (maxAge 300) must deny.",
    "chain",
    {
      bundle,
      anchors,
      opts: { ...baseOpts, operationClass: "financial", revocationList: staleList },
    },
    "E_STALE"
  );

  // 7b. financial with NO list at all must also deny — unknown = deny.
  add(
    "financial-unknown-denies",
    "Financial-class verification with no revocation list at all must deny (unknown = deny).",
    "chain",
    { bundle, anchors, opts: { ...baseOpts, operationClass: "financial" } },
    "E_STALE"
  );

  // 8. valid mandate, signed by the ops delegation key, within ceilings
  const validMandate = await createMandate({
    domain,
    agentId: agentCert.id,
    limits: { currency: "USD", perTransaction: 150, perDay: 800, total: 3000 },
    enforcers: ["atheries.com"],
    nbf: NOW - 60,
    exp: NOW + 30 * 24 * 3600,
    scope: { payees: ["acme-travel.com"], categories: ["travel"] },
    signer: { privatePkcs8: ops.privatePkcs8, kid: ops.kid },
  });
  add(
    "valid-mandate",
    "Mandate within the ops delegation's ceiling, naming a designated enforcer.",
    "mandate",
    {
      bundle,
      anchors,
      mandate: validMandate,
      opts: { ...baseOpts, revocationList: freshList },
    },
    "valid"
  );

  // 9. mandate exceeding the signer's ceiling (perTransaction 900 > 500)
  const overMandate = await createMandate({
    domain,
    agentId: agentCert.id,
    limits: { currency: "USD", perTransaction: 900 },
    enforcers: ["atheries.com"],
    nbf: NOW - 60,
    exp: NOW + 30 * 24 * 3600,
    signer: { privatePkcs8: ops.privatePkcs8, kid: ops.kid },
  });
  add(
    "mandate-exceeds-ceiling",
    "Mandate perTransaction 900 exceeds the ops delegation's ceiling of 500.",
    "mandate",
    {
      bundle,
      anchors,
      mandate: overMandate,
      opts: { ...baseOpts, revocationList: freshList },
    },
    "E_CHAIN"
  );

  // 10. mandate naming an enforcer the org never designated
  const rogueEnforcerMandate = await createMandate({
    domain,
    agentId: agentCert.id,
    limits: { currency: "USD", perTransaction: 100 },
    enforcers: ["rogue-settler.example"],
    nbf: NOW - 60,
    exp: NOW + 30 * 24 * 3600,
    signer: { privatePkcs8: ops.privatePkcs8, kid: ops.kid },
  });
  add(
    "mandate-unauthorized-enforcer",
    "Mandate names an enforcer absent from the org's policy.mandateEnforcers.",
    "mandate",
    {
      bundle,
      anchors,
      mandate: rogueEnforcerMandate,
      opts: { ...baseOpts, revocationList: freshList },
    },
    "E_CHAIN"
  );

  // 11. wrong-anchor chain: same structure, signed by an unrelated "root"
  const impostorRoot = await generateRootKeypair();
  const impostorDelegation = await createDelegation({
    domain,
    name: "ops",
    parentChain: [],
    subject: ops.publicJwk,
    grants: { scopes: ["booking:*"] },
    nbf: NOW - 3600,
    exp: NOW + YEAR,
    signer: { privatePkcs8: impostorRoot.privatePkcs8, kid: impostorRoot.kid },
  });
  const agentUnderImpostor = await createAgentCert({
    domain,
    name: "rebooker-7",
    parentChain: [impostorDelegation],
    subject: agent.publicJwk,
    grants: { scopes: ["booking:rebook"] },
    nbf: NOW - 3600,
    exp: NOW + 50 * 24 * 3600,
    signer: { privatePkcs8: ops.privatePkcs8, kid: ops.kid },
  });
  add(
    "chain-wrong-anchor",
    "Chain signed by a root key not in the domain's anchors — the scammer-runs-the-same-code case.",
    "chain",
    {
      bundle: createBundle(agentUnderImpostor, [impostorDelegation]),
      anchors, // delta.com's real anchors
      opts: { now: NOW, operationClass: "read" },
    },
    "E_ANCHOR"
  );

  for (const v of vectors) {
    const name = (v as { name: string }).name;
    fs.writeFileSync(path.join(outDir, `${name}.json`), JSON.stringify(v, null, 2));
  }
  fs.writeFileSync(
    path.join(outDir, "README.md"),
    `# GentID Protocol Conformance Vectors\n\nGenerated by \`@gentid/core\` (spec §12). Each file: \`{ name, description, kind, input, expect }\`.\n\`kind: "chain"\` → run \`verifyChain(input.bundle, input.anchors, input.opts)\`.\n\`kind: "mandate"\` → run \`verifyMandate(input.mandate, input.bundle, input.anchors, input.opts)\`.\n\`expect\` is \`"valid"\` or the required error code. A conforming verifier matches every vector.\n\nVectors are deterministic: \`opts.now\` is fixed inside each file. ${vectors.length} vectors.\n`
  );
  console.log(`wrote ${vectors.length} vectors to ${outDir}`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
