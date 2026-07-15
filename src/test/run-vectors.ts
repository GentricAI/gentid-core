/**
 * Conformance runner: unit checks (JCS, ids, did:web) + every spec/test-vectors file.
 * Exits non-zero on any failure.
 */

import * as fs from "fs";
import * as path from "path";
import { canonicalize } from "../jcs";
import { formatGentId, fromDidWeb, parseGentId, toDidWeb } from "../id";
import { scopeCovers } from "../narrowing";
import { verifyChain, verifyMandate } from "../verify";
import { VerifyError } from "../types";

let passed = 0;
let failed = 0;
function check(name: string, cond: boolean, detail?: string) {
  if (cond) {
    passed++;
  } else {
    failed++;
    console.error(`FAIL ${name}${detail ? " — " + detail : ""}`);
  }
}

function unitTests() {
  // JCS — RFC 8785 behaviors
  check("jcs sorts keys", canonicalize({ b: 1, a: 2 }) === '{"a":2,"b":1}');
  check("jcs nested", canonicalize({ z: { y: [2, 1], x: null } }) === '{"z":{"x":null,"y":[2,1]}}');
  // RFC 8785: ECMAScript number serialization — 1e-6 prints as 0.000001, 1e-7 as 1e-7.
  check(
    "jcs numbers",
    canonicalize({ n: 1e21, m: 0.000001, s: 1e-7 }) === '{"m":0.000001,"n":1e+21,"s":1e-7}'
  );
  check("jcs unicode key order", canonicalize({ "€": 1, a: 2 }) === '{"a":2,"€":1}');
  check(
    "jcs drops undefined members",
    canonicalize({ a: 1, sig: undefined }) === '{"a":1}'
  );

  // Identifiers — spec §2.1
  const p = parseGentId("gentic:agent:delta.com:ops:booking:rebooker-7");
  check("id parse domain", p.domain === "delta.com");
  check("id parse path", JSON.stringify(p.path) === '["ops","booking"]');
  check("id parse name", p.name === "rebooker-7");
  check("id roundtrip", formatGentId(p.domain!, p.path!, p.name!) === p.id);
  const legacy = parseGentId("gentic:agent:a3f9d2e8b1c4");
  check("legacy flagged", legacy.legacy === true);
  check("legacy no domain", legacy.domain === undefined);
  let threw = false;
  try {
    parseGentId("gentic:agent:no_dots_not_hex");
  } catch {
    threw = true;
  }
  check("malformed id rejected", threw);

  // did:web — spec §2.2
  const did = toDidWeb("gentic:agent:delta.com:ops:rebooker-7");
  check("toDidWeb", did === "did:web:delta.com:gentid:ops:rebooker-7");
  check("fromDidWeb roundtrip", fromDidWeb(did) === "gentic:agent:delta.com:ops:rebooker-7");

  // Scope matching — spec §4.1
  check("scope wildcard covers", scopeCovers("booking:*", "booking:create"));
  check("scope wildcard deep", scopeCovers("booking:*", "booking:intl:create"));
  check("scope wildcard not prefix-string", !scopeCovers("booking:*", "bookingx"));
  check("scope exact", scopeCovers("support:read", "support:read"));
  check("scope exact mismatch", !scopeCovers("support:read", "support:write"));
  check("scope star covers all", scopeCovers("*", "anything:at:all"));
}

async function vectorTests() {
  const dir = path.resolve(__dirname, "../../../spec/test-vectors");
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .sort();
  check("vectors present", files.length >= 12, `found ${files.length}`);

  for (const f of files) {
    const v = JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
    const { name, kind, input, expect } = v;
    let outcome: string;
    try {
      if (kind === "mandate") {
        await verifyMandate(input.mandate, input.bundle, input.anchors, input.opts);
      } else {
        await verifyChain(input.bundle, input.anchors, input.opts);
      }
      outcome = "valid";
    } catch (e) {
      outcome = e instanceof VerifyError ? e.code : `UNEXPECTED:${(e as Error).message}`;
    }
    check(`vector ${name}`, outcome === expect, `expected ${expect}, got ${outcome}`);
  }
}

(async () => {
  unitTests();
  await vectorTests();
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
})();
