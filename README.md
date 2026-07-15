# @gentid/core

The GentID protocol standard, as a library. **Zero runtime dependencies. Zero network calls.**

GentID is an open, federated identity protocol for AI agents: organizations issue identities
under their own domains, and anyone verifies them with pure cryptography — no central registry.
This package implements every format and algorithm in the
[protocol specification](https://gentid.com/spec):

- RFC 8785 (JCS) canonicalization and Ed25519 (WebCrypto — Node ≥ 20, Workers, browsers)
- `gentic:agent:domain[:path]:name` identifiers (+ legacy IDs, `did:web` projection)
- Certificates: `gentid.delegation.v1`, `gentid.agent.v1` with **monotonic narrowing**
- `verifyChain` / `verifyMandate` — pure functions per spec §5.2 / §7.2
- Revocation lists with anti-rollback and read/commit/**financial** freshness tiers
  (financial + unknown = deny, with no bypass flag)
- Mandates, settlement receipts, attestations
- Local-only key generation — private keys never cross a network boundary

```ts
import { verifyChain } from "@gentid/core";

const identity = await verifyChain(bundle, anchors, { operationClass: "commit" });
// { id: "gentic:agent:delta.com:ops:rebooker-7", domain, grants, assurance, ... }
```

Network resolution (DNS TXT + `.well-known`) lives in
[`@gentid/resolver`](https://github.com/010101G/gentid-resolver) and is injected — this package
stays pure so any runtime can host it and any implementer can check it against the published
[conformance test vectors](https://github.com/010101G/gentid/tree/main/spec/test-vectors).

```bash
npm run build && npm test   # runs the full conformance suite
```

MIT.
