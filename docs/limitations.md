# Limitations (DRAFT r3.1)

**Status:** DRAFT r3.1, 2026-10-15. Updated as stages land; measured limits are added only
after they are measured.

## What an Accept does not mean

- It is not proof that O exists, that K_O belongs to O, or that O legally owns or may
  authorize testing of an asset. Organization identity (RQ1) is an in-memory registry
  fixture and asset binding (RQ2) is an in-memory binding fixture. Both are assumed
  correct; nothing in this prototype checks them against real evidence.
- It is not proof that the party presenting G holds K_T, nor that a given agent session
  or subagent is bound to G. A copied grant verifies exactly like the original. The RQ5
  slice (docs/session.md) adds a *separate* `SessionAccept` decision for that. A chain
  Accept is never a session authorization.
- A `SessionAccept` (s1, reviewed labels) shows only that a holder of K_T's key signed a
  fresh, one-time, P-issued challenge naming P's session and the exact G, and that the
  chain re-verified at that moment. It does not provide:
  - channel or TLS binding;
  - relay or phishing resistance;
  - proof of possession on later requests;
  - protection against K_T compromise;
  - any check that P's session belongs to an entitled account.
  The challenge store's atomic compare-and-set is shown only for the in-memory store.
- It is not enforcement of what an agent or tool actually does. `exact_node_lookup` and
  `subtree_lookup` are lookups on a grant, not mediation of traffic or effects. The RQ6 slice
  e2 (docs/enforcement.md) adds a *separate*, synthetically implemented provider-mediator over
  modeled operations; it is not live tool enforcement, and a chain Accept is not that decision.
  An exact-node InScope answer covers one node only, never its subtree. Effects of unmanaged or
  opaque tools are not observed. What a TestClass such as `injection_testing` permits in terms of
  concrete *real* actions is not defined anywhere in v0; only sets of class names are compared.
- It is not a fresh revocation decision in the default chain/session/enforcement runs, which use
  an in-memory status fixture that answers instantly and is always current. The RQ7 slice f2
  (docs/freshness.md) implements a whole-interval freshness policy over a signed responder
  statement synthetically, behind its own runner; it is not wired into those default runs, and
  real freshness, caching, propagation and bounded revocation *delay* remain unmeasured (an RQ8
  latency question, docs/rq8.md). Since r3 the status fixture is keyed by the exact signed object
  (spec §6). That prevents status inheritance between objects, but says nothing about how a real
  status service learns of objects or keeps up to date.
- An object with no exact status record is Indeterminate, not Reject, even when a record
  exists for the same id/version with different content. By owner decision (spec Q9) v0
  does not infer equivocation from a digest difference; an evidenced conflict result is
  future work and needs its own definition.
- Only `verify(&Bundle)` is a supported decision API (spec §7.5). The r3 public
  pre-decoded API allowed policy to run on unsigned, altered bodies; it was removed in r3.1.
  Integrations must not reconstruct decisions from `decode_chain` output.
- The anchor stage checks that the returned registry record names O and Ed25519. The
  registry itself is still a trusted fixture (RQ1). Root rotation and multiple records per
  org are deferred (spec Q11); v0 never accepts "any available key" for an org.
- It is not P's service decision (ProviderExec). P may still refuse to run something under
  its own policy; that refusal is not a statement about O's authorization.
- "Indeterminate" and "Reject" are not accusations of malicious activity.

## Model limits

- Fixed chain depth (root → admin → authorizer → grant). Arbitrary-depth or multi-admin
  delegation (rest of RQ3) is not modelled.
- Two asset types only (web origin+path, database schema hierarchy). No wildcards, regex,
  IP ranges, cloud resources, query strings or ports-as-ranges.
- Exactly one known constraint (`max_requests_per_second`); everything else is an unknown
  constraint handled by the critical flag.
- The test-scope vocabulary (`aisig-testclass/v0`) is a small fixed enum kept for this
  experiment by owner decision (spec Q6). It is not a standard taxonomy, and how a class
  maps to concrete actions is unresolved (RQ6).
- The admissibility rule rejects some objects whose effective permission is harmless
  (a redundant target that is also excluded). This is a deliberate false reject that keeps
  the subset test exact; it is not evidence that such grants are unsafe.
- The conditional-evaluation rule (spec §7.2) lets an unauthenticated chain be rejected
  for a contradiction found under asserted keys. The reported reason is sufficient for
  rejection but may not be the only defect.
- Times are second-precision UTC; clock uncertainty is a single symmetric ε supplied by
  the fixture.
- Single provider P. No federation, no separate CA or verification authority.

## Encoding and crypto limits

- The ScopeWithin equivalence has a written proof sketch only (spec §4.3), cross-checked
  by a brute-force oracle on a small finite universe. It is not machine-checked.
- The canonical JSON subset is intended to match RFC 8785 on its restricted value domain
  but is not conformance-tested against JCS test vectors.
- No production wire format is selected (not JWS, COSE or VC). Envelope design is for
  this experiment only.
- Ed25519 only; no algorithm agility, key rotation or HSM handling beyond registry
  version/status fields.
- Synthetic keys are derived from public labels and are deliberately insecure.

## Evaluation limits

- Expected labels were drafted by the implementer; the RQ4 chain/lookup, RQ5 session, RQ6
  enforcement and RQ7 freshness labels are now owner-reviewed (see experiment.md,
  freshness.md). New measurement slices (e.g. RQ8, docs/rq8.md) introduce proposed labels that
  are reviewed in batches. Agreement between the verifier and the labels is empirical evidence
  about this implementation, not a formal soundness proof and not evidence that the spec itself
  is right.
- Cases are synthetic and single-factor (plus three precedence cases); real deployments
  will produce combinations not covered here.
- Benchmarks measure a single machine and an in-memory status fixture; they say nothing
  about network status lookups or production load. The recorded run used the `powersave`
  CPU governor without core pinning, and the policy and status series are within a few
  hundred ns, close to `Instant` timer overhead (see docs/report.md).
- Property tests use a fixed seed plus two extra seeds that were run by hand. Passing
  them is not a coverage guarantee.
- The literature comparison behind this design is selective; absence of a public feature
  in provider documentation does not show that no private implementation exists.
