# Limitations (DRAFT r2)

**Status:** DRAFT r2, 2026-10-15. Updated as stages land; measured limits are added only
after they are measured.

## What an Accept does not mean

- It is not proof that O exists, that K_O belongs to O, or that O legally owns or may
  authorize testing of an asset. Organization identity (RQ1) is an in-memory registry
  fixture and asset binding (RQ2) is an in-memory binding fixture. Both are assumed
  correct; nothing in this prototype checks them against real evidence.
- It is not proof that the party presenting G holds K_T, nor that a given agent session
  or subagent is bound to G (RQ5). A copied grant verifies exactly like the original.
- It is not enforcement of what an agent or tool actually does. `scope_query` is a lookup
  on a grant, not mediation of traffic or effects (RQ6). Effects of unmanaged or opaque
  tools are not observed. What a TestClass such as `injection_testing` permits in terms of
  concrete actions is not defined anywhere in v0; only sets of class names are compared.
- It is not a fresh revocation decision. Status comes from an in-memory fixture that
  answers instantly and is always current; real freshness, caching, propagation and
  bounded revocation delay are RQ7 and are not measured.
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

- Expected labels were drafted by the implementer; most are now owner-reviewed, some
  remain proposed (see experiment.md). Agreement between the verifier and the labels is
  empirical evidence about this implementation, not a formal soundness proof and not
  evidence that the spec itself is right.
- Cases are synthetic and single-factor (plus three precedence cases); real deployments
  will produce combinations not covered here.
- Benchmarks measure a single machine and an in-memory status fixture; they say nothing
  about network status lookups or production load.
- The literature comparison behind this design is selective; absence of a public feature
  in provider documentation does not show that no private implementation exists.
