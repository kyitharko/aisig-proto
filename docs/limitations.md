# Limitations (DRAFT v0)

**Status:** DRAFT for owner review, 2026-10-15. Updated as stages land; measured limits
will be added only after they are measured.

## What an Accept does not mean

- It is not proof that O legally owns or may authorize testing of an asset. Organization
  identity (RQ1) and asset binding (RQ2) are trusted fixtures in this prototype.
- It is not proof that the party presenting G holds K_T, nor that a given agent session
  or subagent is bound to G (RQ5).
- It is not enforcement of what an agent or tool actually does. `scope_query` is a lookup
  on a grant, not mediation of traffic or effects (RQ6). Effects of unmanaged or opaque
  tools are not observed.
- It is not a fresh revocation decision. Status comes from an in-memory fixture; real
  freshness, caching and bounded revocation delay are RQ7.
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
- The test-scope vocabulary is a small fixed enum chosen for the experiment; it is not a
  standard taxonomy and is open for owner review (spec Q6).
- Times are second-precision UTC; clock uncertainty is a single symmetric ε supplied by
  the fixture.
- Single provider P. No federation, no separate CA or verification authority.

## Encoding and crypto limits

- The canonical JSON subset is intended to match RFC 8785 on its restricted value domain
  but is not conformance-tested against JCS test vectors.
- No production wire format is selected (not JWS, COSE or VC). Envelope design is for
  this experiment only.
- Ed25519 only; no algorithm agility, key rotation or HSM handling beyond registry
  version/status fields.
- Synthetic keys are derived from public labels and are deliberately insecure.

## Evaluation limits

- Expected labels are written by the implementer and remain *proposed* until independently
  reviewed by the research owner. Agreement with the verifier is not evidence of
  correctness of the spec itself.
- Cases are synthetic and single-factor (plus three precedence cases); real deployments
  will produce combinations not covered here.
- Benchmarks measure a single machine and an in-memory status fixture; they say nothing
  about network status lookups or production load.
- The literature comparison behind this design is selective; absence of a public feature
  in provider documentation does not show that no private implementation exists.
