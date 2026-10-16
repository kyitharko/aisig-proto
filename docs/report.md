# Prototype report — RQ4 chain verifier (r3.1), RQ5 session (s1), RQ6 enforcement (e2)

**Date:** 2026-10-15. **Branch:** `feature/chain-verifier-prototype` (local only, no remote).
All numbers below were produced by the commands listed; files in `results/` are the raw
outputs. Nothing here is extrapolated. Revision r3 follows the owner's review of
Stages 0–4; r3.1 follows the owner's review of r3 (see "r3.1 changes" below).

## Research-question status

| RQ | Status in this prototype |
| --- | --- |
| RQ1 organization identity / first admin | **Assumed.** In-memory registry fixture pinning (org_id, K_O). r3 checks that the returned record names O and Ed25519, but the record itself is still trusted fixture data. |
| RQ2 asset binding | **Assumed.** In-memory binding fixture. |
| RQ3 delegation non-amplification | **Partly exercised.** Fixed depth-3 chain only. |
| RQ4 grant scope semantics | **Implemented and tested** against owner-reviewed labels (spec r3). |
| RQ5 tester/session binding | **First slice (s1), reviewed labels.** Challenge/response proof of possession bound to a P-held session and the exact G (docs/session.md); no channel binding, relay resistance or per-request proof. |
| RQ6 enforcement of agent actions | **Slice e2 implemented (synthetic).** Provider-mediated tool adapter (docs/enforcement.md): 28/28 reviewed cases match. One clock snapshot per mediation; the effect-sink append is private. Only modeled synthetic effects; no live tool enforcement. |
| RQ7 revocation freshness | **Slice f2 implemented (synthetic).** Whole-interval freshness over a signed responder statement (docs/freshness.md; `src/freshness.rs`): 34/34 cases match. Labels all owner-`reviewed`. The chain/session/enforcement runs keep the instant, always-current fixture. |
| RQ8 privacy / latency / onboarding | Only single-machine CPU latency measured. |

## RQ5 session slice s1 (reviewed; separate from the chain results)

Spec [session.md](session.md); labels `tests/cases/session_cases.toml` (28, all
**proposed**), committed in `c96a39b` before the implementation (`0123190`).

**Result: 28/28 session labels match** (24 redemption, 4 issuance;
`results/session_cases.md`). These are reported separately. The chain and lookup results
above are unchanged: `results/case_comparison.*` was byte-identical after the slice, and
the reviewed labels file was not touched.

| Group | Cases | Outcome |
| --- | --- | --- |
| Valid proof | SS01, SS11 (now + ε just before expiry) | `SessionAccept` |
| Copied G without proof / wrong key | SS02 / SS03, SS04 | `MissingProof` / `InvalidProofSignature` |
| Replay, sequential and concurrent | SS05 / SS22 | second use `ChallengeAlreadyConsumed`; 8 threads → `accepts=1 already_consumed=7 other=0` |
| Cross-session, cross-grant, wrong audience | SS06, SS07, SS08 | `SessionMismatch`, `GrantMismatch`, `ChallengeAudienceMismatch` |
| Expiry boundary | SS09 / SS10 | `ChallengeExpired` / `SessionIndeterminate … ClockUncertainty` |
| Challenge state unavailable / unknown | SS12 / SS13 | `SessionIndeterminate … ChallengeStateUnavailable` / `UnknownChallenge` |
| Chain recheck at redemption | SS14, SS23, SS15, SS24 | altered or revoked G → `ChainRejected(…)`; status or clock unavailable → `ChainIndeterminate(…)` |
| Reject dominates Indeterminate | SS16 | `InvalidProofSignature` despite the chain Indeterminate |
| Rebinding / cross-protocol / malformed | SS17, SS18 / SS19 | `InvalidProofSignature` / `MalformedProof` |
| No consumption on failure | SS20, SS21 | a later valid proof still gets `SessionAccept` |
| Issuance | SI01–SI04 | issued with 10:02:00Z expiry; refused for a revoked G; unavailable store; expiry clamped to 10:01:00Z |

Additional checks:
- The new `compile_fail` doctest (a `SessionAuthorization` cannot be built outside
  redemption) fails with E0451, confirmed with a scratch example.
- Changing SS01's label in a scratch copy made `session_outcomes_match_labels` fail. The
  labels file was restored and checked identical to the commit.
- SS22 gave the same tally in 200/200 repeated runs (release build).

Checks at `0123190`:
- `cargo fmt --check` clean; `clippy -D warnings` clean.
- `cargo test`: 43 passed, 0 failed (20 unit, 2 predecoded-API, 5 reviewed-case,
  7 property, 3 scope-oracle, 2 session-case, 4 doctests).
- Seeds 1 and 20261015 passed.
- Eval: 93/93 chain, 15/15 lookups, 28/28 session.

**Benchmark not rerun.** `verify()` now returns the decision from an internal helper that
also hands back the decoded chain it already built; the verification work is the same.
The session path itself has not been benchmarked.

**What s1 does not show:**
- channel binding;
- relay or phishing resistance (an attacker can relay their own session's challenge to a
  victim tester);
- proof of possession after redemption;
- K_T compromise handling;
- a distributed store's atomicity (assumed);
- RQ6 enforcement and RQ7 freshness during a session.

See [session.md §8](session.md).

## r3.1 changes

1. **Labels.** R07, R08, X07–X09, Q11 and U01–U04 are now reviewed (owner r3 review). All
   93 chain labels and 15 lookup labels are reviewed. No expected decision, stage, reason
   or probe changed; the original 88 chain labels are unchanged.
2. **Decisions Q9–Q11** are recorded in spec §10:
   - Q9: an unmatched exact key stays Indeterminate, with no equivocation inference, and
     changed content needs a new version or id.
   - Q10: the digest covers the signed payload only.
   - Q11: root rotation is deferred; v0 never accepts "any available key".
3. **Public pre-decoded API bypass (closed).**
   - *Reproduced* at `bcfe70f` by `tests/predecoded_api.rs`. Starting from the accepted
     base chain, changing only `chain.grant.body.test_scope` to `[auth_testing]` made the
     public `verify_decoded` return **Accept**, while the signed payload still said
     `[injection_testing, recon]`. Signatures and the status digest used `Signed.payload`;
     policy used `Signed.body`.
   - *Fix:* `verify_decoded` is now a private `evaluate`. `Signed<T>` and `DecodedChain`
     have private fields with read-only getters and no constructor other than decoding.
     `verify(&Bundle)` is the only public decision entry point (spec §7.5).
   - *Evidence after the fix:*
     - Two `compile_fail` doctests in `src/verifier.rs` cover the field assignment and the
       `verify_decoded` call. Compiling each snippet as a scratch example confirmed the
       intended errors, E0616 (private field) and E0599 (no such method); stable rustdoc
       does not check the error code itself.
     - A test checks that decoded bodies equal the strict decoding of their payloads.
     - The same alteration made in raw bundle bytes is
       `Reject / S / InvalidSignature{G}`.
   - *Scope:* the issue concerned the public pre-decoded API. No bypass of the raw-bundle
     `verify()` path was shown.
4. **Benchmark not rerun.** The runtime verification steps are unchanged: the same
   decode, anchor, signature, policy, binding, time and status work. Only field visibility
   changed (inlined getters) and the evaluation helper became private. The r3 results
   below still describe the current path.

## r3 changes

1. **Status bound to the exact signed object.** Before r3 the status source was keyed by
   (id, version). On the pre-r3 code (`e0b525c`) a scratch probe gave **Accept** for
   all three new status-substitution cases (X07, X08, X09). The status key is now

   ```
   StatusKey(X) = ( org_id(X), type(X), id(X), version(X), digest(X) )
   digest(X)    = SHA-256( "aisig-v0" ‖ 0x00 ‖ type(X) ‖ 0x00 ‖ payload_bytes(X) )
   ```

   `type(X)` is the TypeTag of the bundle slot; org_id, id and version come from the decoded
   payload; payload_bytes are the exact canonical bytes the signature covers. The signature
   bytes are not hashed. The status source answers only for an exact key match. Anything
   else is `Unknown`, which yields `Indeterminate / X / StatusUnknown{obj}` (existing policy).
2. **Registry record validation.** The anchor stage now rejects a returned record whose
   `org_id` differs from C_A.org_id (`RootOrgMismatch`) or whose `algorithm` is not Ed25519
   (`RootAlgorithmMismatch`), before the key, usage and status checks. These fail closed.
3. **Named lookups.** `scope_query` became `exact_node_lookup`, documented as covering one
   node only. `subtree_lookup` was added with effective-set semantics. The base grant shows
   the difference: node `/app` is InScope, while subtree `/app` is PartiallyAllowed because
   `/app/admin` and `/app/private` are excluded.

Labels for all new cases were written into docs/experiment.md and the labels file and
committed (`e54774a`) before the implementation changed.

## Checks run

r3.1 (this revision): `cargo fmt --all -- --check` clean; `cargo clippy --all-targets -- -D
warnings` clean; `cargo test` 37 passed, 0 failed (17 unit, 2 predecoded-API, 5
reviewed-case, 7 property, 3 scope-oracle, 3 doctests incl. 2 compile_fail);
`AISIG_PROPTEST_SEED=1` and `=20261015` property + oracle tests passed; eval 93/93 chain
and 15/15 lookups.

r3 (at `526a3c6`):

| Command | Outcome |
| --- | --- |
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --all-targets -- -D warnings` | no warnings |
| `cargo test --all-targets` | 32 passed, 0 failed (17 unit, 5 reviewed-case, 7 property, 3 scope-oracle) |
| `AISIG_PROPTEST_SEED=1` and `=20261015`, property + oracle tests | all passed |
| `cargo run --release --bin eval` | results below |
| `scripts/bench.sh` (N = 10 000, R = 10) | results below |

## E1/E2 — labelled cases (`results/case_comparison.md`)

| Verifier / subset | Cases | False accept | False reject | Indeterminate | R-vs-I mismatch | Exact stage+reason |
| --- | --- | --- | --- | --- | --- | --- |
| chain-aware, all | 94 | 0 | 0 | 12 | 0 | 94 |
| chain-aware, reviewed only | 94 | 0 | 0 | 12 | 0 | 94 |
| signature-only, all | 94 | 76 | 2 | 0 | 0 | n/a |
| signature-only, reviewed only | 94 | 76 | 2 | 0 | 0 | n/a |

(Every chain case is reviewed, so the "reviewed only" rows equal the "all" rows. The 94th
case, T12, is the negative-ε case added this round; the signature-only baseline false-accepts
it, 76 vs 75 before, because it ignores the clock entirely.)

- **The original 88 cases still match their existing labels exactly** (decision, stage and
  reason). A field-by-field comparison with the r2 labels file shows no change to any
  `expected`, `stage`, `reason` or `probe` value. The only changes are: six status flips to
  reviewed (owner approval), and Q01–Q10's `kind` renamed from `scope_query` to
  `exact_node_query`.
- The five chain cases added in r3 (reviewed in r3.1) match their pre-written labels: R07, R08 →
  `Reject / N / …`; X07, X08, X09 → `Indeterminate / X / StatusUnknown{G}`. The baseline
  accepts all five.
- Scope lookups: 15/15 match (Q01–Q11 exact-node, U01–U04 subtree).
- All 11 Indeterminate outputs are on cases labelled Indeterminate.
- Agreement with labels is empirical evidence about this implementation on these inputs,
  not a proof of soundness (threat-model §5).

## Property and oracle tests

- Default seed `104372539625493`; 128 cases per chain property, 512 per scope-oracle property.
- New in r3:
  - `reissued_grant_inherits_no_status`: for random valid grants, registering only the
    original G gives Accept. Changing `engagement_id` under the same id/version then gives
    `Indeterminate / X / StatusUnknown{G}`.
  - SO3: `exact_node_lookup` and `subtree_lookup` equal the enumeration oracle for random
    scopes and probes.
  - Unit tests: exact-key status (other type, other content, other org → Unknown) and the
    `/app` vs `/app/admin` lookup pair.

## E3 — CPU benchmark (current: `results/bench_20261015T201455Z.md`; earlier runs historical)

Intel Core i7-6700 @ 3.40 GHz, 8 logical cores, Linux 7.0.0-31-generic, governor
`powersave`, rustc 1.98.0, release profile, single-threaded, git `526a3c6`.
Medians across 10 runs of 10 000 timed calls; nanoseconds per call.

| Series | p50 | p95 | p99 |
| --- | --- | --- | --- |
| timer overhead (empty call) | 19 | 20 | 20 |
| signature verification ×3 | 125 886 | 179 924 | 239 191 |
| typed policy (linkage + policy) | 165 | 167 | 169 |
| status key derivation ×3 (SHA-256 + key fields) — new | 10 864 | 13 460 | 26 411 |
| status lookup ×3, precomputed exact keys | 208 | 223 | 228 |
| full chain verify (decode → status) | 251 249 | 371 344 | 464 161 |

Compared with the historical r2 run below:

- Full verification p50 rose from 230 649 to 251 249 ns (+20.6 µs, ~9%). That is
  consistent with the new ~10.9 µs key derivation plus run-to-run variance. It was not
  separated further.
- The lookup itself went from 133 to 208 ns p50 because larger keys are hashed and compared.
  It remains a few hundred ns.
- Signature and policy series are within run-to-run variation of r2.
- Limits: `powersave` governor, no core pinning, one machine. Timer overhead differed
  between the two runs (19 vs 38 ns p50), which shows the noise level for sub-µs series.
  The status series measure an in-memory HashMap only and say nothing about RQ7.

### Historical (r2, before exact-object status keys)

`results/bench_20261014T183348Z.md`, git `9412502`, same machine and settings. Status was
keyed by (id, version) only, so these timings do not reflect the current status stage.

| Series | p50 | p95 | p99 |
| --- | --- | --- | --- |
| timer overhead | 38 | 48 | 54 |
| signature verification ×3 | 126 870 | 180 804 | 236 236 |
| typed policy | 169 | 173 | 180 |
| status lookup ×3 (id, version keys) | 133 | 150 | 212 |
| full chain verify | 230 649 | 355 817 | 438 477 |

## RQ6 enforcement slice e2 (separate from the chain/lookup/session results)

Spec [enforcement.md](enforcement.md); labels `tests/cases/enforcement_cases.toml`
(EE01–EE26 reviewed, EE27 proposed), written before the implementation. Implemented in
`src/enforcement.rs`; results in `results/enforcement_cases.md`.

**Result: 27/27 enforcement labels match** (4 Allow, 20 Deny, 3 Indeterminate). Reported
separately; the chain (93/93), lookup (15/15) and session (29/29) results are unchanged and
`results/case_comparison.*` and `results/session_cases.*` were not altered by this slice.

- The agent's `claimed_class` never changes the outcome (EE12: a `recon` claim on a
  `db.write` is still denied as `data_modification`).
- Scope precedes class: an excluded or out-of-scope target is denied before any class check
  (EE05–EE09); EE23 shows a recon-only grant denied at class for `web.get`.
- EE27 shows a `PartiallyAllowed` subtree with **no explicit exclusion** (grant targets only
  `.../billing`, so `cluster1/main` is part-in/part-out) denied as
  `DenySubtreePartiallyAllowed`.
- Target validation (EE25) rejects a non-canonical target at the validate stage; combined
  with the `compile_fail` doctest (a `MediationRequest` has no `AssetRef` field, E0560), a
  pre-built non-canonical `AssetRef` cannot enter mediation.
- Chain is re-verified each action: EE22 (altered grant) and EE26 (revoked before mediation)
  deny at the chain stage; EE18 denies a grant-ref mismatch.
- Evidence outages are Indeterminate, never Allow, and never append an effect: EE19 (session
  store), EE20 (status source), EE21 (clock).
- The effect sink grows by exactly 1 on each Allow and by 0 on every Deny/Indeterminate
  (checked by measuring sink growth; `only_allow_performs_an_effect`).

Checks at this slice: `cargo fmt --check` clean; `clippy -D warnings` clean; `cargo test`
all pass (incl. 5 doctests, 3 of them `compile_fail`); both extra proptest seeds pass; eval
reports 93/93, 15/15, 29/29, 27/27. Passing the earlier chain/session tests is **not**
offered as evidence for RQ6 — the RQ6 result is the 27/27 enforcement match above.

Not claimed: live tool enforcement, interception of real processes/network, confinement of
unmanaged tools, a complete effect taxonomy, or RQ7 status-source freshness.

## Review round 2 (2026-10-16): clock and sink boundary fixes

Three defects found by review of commit `36e2875`, each reproduced before the fix
(commit `8cbd104`) and reported here reproduction-then-fixed.

| # | Defect (reproduction result at `8cbd104`) | Fixed result |
| --- | --- | --- |
| 1a | RQ6 read the clock a 3rd time at perform; a `None` there **panicked** | One snapshot per mediation; no perform read → no panic (`perform_does_not_reread_clock_no_panic`) |
| 1b | With a later reading at perform, the receipt was stamped stale: `performed_at=2026-10-15T23:00:00Z` | `performed_at` is the decision snapshot `10:30:00Z` (`performed_at_is_the_decision_snapshot_not_a_later_read`) |
| 2 | `EffectSink::record` was public: an external caller grew the sink with a cloned receipt (1 → 2) | Append is module-private; external code has read-only `len`/`receipts`; `compile_fail` doctest (E0624) and `external_caller_cannot_append_a_cloned_receipt` |
| 3a | RQ5 issuance before `window.start` **issued** a challenge dated before the grant (`expires_at=…T08:02:00Z`) | `IssueUnavailable / InvalidClockReading` (SI06) |
| 3b | RQ5 issuance with a **negative** uncertainty was silently accepted (`Issued`) | `IssueUnavailable / InvalidClockReading` (SI07) |

Fixes: the RQ6 mediator reads the clock once (stage 3) and reuses that snapshot for the
expiry check, the chain-time verification (run against a frozen clock), and `performed_at`;
`EffectSink` is a concrete type whose append only `perform` can call. RQ5 `issue` validates
the issuance reading against `[G.window.start, G.window.end)`, canonical representability,
and non-negative uncertainty, rejecting (never clamping) an invalid reading.

New labels: SI06, SI07 (proposed), each `IssueUnavailable / InvalidClockReading`. Status
flips to reviewed: SI05, EE27. No expected value of any previously-reviewed case changed
(verified by diffing the label files against `36e2875`): the 93 chain, 15 lookup, the
original 28 session and 26 RQ6 outcomes are unchanged. Post-fix eval: 93/93, 15/15,
session 31/31 (29 reviewed + SI06/SI07 proposed), RQ6 27/27. *(Round-2 snapshot; superseded
by the round-3 counts below.)*

## Review round 3 (2026-10-16): reject negative clock uncertainty

A follow-up review found that `issue()` rejected a negative `ClockReading.epsilon`, but
`ChainVerifier::verify`, `SessionService::redeem` and `Mediator::mediate` still clamped it
with `epsilon.max(0)`. Since spec §6 requires ε ≥ 0 and `ClockReading` has public fields, an
invalid reading could still reach Accept / SessionAccept / Allow. Reproduced before the fix
(commit `94185e2`), reported reproduction-then-fixed.

| Case | Reproduction at `94185e2` (pre-fix) | Fixed result |
| --- | --- | --- |
| T12 (chain, ε=−5) | **Accept** | `Indeterminate / T / InvalidClockReading` |
| SI08 (issuance, ε=−5 on the chain-check read, valid issuance read) | **Issued …T10:02:00Z** | `IssueRefused / Indeterminate / T / InvalidClockReading` |
| SS25 (redeem ε=−5, then valid retry) | **SessionAccept ; SessionReject/…/ChallengeAlreadyConsumed** (invalid attempt accepted *and* consumed) | `SessionIndeterminate / chain / ChainIndeterminate(Indeterminate / T / InvalidClockReading) ; SessionAccept` |
| EE28 (mediate ε=−5) | **Allow effects=1** | `Indeterminate / expiry / InvalidClockReading effects=0` |

Fix: all three time paths reject a negative ε (new `InvalidClockReading` outcome) instead
of clamping; `time_check` now assumes ε ≥ 0 and saturates for overflow. The mediator's
single snapshot and private sink are unchanged. New proposed labels T12, SS25, SI08, EE28
(and SI06/SI07 from round 2). No previously-reviewed expected value changed (verified by
diffing the label files against `b40ef85`).

**Post-fix counts (reported separately):** chain 94/94 (all reviewed), lookup 15/15,
session 33/33 (all reviewed), enforcement 28/28 (all reviewed). T12, SI06, SI07, SI08, SS25
and EE28 were owner-reviewed in the follow-up cleanup; SS26 (redemption-time guard,
distinct from SS25) was added there and remains proposed. fmt/clippy clean; all tests incl.
doctests pass; both extra proptest seeds pass.

**Benchmark rerun** (`results/bench_20261015T201455Z.md`, git `21487fc`, same machine,
`powersave` governor): medians p50 — full chain verify ≈243 µs, signature ×3 ≈132 µs, typed
policy ≈172 ns, status-key ×3 ≈11.1 µs, status lookup ≈209 ns — within run-to-run variance
of the round-2 run; the added negative-ε comparison is not separately measurable. Earlier
runs are marked historical in results/README.md.

## Remaining open items

- Q9–Q12 are decided (spec §10). Their follow-ups are future work:
  - an evidenced *conflict* result from an authoritative, complete status service (Q9);
  - root rotation with explicit record versions, validity and retirement (Q11).
- As of the round-3 cleanup, no proposed labels remain: chain 94, lookup 15, session 34,
  enforcement 28 are all owner-reviewed.
- RQ5 s1 (34 labels) is owner-reviewed. RQ5 channel binding, relay resistance and
  per-request PoP remain open.
- RQ6 e2 is implemented for synthetic operations; all 28 labels reviewed. Live tool
  enforcement is not claimed.
- RQ7 (status-source freshness / bounded revocation delay): slice f2 is implemented behind a
  separate freshness-slice runner ([freshness.md](freshness.md); `src/freshness.rs`). All 34
  labels are owner-`reviewed` and matched by the implementation (`results/freshness_cases.md`),
  with a `cargo test` gate and a nonzero `eval` exit on any mismatch. The HWM seeding seams are
  crate-internal (`pub(crate)`), so an external holder of a `&HwmStore` cannot clear a sticky
  revocation. The bounded-revocation-delay figure stays a conjecture (§6, withdrawn as a claim).
- RQ5 issuance now rejects inconsistent clock readings (SI05 reviewed; SI06/SI07 proposed).
- Round 3: all time paths reject a negative ε (never clamp). New proposed labels T12,
  SS25, SI08, EE28 await owner review.
