# Prototype report — RQ4 chain verifier (r3.1)

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
| RQ5 tester/session binding | **Unresolved.** `tester_key` is signed but never challenged (non-case K01). |
| RQ6 enforcement of agent actions | **Unresolved.** `exact_node_lookup` and `subtree_lookup` are lookups; TestClass→action mapping undefined. |
| RQ7 revocation freshness | **Unresolved.** Status is an instant, always-current in-memory fixture, now keyed by exact object (r3). |
| RQ8 privacy / latency / onboarding | Only single-machine CPU latency measured. |

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
| chain-aware, all | 93 | 0 | 0 | 11 | 0 | 93 |
| chain-aware, reviewed only | 93 | 0 | 0 | 11 | 0 | 93 |
| signature-only, all | 93 | 75 | 2 | 0 | 0 | n/a |
| signature-only, reviewed only | 93 | 75 | 2 | 0 | 0 | n/a |

(As of r3.1 every case is reviewed, so the "reviewed only" rows equal the "all" rows.
At r3 they covered 88 cases: chain-aware 0/0/8, signature-only 70 FA / 2 FR.)

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

## E3 — CPU benchmark (current: `results/bench_20261014T192333Z.md`)

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

## Remaining open items

- Q9–Q12 are decided (spec §10). Their follow-ups are future work:
  - an evidenced *conflict* result from an authoritative, complete status service (Q9);
  - root rotation with explicit record versions, validity and retirement (Q11).
- No proposed labels remain.
- RQ5, RQ6 and RQ7 remain unresolved as listed above.
