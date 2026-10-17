# RQ8 — privacy, latency and onboarding cost

**Status:** DRAFT, 2026-10-17. **Q1 slice 1 (privacy: field disclosure + linkability) is
implemented synthetically with 16 owner-`reviewed` observations; Q2 slice 1 (latency) adds a
rerun CPU benchmark plus 6 `reviewed` modeled responder-delay scenarios (real end-to-end
latency stays unmeasured); Q3 slice 1 adds a per-party step inventory (critical path open) and
measured bundle-slot artifact byte sizes (17 `reviewed`), with human/monetary/storage cost left
to a real deployment.** This
document defines the *questions* and
*measurement methods* so that any RQ8 result is produced against a method fixed in advance.
Where the existing synthetic prototype can support a method it is stated; where a real
deployment is required it is stated. **The only numbers asserted are a local CPU benchmark
(wall-clock, this machine) and deterministic synthetic/modeled byte-size and scenario values;
no real-deployment latency, privacy, or cost number is asserted.** The Q1 observations are
structural facts about this synthetic encoding (which top-level field
names appear, and which fields are byte-equal across showings), **not** a complete analysis of
nested values or envelopes and **not** a real-world leakage or privacy guarantee.

Scope note: RQ1 (organization identity) and RQ2 (asset binding) are assumed trusted fixtures;
RQ4 (chain), RQ5 (session), RQ6 (mediation) and RQ7 (status freshness) are implemented
synthetically (see [spec.md](spec.md), [session.md](session.md), [enforcement.md](enforcement.md),
[freshness.md](freshness.md)). RQ8 asks what those mechanisms *cost* and *leak*, and what it
takes to *adopt* them. It is three distinct questions; they are not combined into a single
score.

Everything the prototype can measure is on synthetic data only: synthetic organizations,
test-only keys, `.test` hosts (RFC 6761), in-memory registry/binding/clock/status fixtures, and
a modeled status responder. Nothing contacts a real CA, OCSP/CRL endpoint, target or network.

---

## Q1 — Privacy leakage, with an explicit observer/threat model

**Question.** What does an adversary *learn* from the authorization-chain mechanism itself —
from the signed objects, the status-responder exchange, the session challenge/response, and the
mediation records — beyond what the engagement already discloses? Privacy here is about the
*metadata of authorization*, not the confidentiality of the tested target.

**Observers to define before measuring (each a distinct threat).**
- **O1 — a holder of a bundle** (e.g. the tester, or anyone a grant is shown to): sees the full
  chain `K_O → C_A → D_U → G` and every field in it.
- **O2 — the provider P:** sees the bundle, the session exchange and every mediation request.
- **O3 — the status responder R:** sees each `StatusKey` P queries and when (query pattern), but
  not P's `now`/`ε` (R never receives them; freshness.md §2).
- **O4 — a network/path observer** of a *real* deployment: sees timing, size and endpoint
  metadata of status queries and session/mediation traffic. **Not modeled** (no network here).
- **O5 — a reader of P's effect sink:** sees the modeled `EffectReceipt`s. (Decision logs /
  findings are not modeled or measured in this slice; O5 covers the effect-receipt data only.)

**What to characterize (leakage surfaces), per observer.**
- Field-level disclosure in `C_A`/`D_U`/`G`: org id, admin/issuer/tester key ids, asset scope
  (hosts, DB schemas), windows, test-scope classes, engagement id, constraints. A canonical,
  deterministic encoding (spec §3) means byte-identical objects are linkable across showings.
- **Linkability / correlation:** stable key ids and the exact-object `StatusKey` (digest of the
  signed bytes) let O2/O3 correlate repeated use of the same `C_A`/`D_U`/`G` over time; R learns
  which objects P relies on and the cadence of P's checks.
- **Status-query leakage (O3):** querying by exact `StatusKey` tells R precisely which object is
  being evaluated; query timing may reveal engagement activity.
- **Session/mediation leakage (O2, O5):** challenge/response ties a tester key to a session;
  mediation receipts record operation, target, class and time.

**Measurable methods.**
- *Field inventory (synthetic; implemented, `rq8_privacy.rs`):* enumerate, per observer, the
  artifacts received and the fields each discloses, from the actual canonical signed bytes / wire
  forms (and, for the effect receipt, its struct fields). A structural audit, not a number —
  reported as a disclosure table. No network.
- *Linkability comparison (synthetic; implemented, `rq8_privacy.rs`):* a deterministic comparison
  of a repeated identical signed grant versus a legitimately reissued grant, reporting equality of
  signed bytes, key ids and exact `StatusKey` **separately** to show which fields correlate across
  showings. Uses the existing fixture; no network.
- *Query-pattern leakage (synthetic model; feasible as an extension):* from the status-stage call
  sequence (which `StatusKey`s, in what order) the prototype could report what R observes in
  principle; the *real* timing/size signal (O4) needs a deployment.

**Support level.**
- Measured now: the field inventory and the linkability comparison (`rq8_privacy.rs`,
  `results/rq8_privacy.md`).
- Requires a real deployment: O4 (network/traffic analysis — timing, size, endpoint
  correlation), any claim about an actual responder protocol's metadata, and any adversary with
  side channels.

**Open decisions (record; do not pre-judge).**
- Whether to blind the status query (e.g. a privacy-preserving status check) vs the current
  exact-`StatusKey` lookup — a tradeoff against RQ7's exact-object guarantee.
- Whether key ids / digests should be salted or rotated per showing to reduce O1–O3
  linkability, and the cost to RQ1 pinning and RQ7 stickiness.
- What, if anything, in `EffectReceipt`s should be minimized for O5.

---

## Q2 — CPU cost vs end-to-end latency (including the status source)

**Question.** Two different quantities must not be conflated: (a) the **CPU work** of a decision
on one machine, and (b) the **end-to-end latency** a tester/provider experiences in a real
deployment. An open question to *measure* (not assume): **what fraction of end-to-end latency
is the status-source round-trip and network versus P's CPU decision, across cache hit/miss and
across a stapled-token vs live-responder design?** This prototype has not measured end-to-end
latency, so no claim is made about which component dominates.

**What to measure.**
- *CPU, per stage (already measured by existing code).* `src/bin/bench.rs` already times,
  separately and with warmup + N iterations + R repeated runs, reporting p50/p95/p99:
  `signature_x3` (Ed25519 verify of C_A, D_U, G), `typed_policy` (linkage + policy),
  `status_key_x3`, `status_lookup_x3` (simulated in-memory lookup), and `full_chain_verify`
  (the whole `verify(&Bundle)`, format→status). `scripts/bench.sh` records rustc/cargo versions,
  CPU model (`/proc/cpuinfo`), kernel, build profile and seeds, so a CPU result is reproducible;
  the HEAD rerun for this slice is `results/bench_20261017T025341Z.{md,json}` (prior runs are
  marked historical in `results/README.md`). This is **wall-clock elapsed of a tight loop** —
  CPU-focused, but not process CPU time (`getrusage`); it measures (a) only, and only the
  synthetic, in-memory status path.
- *Responder-delay scenarios (modeled; implemented as Q2 slice 1).* Deterministic responder-delay
  values computed from **explicitly assumed** inputs (query count, cache hit/miss, serial vs
  parallel, an assumed per-query RTT). No `sleep`, no timing, no network — pure arithmetic over
  the assumptions, clearly labeled modeled, never a measured RTT.
- *End-to-end latency (requires a real deployment).* The real components are: client→P, P→R
  status query (network + R compute + R's own freshness/caching), P's CPU decision, and the
  session/mediation round-trips. Any concrete end-to-end number needs a real responder and
  network and is out of scope for this synthetic prototype.

**Method (fixed in advance).**
- Keep **three quantities visibly separate** and never conflate them:
  1. **Measured** local per-call elapsed time from the `Instant` benchmark (`bench.rs`). This is
     wall-clock elapsed of a tight loop — CPU-focused, but **not** process CPU time
     (`getrusage`); it includes scheduler/measurement overhead. Reported as p50/p95/p99 per
     stage in `results/bench_<UTC>.{md,json}` with recorded environment.
  2. **Modeled** responder-delay scenarios — deterministic, from assumed inputs (below). Modeled,
     not measured; gated observations (owner-reviewed).
  3. **Unmeasured** real end-to-end network latency — stated, never computed here.
- Never present a CPU microbenchmark as an end-to-end latency, and never present a modeled delay
  as a measured RTT.
- `full_chain_verify` is the measured whole-decision time; the per-stage times (`signature_x3`,
  `typed_policy`, `status_*`) are **not** summed as though they equal it (measurement overhead
  and non-additivity make the sum only a rough decomposition).

### Q2 measurement slice 1 — modeled responder-delay scenarios (method)

Assumptions, fixed before computing (all **assumed**, not measured):
- **Query count `Q = 3`:** one status query per chain object (C_A, D_U, G).
- **Cache hit/miss:** a cache hit is served locally (0 RTT); a miss costs one responder
  round-trip of an **assumed** latency `rtt_ms` (default `50`, a placeholder, not a measurement).
- **Serial vs parallel:** serial issues misses one after another; parallel issues them at once.
- **Stapled variant:** an owner-signed freshness token carried in the bundle (freshness.md §10
  Q1) makes `Q = 0` — no responder round-trip.

Formula (the gated observation, deterministic):
```
responder_delay_ms = 0                         if queries == 0            (stapled)
                   = misses * rtt_ms           if mode == serial
                   = (misses > 0 ? rtt_ms : 0) if mode == parallel
```
The three quantities are **not added into a single total**: the modeled responder delay
(quantity 2) and the real network latency (quantity 3) overlap — a real RTT already includes
network time — so summing them would double-count, and neither is a measured RTT. Only the
modeled `responder_delay` is gated; the measured CPU is reported separately in the bench results
(it is machine- and run-dependent and is not baked into a gated label). **Parallel status
queries and the stapled-token variant are hypothetical scenarios, not implemented verifier
paths:** the verifier issues its status checks serially over an in-memory fixture and v0 has no
stapled-token path. Scenarios QL01–QL06 are in `tests/cases/rq8_latency_cases.toml` (gated in
`cargo test` and `eval`). **`QL06 = 0` means zero modeled responder-query delay (no round-trip),
not zero token-verification cost** — verifying a stapled token would still cost CPU (quantity 1),
unmeasured here.

**Open decisions (record).**
- Whether the status source is stapled (owner-signed token carried in the bundle, no round-trip;
  freshness.md §10 Q1) or a live responder — this changes end-to-end latency fundamentally.
- Target `F` (freshness bound) and `response_expires_at` lifetimes, which trade staleness
  against query rate and thus against both latency and O3 leakage.
- Whether to report CPU in absolute time or in operations (e.g. Ed25519 verifies), which is more
  portable across machines.

---

## Q3 — Onboarding steps and operational cost

**Question.** What must each party *do once* to join (onboarding) and *keep doing* (operation),
and what does that cost? This is a process/cost question, not a latency question.

**Parties and their steps (to enumerate, not yet price).**
- **Organization O:** generate a root key `K_O`; get it pinned by each provider P
  (out-of-band, RQ1-assumed); issue `C_A` to its admin; manage admin delegation lifecycle
  (rotation, revocation).
- **Provider P:** pin each org root (the RQ1 trust decision — manual review in the prototype,
  `evidence_ref` records it); run the verifier; operate or reach a status responder R and pin its
  `K_R` per org (RQ7); operate the session and mediation services; retain logs/effect receipts.
- **Tester T:** hold `K_T`; receive a grant `G` from the issuer `D_U`; perform the session
  challenge/response (RQ5) to bind possession.
- **Status responder R:** be provisioned per org; sign status responses with `K_R` (**on
  publication/update of a status, not necessarily once per verifier action** — P may reuse a
  cached response within its freshness window); maintain the epoch/known-at/expiry discipline
  (RQ7).

**Cost dimensions (define before pricing).**
- One-time: key generation, out-of-band pinning exchanges (O↔P, R-key↔P), initial delegation
  issuance.
- Recurring: delegation/grant issuance per engagement, status responses served, revocation
  propagation, key rotation, log/receipt retention.
- Failure/edge: handling `Indeterminate` outcomes (registry/clock/status unavailable),
  revocation handling, restart of the in-memory high-water-mark (freshness.md §4 limitation).

**Measurable methods.**
- *Per-party step inventory (supported now, structurally):* enumerate each party's steps,
  tagging **fixture-generated** (implemented), **assumed out-of-band** provisioning/pinning, or
  **design-only**, and the cadence. This is a per-party inventory, not a cost figure and **not a
  critical-path analysis** — dependency ordering and durations are left open.
- *Artifact byte sizes (supported now):* measure the canonical byte sizes of the **bundle slot**
  artifacts (`root`, `C_A`, `D_U`, `G`) from actual fixture bytes. Status-response and
  challenge/proof sizes are **not** measured in slice 1 (see below).
- *Operational cost (requires real deployment):* human time, responder running cost, revocation
  SLAs, retention/storage cost — deployment facts, not inferred here.

**Synthetic vs real deployment.**
- Supported now: the per-party step inventory and the bundle-slot canonical byte sizes.
- Requires real deployment: monetary/person-time cost, pinning/review effort, operating cost,
  transport framing, retransmission, and the critical-path durations.

### Q3 measurement slice 1 — step inventory and artifact byte sizes (method)

Two kinds of observation, kept distinct and gated in `tests/cases/rq8_onboarding_cases.toml`
(owner-reviewed). **No human time, monetary cost, storage bill, or operational effort is
inferred from byte sizes or step counts** — those are deployment facts (above).

**Per-party step inventory (structural model, not a measurement; not yet a critical path).**
Each step is tagged `implemented` (**fixture-generated / synthetic** — the prototype derives keys
and signs; this is *not* real provisioning), `assumed-oob` (real out-of-band provisioning or
RQ1/RQ2 pinning the prototype assumes), or `design-only` (described, not implemented), and by
cadence. The runner holds this inventory as data and emits per-party counts (`OS-O/A/U/T/P/R`),
so the gate catches drift between the code's inventory and this table; the counts are a model,
not a measured quantity. **Dependency ordering and step durations (the actual critical path) are
left open; no duration is inferred from step counts.** The delegation chain's issuing roles are
modeled explicitly: `A` = admin (`K_admin`, issues `D_U`), `U` = issuer/authorizer
(`K_authorizer`, issues `G`).

| Party | Step | Tag | Cadence |
| --- | --- | --- | --- |
| O | generate root key `K_O` | implemented | one-time |
| O | issue admin delegation `C_A` (sign `K_O`) | implemented | one-time |
| O | get `K_O` pinned at P | assumed-oob (RQ1) | one-time |
| O | rotate / retire root | design-only | lifecycle |
| A | hold admin key `K_admin` | implemented | one-time |
| A | issue issuer delegation `D_U` (sign `K_admin`) | implemented | one-time |
| U | hold issuer key `K_authorizer` | implemented | one-time |
| U | issue grant `G` (sign `K_authorizer`) | implemented | per-engagement |
| T | hold tester key `K_T` | implemented | one-time |
| T | receive grant `G` (delivery) | assumed-oob | per-engagement |
| T | respond to the session challenge | implemented | per-session |
| P | pin org root `K_O` (trust decision) | assumed-oob (RQ1) | one-time/org |
| P | pin responder key `K_R` | assumed-oob (RQ7) | one-time/org |
| P | rely on asset-binding evidence | assumed-oob (RQ2) | one-time/asset |
| P | verify the chain (`ValidChain_P`) | implemented | per-action |
| P | query status / freshness | implemented | per-action |
| P | issue + redeem a session | implemented | per-session |
| P | mediate an action | implemented | per-action |
| R | be provisioned / hold `K_R` | assumed-oob | one-time/org |
| R | sign status responses | implemented | per-publication/update |
| R | keep epoch/known-at/expiry discipline | implemented | per-action |

Per-party counts gated (`implemented` / `assumed-oob` / `design-only`): O = 2/1/1, A = 2/0/0,
U = 2/0/0, T = 2/1/0, P = 4/3/0, R = 2/1/0.

**Artifact byte sizes (measured from actual fixture bytes; bundle slots only).** Each `OB*`
states exactly which count it is:
- *signed payload* = the canonical JSON bytes carried in the signature's input
  (`chain.X().payload()`). The signature actually covers the **domain-separated bytes**
  `"aisig-v0" ‖ 0x00 ‖ TypeTag ‖ 0x00 ‖ payload`, which contain but are larger than the payload.
- *signature* = the raw Ed25519 signature, always 64 bytes.
- *full envelope* = the canonical `EnvelopeWire` for one slot (base64 payload + base64 sig +
  type + key_id) — the on-the-wire object. Larger than its signed payload (base64 + wrapper).
- *in-memory* = a Rust struct, not a wire object. **`OB11` reports only the in-memory
  bundle-slot byte size** carried inside a `MediationRequest` (the sum of its four slot
  envelopes). It makes **no transmission-cost claim**: there is no request wire encoding or
  transport here, and a repeated request could incur those bytes again.
- **`OB10`** is the sum of the **four slot envelopes of this fixture, including the optional
  `root` slot** (the verifier ignores `root`, but a holder/P still receive its bytes). It
  **excludes** any enclosing request format, transport framing, and retransmissions, and is
  **not** the sum of the signed payloads (payloads are a subset of envelope bytes; payload and
  envelope sizes are never added).

**Not measured in slice 1:** status-response, challenge and proof byte sizes (Q1 FD covers their
field *names*, not sizes; sizes are future work), transport/wire framing, retransmission cost,
and all human/monetary/storage/operational cost.

**Open decisions (record).**
- Degree of automation vs manual review for RQ1 pinning (the `evidence_ref` process) and its
  effect on onboarding cost and trust.
- Single responder per org (RQ7 v0) vs alternatives (stapled token, multiple responders) and
  their onboarding/operational tradeoffs.
- Key-rotation and root-retirement procedure (spec open item Q11) and its recurring cost.

---

## Q1 measurement slice 1 — field disclosure and linkability (method)

The first implemented RQ8 slice. Method and expected
observations are fixed in `tests/cases/rq8_privacy_cases.toml` **before** the runner; the runner
(`src/experiment/rq8_privacy.rs`, reported in `results/rq8_privacy.md`) extracts the *actual*
field sets and comparisons and must match. All 16 observations are owner-`reviewed`. No
real-world privacy guarantee is inferred; synthetic only, no network, no real data.

**Fixture.** The base synthetic fixture (experiment.md §2): org `org-acme-synthetic`, test-only
keys, `.test` hosts. Artifacts inspected: the four built-bundle slots — `root`, `C_A`, `D_U`,
`G` — read from their signed payload bytes (the three chain objects via the decoded chain; the
ignored-but-present `root` slot by base64-decoding its envelope); the R-signed status response
and the `StatusKey` query; the session challenge and proof; one effect receipt from a real
mediation Allow; and the `MediationRequest` P receives (an in-memory struct, not a wire object).

**Field-disclosure inventory (FD01–FD10, PO1/PO2/PO3/PO5).** For each artifact, report the
sorted **top-level** field names (what any receiver of that artifact learns). This is
deliberately a names-only inventory: it does **not** recurse into nested values (e.g. the
contents of `bounds`, `envelope`, `targets`, `test_scope`, `validity`, or the `status_key`
sub-object beyond FD05), does not analyse the envelope around a signed payload, and is not a
real-world leakage analysis. FD01–FD03 (`C_A`/`D_U`/`G`) and FD09 (`root`) are raw signed
bundle payloads; FD10 (`mediation_request`) is an in-memory request struct (its `bundle` field
carries the raw bundle bytes already inventoried). The PO observer→artifact sets are derived
from an executed synthetic flow (below). For each observer, which artifacts it *actually
receives*:
- **O1** (bundle holder): the bundle slots — `root`, `admin`, `issuer`, `grant` (the verifier
  ignores `root`, but a holder sees its bytes).
- **O2** (provider P): the bundle (incl. `root`), the R-signed status response, the session
  exchange (challenge, proof), and the `mediation_request` it receives.
- **O3** (responder R): only the `StatusKey` query (`org_id`, `object_type`, `id`, `version`,
  `digest`); the model **assumes** R never receives P's `now`/`ε` (freshness.md §2) — an
  assumption, not a measurement.
- **O5** (effect-sink reader): the effect receipts (modeled effect data only; decision logs are
  not modeled or measured).
- **O4** (network/traffic metadata) remains **unmeasured** (no network here).

**Linkability comparison (PL01, PL02).** Deterministic, no population sampling. Each grant is
**built and verified** (chain `Accept`); the comparison uses the exact payload bytes covered by
the signature. `issuer_key_id` is the signed key id; `tester_key_id` is derived as
`keyid(tester_key)` (SHA-256 of the raw public key, not the raw key value). The `StatusKey` is
compared **component-by-component** (`org_id`, `object_type`, `id`, `version`, `digest`), so a
`digest` difference is never mistaken for an absence of correlation.
- *PL01 — identical grant presented twice:* the same signed `G`; everything equal.
- *PL02 — legitimately reissued grant (spec §6 issuance rule):* the same parties re-issue `G`
  for a **new engagement** (`engagement_id`) under a **new `version`** (a new `version` or `id`
  is required; re-signing different content under the same `(org, type, id, version)` is
  unsupported — spec §6). Report `signed_bytes`, `issuer_key_id`, `tester_key_id` and each
  `StatusKey` component separately. (`engagement_id` is signed content, not a `StatusKey`
  component or key id, so the reported equalities are the same as a version-only reissue.)

This shows that across a legitimate reissue the signed bytes, the grant `version` and the
`StatusKey` `digest` differ, while the stable correlators — `issuer_key_id`, `tester_key_id`,
and the `StatusKey` `org_id`, `object_type` and `id` — remain equal. It is an observation about
this synthetic encoding, not a privacy guarantee.

**Gate.** Exact matches are gated in `cargo test` (an integration test one-to-one with the
runner) and `eval` exits nonzero on any mismatch. The 16 observations are owner-`reviewed`.

## Measurement-support summary

Support levels: **measured** = produced by code from real observation (e.g. the `Instant`
benchmark); **modeled** = produced by code from explicitly assumed inputs, deterministic and not
a measurement; **extension** = feasible after a synthetic (no-network) code extension, not
implemented yet; **deployment** = requires a real deployment and is out of scope here.

| Method | Support level | Where / note |
| --- | --- | --- |
| Q1 field-disclosure inventory (per observer) | measured | `rq8_privacy.rs` (`results/rq8_privacy.md`), FD01–FD10 + PO1/PO2/PO3/PO5 |
| Q1 linkability comparison (identical vs reissued) | measured | `rq8_privacy.rs`, PL01/PL02 |
| Q1 network/traffic metadata (O4) | deployment | no network modeled |
| Q2 per-stage CPU (sig / policy / status), p50/p95/p99 | measured | `bench.rs`: `signature_x3`, `typed_policy`, `status_key_x3`, `status_lookup_x3` (HEAD rerun `results/bench_20261017T025341Z.md`) |
| Q2 whole-`ValidChain_P` CPU | measured | `bench.rs`: `full_chain_verify` (same rerun) |
| Q2 responder-delay scenarios (modeled) | modeled (implemented) | `rq8_latency.rs`, QL01–QL06: deterministic over an **assumed** rtt, not a measured RTT |
| Q2 end-to-end latency (real R + network) | deployment | real responder + network RTT, cache, load |
| Q3 per-party step inventory (critical path open) | modeled (implemented) | `rq8_onboarding.rs`, OS-O/A/U/T/P/R: per-party step counts from the inventory held as data |
| Q3 canonical artifact byte sizes (bundle slots) | measured | `rq8_onboarding.rs`, OB01–OB11: from the actual fixture bytes |
| Q3 person-time / monetary / operating / storage cost | deployment | not inferred from bytes or step counts |

## Non-goals and no-claim statement

- Q1 slice 1 (field disclosure + linkability), Q2 slice 1 (CPU benchmark + modeled
  responder-delay scenarios) and Q3 slice 1 (per-party step inventory + measured bundle-slot
  byte sizes) are implemented, all owner-reviewed. No human time, monetary cost, storage bill,
  or operational effort is inferred from bytes or step counts — those remain real-deployment
  facts.
- The Q1 observations are structural facts about this synthetic encoding (field names present,
  and which fields are byte-equal across showings). They are **not** a real-world privacy
  guarantee, and no privacy *number* over a real population is asserted. O4 network metadata is
  unmeasured.
- Q2 keeps three quantities separate: the **measured** CPU elapsed (bench, wall-clock, not
  process CPU time), the **modeled** responder-delay scenarios (deterministic over an assumed
  rtt, never a measured RTT), and the **unmeasured** real end-to-end network latency. No
  end-to-end or latency number over a real deployment is asserted, and the modeled delay is
  never presented as a measured RTT.
- Each of Q1/Q2/Q3 is reported on its own axis; they are not reduced to a single score.
- Every reported CPU number cites the recorded environment and exact commit; every synthetic
  byte-size or modeled value distinguishes what is measured here from what a real deployment
  would add (transport framing, retransmissions, real RTT, human/monetary/storage cost).
