# RQ8 — privacy, latency and onboarding cost

**Status:** DRAFT, 2026-10-17. **Q1 slice 1 (privacy: field disclosure + linkability) is
implemented synthetically with 14 `proposed` observations awaiting owner review; Q2 (latency)
and Q3 (onboarding/cost) remain design only.** This document defines the *questions* and
*measurement methods* so that any RQ8 result is produced against a method fixed in advance.
Where the existing synthetic prototype can support a method it is stated; where a real
deployment is required it is stated. **No performance, privacy or cost *number* is asserted:**
the Q1 observations are structural facts about this synthetic encoding (which top-level field
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
- **O5 — a reader of P's logs / effect sink:** sees `EffectReceipt`s and decision findings.

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
  CPU model (`/proc/cpuinfo`), kernel, build profile and seeds, so a CPU result is reproducible.
  This measures (a) only, and only the synthetic, in-memory status path.
- *Responder-delay sensitivity (feasible after a synthetic extension).* A *configurable* modeled
  responder delay, to show how a nonzero status-source latency would shift the decomposition.
  **Not implemented yet;** when added it is clearly labeled modeled, not measured, and injects no
  real network.
- *End-to-end latency (requires a real deployment).* The real components are: client→P, P→R
  status query (network + R compute + R's own freshness/caching), P's CPU decision, and the
  session/mediation round-trips. Any concrete end-to-end number needs a real responder and
  network and is out of scope for this synthetic prototype.

**Method (fixed in advance).**
- Separate the two axes explicitly in any report: "CPU per stage (this machine)" vs "end-to-end
  (deployment)". Never present a CPU microbenchmark as an end-to-end latency.
- For CPU: warmup, fixed iteration/repeat counts, fixed RNG seed, recorded environment; report
  p50/p95/p99 per stage; attribute cost to signature verification vs policy vs status.
- For end-to-end: define the components (client RTT, P→R RTT, R compute, cache hit/miss, P CPU,
  session/mediation RTTs) and measure each in the real deployment; the synthetic prototype can
  at most provide the P-CPU component and a *modeled* (not measured) responder-delay sensitivity.

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
- **Status responder R:** be provisioned per org; sign status responses with `K_R`; maintain the
  epoch/known-at/expiry discipline (RQ7).

**Cost dimensions (define before pricing).**
- One-time: key generation, out-of-band pinning exchanges (O↔P, R-key↔P), initial delegation
  issuance.
- Recurring: delegation/grant issuance per engagement, status responses served, revocation
  propagation, key rotation, log/receipt retention.
- Failure/edge: handling `Indeterminate` outcomes (registry/clock/status unavailable),
  revocation handling, restart of the in-memory high-water-mark (freshness.md §4 limitation).

**Measurable methods.**
- *Step count / critical-path audit (supported now, structurally):* from the implemented flows,
  enumerate the mandatory steps and the out-of-band (assumed) steps per party, and mark which are
  one-time vs recurring. This is a process map, not a cost figure.
- *Artifact-size cost (supported now):* measure the byte sizes of `C_A`/`D_U`/`G`/status
  responses/challenges as a proxy for storage/transmission cost, using the canonical encoding.
- *Operational cost (requires real deployment):* human time for out-of-band pinning and review,
  responder provisioning/running cost, revocation SLAs, and retention cost are all deployment
  facts; the prototype cannot measure them.

**Synthetic vs real deployment.**
- Supported now: the step/critical-path map and canonical artifact sizes.
- Requires real deployment: any monetary or person-time cost, pinning/review effort, responder
  operating cost, and revocation-propagation cost under real conditions.

**Open decisions (record).**
- Degree of automation vs manual review for RQ1 pinning (the `evidence_ref` process) and its
  effect on onboarding cost and trust.
- Single responder per org (RQ7 v0) vs alternatives (stapled token, multiple responders) and
  their onboarding/operational tradeoffs.
- Key-rotation and root-retirement procedure (spec open item Q11) and its recurring cost.

---

## Q1 measurement slice 1 — field disclosure and linkability (method)

First implemented RQ8 slice (Q1 only; Q2 and Q3 stay design-only). Method and expected
observations are fixed in `tests/cases/rq8_privacy_cases.toml` **before** the runner; the runner
(`src/experiment/rq8_privacy.rs`, reported in `results/rq8_privacy.md`) extracts the *actual*
field sets and comparisons and must match. All observations are `proposed` for owner review. No
real-world privacy guarantee is inferred; synthetic only, no network, no real data.

**Fixture.** The base synthetic fixture (experiment.md §2): org `org-acme-synthetic`, test-only
keys, `.test` hosts. Artifacts inspected, each from its actual canonical signed bytes / wire
form (the effect receipt from its struct fields, as it is an in-memory record, not a wire
object): `C_A`, `D_U`, `G`; the R-signed status response and the `StatusKey` query; the session
challenge and proof; one effect receipt from a real mediation Allow.

**Field-disclosure inventory (FD01–FD08, PO1/PO2/PO3/PO5).** For each artifact, report the
sorted **top-level** canonical field names (what any receiver of that artifact learns). This is
deliberately a names-only inventory: it does **not** recurse into nested values (e.g. the
contents of `bounds`, `envelope`, `targets`, `test_scope`, or the `status_key` sub-object beyond
FD05), does not analyse the envelope around a signed payload, and is not a real-world leakage
analysis. The PO observer→artifact sets are derived from an executed synthetic flow (below). For
each observer, which artifacts it *actually receives*:
- **O1** (bundle holder): `admin`, `issuer`, `grant`.
- **O2** (provider P): the bundle plus the status response and the session exchange.
- **O3** (responder R): only the `StatusKey` query (`org_id`, `object_type`, `id`, `version`,
  `digest`); the model **assumes** R never receives P's `now`/`ε` (freshness.md §2) — an
  assumption, not a measurement.
- **O5** (log / effect-sink reader): the effect receipts.
- **O4** (network/traffic metadata) remains **unmeasured** (no network here).

**Linkability comparison (PL01, PL02).** Deterministic, no population sampling. Each grant is
**built and verified** (chain `Accept`); the comparison uses the exact payload bytes covered by
the signature. `issuer_key_id` is the signed key id; `tester_key_id` is derived as
`keyid(tester_key)` (SHA-256 of the raw public key, not the raw key value). The `StatusKey` is
compared **component-by-component** (`org_id`, `object_type`, `id`, `version`, `digest`), so a
`digest` difference is never mistaken for an absence of correlation.
- *PL01 — identical grant presented twice:* the same signed `G`; everything equal.
- *PL02 — legitimately reissued grant (spec §6 issuance rule):* the same parties re-issue `G`
  under a **new `version`** (a new `version` or `id` is required; re-signing different content
  under the same `(org, type, id, version)` is unsupported — spec §6). Report `signed_bytes`,
  `issuer_key_id`, `tester_key_id` and each `StatusKey` component separately.

This shows that across a legitimate reissue the signed bytes, the grant `version` and the
`StatusKey` `digest` differ, while the stable correlators — `issuer_key_id`, `tester_key_id`,
and the `StatusKey` `org_id`, `object_type` and `id` — remain equal. It is an observation about
this synthetic encoding, not a privacy guarantee.

**Gate.** Exact matches are gated in `cargo test` (an integration test one-to-one with the
runner) and `eval` exits nonzero on any mismatch. Labels stay `proposed`.

## Measurement-support summary

Three support levels: **measured** = already produced by existing code; **extension** = feasible
after a synthetic (no-network) code extension, not implemented yet; **deployment** = requires a
real deployment and is out of scope here.

| Method | Support level | Where / note |
| --- | --- | --- |
| Q1 field-disclosure inventory (per observer) | measured | `rq8_privacy.rs` (`results/rq8_privacy.md`), FD01–FD08 + PO1/PO2/PO3/PO5 |
| Q1 linkability comparison (identical vs reissued) | measured | `rq8_privacy.rs`, PL01/PL02 |
| Q1 network/traffic metadata (O4) | deployment | no network modeled |
| Q2 per-stage CPU (sig / policy / status), p50/p95/p99 | measured | `bench.rs`: `signature_x3`, `typed_policy`, `status_key_x3`, `status_lookup_x3` |
| Q2 whole-`ValidChain_P` CPU | measured | `bench.rs`: `full_chain_verify` |
| Q2 responder-delay sensitivity (modeled) | extension | configurable modeled delay, not implemented |
| Q2 end-to-end latency (real R + network) | deployment | real responder + network RTT, cache, load |
| Q3 onboarding step / critical-path map | extension | structural audit, not implemented |
| Q3 canonical artifact sizes | extension | byte sizes of the canonical artifacts, not implemented |
| Q3 person-time / monetary / operating cost | deployment | human/operating cost under real conditions |

## Non-goals and no-claim statement

- Only Q1 slice 1 (field disclosure + linkability) is implemented; Q2 (latency) and Q3
  (onboarding/cost) remain design-only. No benchmark run or latency/cost number is produced.
- The Q1 observations are structural facts about this synthetic encoding (field names present,
  and which fields are byte-equal across showings). They are **not** a real-world privacy
  guarantee, and no privacy *number* over a real population is asserted. O4 network metadata is
  unmeasured.
- Each of Q1/Q2/Q3 is reported on its own axis; they are not reduced to a single score.
- When Q2/Q3 are implemented, every reported number must cite the method fixed here, the exact
  commit, and the recorded environment (for CPU), and must distinguish synthetic from
  real-deployment measurement.
