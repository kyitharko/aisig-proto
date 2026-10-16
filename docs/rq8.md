# RQ8 — privacy, latency and onboarding cost (DESIGN ONLY)

**Status:** DRAFT, 2026-10-17. **Design only — no implementation, no RQ8 expected-case labels,
and no performance or privacy claim is made here.** This document defines *questions* and
*measurement methods* so that any future RQ8 result is produced against a method fixed in
advance. Where the existing synthetic prototype can support a method it is stated; where a real
deployment is required it is stated. Every quantity below is a method, not a result: this
prototype has produced no RQ8 numbers, and none may be quoted until measured against the method
recorded here.

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
- *Field inventory (synthetic, supported now):* enumerate, per object type and per observer, the
  fields disclosed, using the typed model and canonical encoding already in the prototype. This
  is a structural audit, not a number — report it as a disclosure table.
- *Linkability count (synthetic, supported now):* over a generated population of synthetic
  chains, count how many objects are byte-identical / share a key id / share a `StatusKey`
  across showings, to quantify correlation potential under O1–O3. Uses the existing fixture and
  mutation machinery; no network.
- *Query-pattern leakage (synthetic model, partial):* from the status-stage call sequence
  (which `StatusKey`s, in what order) the prototype can report what R would observe in principle;
  the *real* timing/size signal (O4) needs a deployment.

**Synthetic vs real deployment.**
- Supported now: field inventory, linkability counts, and the in-principle query pattern R sees.
- Requires real deployment: O4 (network/traffic analysis — timing, size, endpoint correlation),
  any claim about an actual responder protocol's metadata, and any adversary with side channels.

**Open decisions (record; do not pre-judge).**
- Whether to blind the status query (e.g. a privacy-preserving status check) vs the current
  exact-`StatusKey` lookup — a tradeoff against RQ7's exact-object guarantee.
- Whether key ids / digests should be salted or rotated per showing to reduce O1–O3
  linkability, and the cost to RQ1 pinning and RQ7 stickiness.
- What, if anything, in `EffectReceipt`s should be minimized for O5.

---

## Q2 — CPU cost vs end-to-end latency (including the status source)

**Question.** Two different quantities must not be conflated: (a) the **CPU work** of a decision
on one machine, and (b) the **end-to-end latency** a tester/provider experiences, which in a
real deployment is dominated by the **status source** round-trip and by network, not by CPU.

**What to measure.**
- *CPU, per stage (supported now).* `src/bin/bench.rs` already times, separately and with
  warmup + N iterations + R repeated runs, reporting p50/p95/p99: Ed25519 signature verification
  (×3), typed policy evaluation, and a *simulated* status lookup. `scripts/bench.sh` records
  rustc/cargo versions, CPU model (`/proc/cpuinfo`), kernel, build profile and seeds, so a CPU
  result is reproducible. This measures (a) only, and only the synthetic, in-memory status path.
- *Decision CPU for the whole `ValidChain_P` (supported now, as an extension of bench):* time
  `verify(&Bundle)` end-of-CPU (format→status) against the in-memory fixtures. Still (a): the
  status stage here is the always-current fixture (or the synthetic `FreshnessOracle` with an
  in-memory responder), so there is **no** real responder latency.
- *End-to-end latency (requires real deployment).* The real cost is: client→P, P→R status query
  (network + R compute + R's own freshness/caching), P's CPU decision, and the session/mediation
  round-trips. The prototype can model a *configurable* responder delay to show how end-to-end
  latency decomposes, but any concrete end-to-end number needs a real responder and network.

**Method (fixed in advance).**
- Separate the two axes explicitly in any report: "CPU per stage (this machine)" vs "end-to-end
  (deployment)". Never present a CPU microbenchmark as an end-to-end latency.
- For CPU: warmup, fixed iteration/repeat counts, fixed RNG seed, recorded environment; report
  p50/p95/p99 per stage; attribute cost to signature verification vs policy vs status.
- For end-to-end: define the components (client RTT, P→R RTT, R compute, cache hit/miss, P CPU,
  session/mediation RTTs) and measure each in the real deployment; the synthetic prototype only
  provides the P-CPU component and a *modeled* (not measured) responder delay for sensitivity
  analysis.

**Synthetic vs real deployment.**
- Supported now: per-stage CPU, whole-`ValidChain_P` CPU, and a sensitivity analysis over a
  modeled responder delay (clearly labeled as modeled, not measured).
- Requires real deployment: every end-to-end latency number, real responder/network RTT, cache
  behavior, and any throughput/contention figure under real load.

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

## Measurement-support summary

| Method | Synthetic prototype | Needs real deployment |
| --- | --- | --- |
| Q1 field-disclosure inventory (per observer) | yes | — |
| Q1 linkability / correlation counts (O1–O3) | yes | — |
| Q1 network/traffic metadata (O4) | — | yes |
| Q2 per-stage CPU (sig / policy / status), p50/p95/p99 | yes (`bench.rs`) | — |
| Q2 whole-`ValidChain_P` CPU | yes (bench extension) | — |
| Q2 responder-delay sensitivity (modeled) | yes (modeled, not measured) | — |
| Q2 end-to-end latency (real R + network) | — | yes |
| Q3 onboarding step / critical-path map | yes (structural) | — |
| Q3 canonical artifact sizes | yes | — |
| Q3 person-time / monetary / operating cost | — | yes |

## Non-goals and no-claim statement (this phase)

- No RQ8 implementation, benchmark run, or expected-case labels are produced here.
- No privacy, latency, throughput, or cost **number** is asserted; the tables above are methods
  and support statements, not results.
- Each of Q1/Q2/Q3 is reported on its own axis; they are not reduced to a single score.
- When RQ8 is implemented, every reported number must cite the method fixed here, the exact
  commit, and the recorded environment (for CPU), and must distinguish synthetic from
  real-deployment measurement.
