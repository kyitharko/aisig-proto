# RQ7 slice — status freshness and bounded revocation delay (DRAFT f1, design only)

**Status:** DRAFT f1, 2026-10-16. **Design only — no implementation, no change to
verification behavior.** This document and the proposed labels in
`tests/cases/freshness_cases.toml` are for owner review *before* any RQ7 code. They do not
change the existing chain / session / enforcement outcomes (94 / 15 / 34 / 28), which stand.
Builds on spec r3.1 ([spec.md](spec.md)), in particular the status stage (spec §6, stage X)
and the exact-object `StatusKey`.

Everything stays synthetic: a modeled status responder, modeled timestamps, an injected
clock. Nothing contacts a real CA, OCSP/CRL endpoint, or network. RQ1 (organization
identity) and RQ2 (asset binding) remain trusted fixtures; RQ7 only concerns how *fresh* a
status answer must be to be relied on.

## 1. Who is authoritative; what an exact-StatusKey response means

- **Authority.** A **status responder** R is authoritative for the liveness of objects of a
  given organization. P trusts R's public key `K_R` the way it trusts a pinned root: `K_R`
  is pinned in P's registry per org (an RQ1-style out-of-band step, assumed). R is *not* the
  owner O and *not* P; it is the party O (or P on O's behalf) designates to publish
  revocation/supersession. In v0 there is exactly one responder per org.
- **A response is about one exact object.** A status response answers a single `StatusKey`
  (spec §6: `org_id`, object type, `id`, `version`, and the SHA-256 digest of the
  type-separated signed bytes). `Active` / `Revoked` / `Superseded` is a statement about
  *that exact signed object only* — never about another object that merely shares an `id`
  and `version`. A response whose `StatusKey` does not exactly match the object under
  decision does not answer it (→ `StatusUnknown`, as today).
- A response is a signed, timestamped statement by R binding that `StatusKey` and the four
  times of §2. The verifier checks R's signature over the response's canonical bytes
  (the §3 domain-separated encoding, a new type tag `StatusResponse`); an invalid or
  wrong-key signature makes the response unusable evidence (`StatusResponseInvalid`,
  Indeterminate), never an Accept and never a Reject on its own.

## 2. The four times (and the decision instant)

| Value | Meaning | Who sets it | Authenticated? |
| --- | --- | --- | --- |
| `status_known_at` | the instant R asserts the status was correct "as of" | R | **yes** (signed) |
| `published_at` | when R produced and signed this response | R | **yes** (signed) |
| `response_expires_at` | when the response must no longer be relied on (`not_after`) | R | **yes** (signed) |
| `observed_at` | when P received the response, or read it from P's cache | P | no (P's own record) |
| `now`, `ε` | P's trusted decision instant and clock uncertainty (spec §6) | P | no (P's clock) |

All times are canonical UTC `Z` (spec §2.1). `status_known_at ≤ published_at ≤
response_expires_at` must hold in the signed response, else the response is malformed
(`StatusResponseInvalid`). The responder also signs a monotonic `status_epoch` (a per-object
non-decreasing counter) used for rollback detection (§3).

What P adds and must not confuse with signed values: `observed_at`, `now`, `ε`, and P's
remembered high-water-mark per `StatusKey` (§3 rollback). P never treats its own
`observed_at` as if it were R's `status_known_at`.

## 3. Decision policy at the status stage

Let `F` be the configured **freshness bound** (max tolerated age of a status answer; a
policy constant, chosen ≤ the tolerable revocation-detection delay of §4). All comparisons
use P's `(now, ε)` with half-open, saturating arithmetic (spec §6). The status stage is
evaluated per object (C_A, D_U, G) as today; the outcomes:

| Situation | Condition | Outcome |
| --- | --- | --- |
| **fresh Active** | signed `Active`, exact `StatusKey`, R-signature valid, `now+ε < response_expires_at`, `now−ε − status_known_at ≤ F`, not in the future (below), epoch ≥ high-water-mark | **ok** (stage passes) |
| **stale Active (expired)** | `Active` but `now−ε ≥ response_expires_at` | `Indeterminate(StatusStale)` |
| **stale Active (too old)** | `Active` but `now−ε − status_known_at > F` | `Indeterminate(StatusStale)` |
| **Revoked** | signed `Revoked`, exact `StatusKey`, valid signature | `Reject(Revoked{obj})` — **regardless of freshness/expiry** (revocation is monotonic; fail-closed) |
| **Superseded** | signed `Superseded`, valid | `Reject(Superseded{obj})` (monotonic) |
| **Unknown** | no record for this exact `StatusKey` | `Indeterminate(StatusUnknown{obj})` |
| **source unavailable** | R / cache cannot be consulted | `Indeterminate(StatusUnavailable)` |
| **future-dated** | `status_known_at > now+ε` or `published_at > now+ε` | `Indeterminate(StatusTimestampInFuture)` (a future-dated response is not trustworthy evidence; never Accept) |
| **freshness uncertain** | the expiry or `F` comparison straddles within ε | `Indeterminate(StatusFreshnessUncertain)` |
| **rollback / replay of older Active** | a valid `Active` whose `status_epoch` (or `published_at`) is *older* than the high-water-mark P already accepted for this `StatusKey` | `Indeterminate(StatusRollback)` |
| **invalid response** | R-signature invalid, wrong `K_R`, malformed, or ordering violated | `Indeterminate(StatusResponseInvalid)` |

**Reject dominates Indeterminate (explicit).** A `Revoked`/`Superseded` response is a Reject
even when the *same or another* status signal is stale, uncertain, future-dated, or rolled
back. Only the absence of a revocation signal leaves staleness/uncertainty as Indeterminate.
A stale or uncertain answer is **never** upgraded to Accept: missing fresh evidence of
liveness blocks Accept but does not by itself prove revocation.

**Monotonic high-water-mark.** P keeps, per `StatusKey`, the greatest `status_epoch` (and
`published_at`) it has accepted, and whether it has ever seen `Revoked`/`Superseded`. Once
revoked-seen, the object is sticky-Reject. An `Active` older than the high-water-mark is not
fresh evidence (`StatusRollback`). This is the replay/rollback defense; it is P-local state.

## 4. Assumptions for a bounded revocation-detection delay

No numeric bound is claimed without these assumptions; the bound is stated as a function of
them:

- **`U` — update/publishing bound.** After an object is revoked at the authority, R
  publishes a `Revoked` response reflecting it within `U`.
- **`Dd` — delivery/cache bound.** A published response reaches P (or P's cache entry for
  that `StatusKey` refreshes) within `Dd`.
- **`ε` — clock uncertainty** between R and P.

Then, if P relies on a response only while `now−ε − status_known_at ≤ F` and
`now+ε < response_expires_at`, the worst-case delay between a real revocation and P refusing
the object is bounded by

```
revocation-detection delay ≤ U + Dd + F + ε
```

because P may still rely on an already-held, not-yet-stale Active response for up to `F`
(and up to its expiry) after the revocation happened but before a `Revoked` response is
published and delivered. Choosing `F` and `response_expires_at` small trades freshness
against responder/network load. **Without `U`, `Dd`, and `ε` as stated assumptions, no
delay bound holds** — in particular an unavailable source yields Indeterminate, not a silent
Accept, precisely so the bound is not violated by relying on stale evidence.

## 5. Where the policy applies

The status stage is already shared by all three decision paths, so RQ7 slots in at one
place and the rest inherit it:

- **Chain verification (spec §6 stage X):** replace the instant, always-current in-memory
  fixture with the freshness policy over a signed, timestamped responder statement. A
  non-fresh Active makes the chain `Indeterminate` (not Accept); a `Revoked`/`Superseded`
  makes it `Reject`.
- **Session redemption (RQ5):** redemption re-verifies the chain, so it inherits the
  freshness policy automatically; a stale status at redemption → `SessionIndeterminate`
  (never `SessionAccept`, never consume), a revoked one → `SessionReject`.
- **Every RQ6 action (mediation):** the mediator re-verifies the chain (status included) on
  each action against its single decision-time snapshot; a stale status → `Indeterminate`
  (no effect), a revoked one → `Deny(ChainRejected(...))`. This is exactly the RQ7 item the
  mediator left open: the mediator already *re-checks* status each action; RQ7 adds *how
  fresh* that check must be.

RQ1/RQ2 stay assumed (trusted registry and binding fixtures). The responder key pinning is
an RQ1-style out-of-band step, assumed. Everything is synthetic.

## 6. Proposed case labels (design only; all **Pr**)

Labels in `tests/cases/freshness_cases.toml`, written before any code. They reuse the base
chain fixture with a modeled responder; expected outcomes are at the status stage (X) of the
chain decision unless noted. These are for owner review and are **not** wired to a runner
yet (no RQ7 implementation exists).

| ID | Situation | Expected (chain) |
| --- | --- | --- |
| FR01 | fresh Active for all three objects | `Accept` |
| FR02 | G's response expired (`now−ε ≥ response_expires_at`) | `Indeterminate / X / StatusStale` |
| FR03 | G Active but `status_known_at` older than `F` | `Indeterminate / X / StatusStale` |
| FR04 | G `Revoked`, fresh | `Reject / X / Revoked{G}` |
| FR05 | G `Revoked`, response expired | `Reject / X / Revoked{G}` (monotonic) |
| FR06 | C_A `Superseded` | `Reject / X / Superseded{C_A}` |
| FR07 | no response for G's exact `StatusKey` | `Indeterminate / X / StatusUnknown{G}` |
| FR08 | responder/cache unavailable | `Indeterminate / X / StatusUnavailable` |
| FR09 | G `status_known_at` in the future (`> now+ε`) | `Indeterminate / X / StatusTimestampInFuture` |
| FR10 | G expiry straddles within ε | `Indeterminate / X / StatusFreshnessUncertain` |
| FR11 | G valid Active but `status_epoch` below the high-water-mark (rollback) | `Indeterminate / X / StatusRollback` |
| FR12 | response bound to a different `StatusKey` (replay of another object's Active) | `Indeterminate / X / StatusUnknown{G}` |
| FR13 | G both `Revoked` and stale | `Reject / X / Revoked{G}` (Reject dominates) |
| FR14 | G response signed by a non-pinned key | `Indeterminate / X / StatusResponseInvalid` |
| FR15 | session redemption with a stale-Active G | `SessionIndeterminate / chain / ChainIndeterminate(Indeterminate / X / StatusStale)` ; no consume |
| FR16 | RQ6 mediation with a stale-Active G | `Indeterminate / chain / ChainIndeterminate(Indeterminate / X / StatusStale) effects=0` |
| FR17 | RQ6 mediation with a `Revoked` G | `Deny / chain / ChainRejected(Reject / X / Revoked{G}) effects=0` |

**Count:** 17 proposed RQ7 labels. None change the existing 94 / 15 / 34 / 28 reviewed
outcomes. No runner, no code.

## 7. Open questions for owner review

1. Is a single responder per org the right v0, or should P also accept owner-signed
   short-lived "status assertions" (a stapled freshness token in the bundle)?
2. Should `StatusRollback` be `Reject` (treat a rollback attempt as hostile) rather than
   `Indeterminate`? v0 proposes Indeterminate, since a rollback is missing-fresh-evidence,
   not proof of revocation — but an authenticated newer epoch makes it suspicious.
3. Should `F` be global, per-org, or per-object-type? Proposed: a single global `F` in v0.
4. Is `U + Dd + F + ε` the bound to publish, or should the stapled-token design (Q1) give a
   tighter, simpler `response_expires_at + ε`?
5. How should P persist the high-water-mark across restarts without becoming a liveness
   bottleneck? Out of scope for the synthetic prototype; flagged for a real design.
