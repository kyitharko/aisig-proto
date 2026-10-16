# RQ7 slice — status freshness and bounded revocation delay (DRAFT f2, design only)

**Status:** DRAFT f2, 2026-10-16. **Design only — no implementation, no change to
verification behavior.** This document and the proposed labels in
`tests/cases/freshness_cases.toml` are for owner review *before* any RQ7 code. They do not
change the existing chain / session / enforcement outcomes (94 / 15 / 34 / 28), which stand.
Builds on spec r3.1 ([spec.md](spec.md)), in particular the status stage (spec §6, stage X)
and the exact-object `StatusKey`.

Everything stays synthetic: a modeled status responder, modeled timestamps, an injected
clock. Nothing contacts a real CA, OCSP/CRL endpoint, or network. RQ1 (organization
identity) and RQ2 (asset binding) remain trusted fixtures; RQ7 only concerns how *fresh* a
status answer must be to be relied on.

**f1 → f2 changes:** Active freshness is now evaluated over the **entire** clock interval
`[now−ε, now+ε]` (f1 used only one side); boundary overlap is explicitly Indeterminate.
Future-timestamp, signed-response validation, epoch/rollback and sticky-revocation
precedence are stated precisely. The responder signs exactly three timestamps, never P's
`observed_at`. The delay statement is split into a policy-only part ("stop accepting Active")
and a delivery-dependent part ("receive evidence of Revoked"), and the combined formula is a
conjecture conditional on stated, unproved assumptions. Concrete boundary and
session-issuance cases are added.

## 1. Who is authoritative; what an exact-StatusKey response means

- **Authority.** A **status responder** R is authoritative for the liveness of an
  organization's objects. P pins R's public key `K_R` per org (an RQ1-style out-of-band
  step, assumed). R is not the owner O and not P. **One pinned responder per org in v0.**
- **A response is about one exact object.** It answers a single `StatusKey` (spec §6:
  `org_id`, object type, `id`, `version`, and the SHA-256 digest of the type-separated
  signed bytes) with `Active` / `Revoked` / `Superseded`. A response whose `StatusKey` does
  not exactly match the object under decision does not answer it (→ `StatusUnknown`).
- A response is a signed statement by R binding that `StatusKey`, a `status`, a monotonic
  `status_epoch`, and the three timestamps of §2. P verifies R's signature over the response's
  canonical bytes (spec §3 encoding, new type tag `StatusResponse`).

## 2. What R signs; the four times; the decision interval

R signs exactly these fields (nothing of P's):
`{ status_key, status, status_epoch, status_known_at, published_at, response_expires_at }`.

| Value | Meaning | Who sets it | In the signed response? |
| --- | --- | --- | --- |
| `status_known_at` | instant R asserts the status was correct "as of" | R | **yes** |
| `published_at` | when R produced and signed this response | R | **yes** |
| `response_expires_at` | when the response must no longer be relied on | R | **yes** |
| `observed_at` | when P received the response / read it from cache | P | **no** (P-local) |
| `now`, `ε` | P's decision instant and clock uncertainty (spec §6) | P | **no** |

**R signs the three responder timestamps, never P's `observed_at`.** `observed_at` is P-local
and is used only for P's own bookkeeping; it never enters the signed response and is never
compared as if it were `status_known_at` or `published_at`.

Ordering required in the signed response: `status_known_at ≤ published_at ≤
response_expires_at`. The **decision interval** is `[now−ε, now+ε]`.

## 3. Signed-response validation (gate before any status meaning)

A response is *usable evidence* only if all hold; otherwise
`Indeterminate(StatusResponseInvalid)` (never Accept, never Reject on its own):

1. canonical bytes decode (spec §3), type tag `StatusResponse`;
2. R-signature verifies under the org's pinned `K_R`;
3. `status_key` is well-formed and equals the object's exact `StatusKey`;
4. the three timestamps are canonical UTC `Z` (spec §2.1) and satisfy
   `status_known_at ≤ published_at ≤ response_expires_at`;
5. `status_epoch` is a non-negative integer.

## 4. Decision policy at the status stage

`F` is a single **global, configurable** freshness bound (max tolerated answer age). All
comparisons use `(now, ε)` with half-open, saturating arithmetic (spec §6). Per object
(C_A, D_U, G), after §3 validation:

**Future check (both responder instants ≤ now+ε):**
if `status_known_at > now+ε` or `published_at > now+ε` →
`Indeterminate(StatusTimestampInFuture)`. (`response_expires_at` is expected to be in the
future and is not a future-error.)

**Revoked / Superseded (sticky, monotonic — highest precedence):**
a validated `Revoked` → `Reject(Revoked{obj})`; `Superseded` → `Reject(Superseded{obj})`,
**regardless of the response's age or expiry** (revocation is one-way; fail-closed). Once P
has observed a validated `Revoked`/`Superseded` for a `StatusKey`, that object is
**sticky-revoked**: every later decision is `Reject`, even if a later `Active` (stale,
rolled-back, or fresh) appears. This precedence dominates every Indeterminate below.

**Active — requires the ENTIRE decision interval to be fresh and unexpired.** Let
`age_max = (now+ε) − status_known_at`, `age_min = (now−ε) − status_known_at`:

| Condition on the interval | Outcome |
| --- | --- |
| expired for the whole interval: `now−ε ≥ response_expires_at` | `Indeterminate(StatusStale)` |
| expiry overlaps the interval: `now−ε < response_expires_at ≤ now+ε` | `Indeterminate(StatusFreshnessUncertain)` |
| too old for the whole interval: `age_min > F` | `Indeterminate(StatusStale)` |
| freshness edge overlaps: `age_min ≤ F < age_max` | `Indeterminate(StatusFreshnessUncertain)` |
| rollback: `status_epoch < high-water-mark(StatusKey)` | `Indeterminate(StatusRollback)` |
| otherwise — whole interval unexpired (`now+ε < response_expires_at`) **and** fresh (`age_max ≤ F`, edge-inclusive) and `status_epoch ≥ hwm` and not future | **ok** (Active accepted) |

So Active is accepted only when the *latest* possible decision instant (`now+ε`) is still
within `F` of `status_known_at` and strictly before expiry; any overlap of either boundary
with the interval is `StatusFreshnessUncertain`, never Accept. `Unknown` (no record) →
`Indeterminate(StatusUnknown{obj})`; source/cache unavailable →
`Indeterminate(StatusUnavailable)`.

**Reject-over-Indeterminate (explicit):** the Revoked/Superseded/sticky rule above is a
Reject and dominates every staleness, uncertainty, future, rollback, unknown, unavailable,
or invalid Indeterminate. An Indeterminate is **never** upgraded to Accept: missing fresh
evidence of liveness blocks Accept but does not prove revocation.

**Epoch / rollback & high-water-mark.** P keeps, per `StatusKey`, an **in-memory**
high-water-mark `hwm` = the greatest `status_epoch` it has accepted, plus a sticky
"revoked-seen" flag. Accepting a response updates `hwm = max(hwm, status_epoch)`. A validated
`Active` with `status_epoch < hwm` is a rollback → `Indeterminate(StatusRollback)`; equal
epoch with matching digest is idempotent (ok). **Restart limitation (explicit):** the `hwm`
and the revoked-seen flag are in-memory only; on P restart they reset to empty, so until P
re-observes a `Revoked`, an attacker could replay an older `Active` that is still within its
own `F`/expiry. v0 does not persist the high-water-mark; a real design must persist it or
rely on a short `response_expires_at`. This is a stated limitation, not a solved problem.

## 5. Two different bounds — kept separate

The owner's distinction between *stopping reliance* and *detecting revocation*:

- **Stop accepting Active (policy-only, no delivery assumption).** Once the held Active
  response ages past `F` or reaches expiry, the policy of §4 stops returning Active (it
  returns `StatusStale`/`StatusFreshnessUncertain`), so P stops *Accepting* the object. The
  time from "last-known-good lapses" to "P no longer Accepts" is bounded by the freshness
  window itself: `≤ F + 2ε` (and no later than `response_expires_at + ε`). This follows from
  the policy alone and needs **no** publishing or delivery assumption.
- **Receive evidence of Revoked (delivery-dependent).** To turn a decision from
  Indeterminate into a `Reject`, P must actually *receive* a `Revoked` response. That needs
  delivery, and a bound requires assumptions.

These are not the same event: P can stop accepting (Indeterminate) long before — or without
ever — receiving a Revoked.

## 6. Delay conjecture — conditional on unproved assumptions

**No numeric revocation-detection bound is claimed.** As a *conjecture* only, under:

- **A1 (publishing bound `U`)** — R publishes a `Revoked` reflecting a real revocation within `U`;
- **A2 (delivery/cache bound `Dd`)** — a published response reaches P / P's cache refreshes within `Dd`;
- **A3 (clock bound `ε`)** — responder/P clock skew is within `ε`;

the time from a real revocation to P issuing a `Reject` would be at most `U + Dd + ε`, and
the time to P merely ceasing to Accept is at most `F + 2ε` (from §5, independent of A1/A2).
The combined `U + Dd + F + ε` figure from f1 is **withdrawn as a claim**; it holds only if
A1–A3 are established for a concrete deployment, which this synthetic prototype does not do.
State the assumptions and prove them before quoting any number.

## 7. Where the policy applies

The status stage is shared, so RQ7 slots in once and the rest inherit it:

- **Chain verification (spec §6 stage X):** the freshness policy replaces the instant,
  always-current fixture. Non-fresh Active → chain `Indeterminate`; Revoked/Superseded →
  `Reject`.
- **Session issuance and redemption (RQ5):** both re-verify the chain, so both inherit it.
  A stale Active at issuance → `IssueRefused(Indeterminate/X/StatusStale)` (no challenge
  minted); a Revoked at issuance → `IssueRefused(Reject/X/Revoked{G})`. At redemption, stale
  → `SessionIndeterminate` (no consume); Revoked → `SessionReject`.
- **Every RQ6 action:** the mediator re-verifies the chain (status included) against its
  single decision-time snapshot; stale → `Indeterminate` (no effect); Revoked →
  `Deny(ChainRejected(...))`.

RQ1/RQ2 stay assumed; the responder-key pinning is an RQ1-style assumed step. Synthetic only.

## 8. Fixture for the proposed cases

Base chain fixture (experiment.md §2) plus a modeled responder:

- `F = 3600 s` (1 h), global. Pinned `K_R` per org.
- Decision `now = 2026-10-15T10:00:00Z`, `ε = 2 s` (so interval `[09:59:58Z, 10:00:02Z]`).
- Each object's response defaults: `status = Active`, `status_epoch = 1`, `hwm = 0` (empty),
  `status_known_at = 2026-10-15T09:59:00Z`, `published_at = 2026-10-15T09:59:00Z`,
  `response_expires_at = 2026-10-15T11:00:00Z`.
- A case overrides only the fields it names. Session timings reuse experiment.md §11
  (issue at 10:00:00Z, redeem at 10:01:00Z).

## 9. Proposed case labels (design only; all **Pr**)

In `tests/cases/freshness_cases.toml`, written before any code, **not** wired to a runner.
Expected outcomes are at the chain status stage (X) unless noted.

### Policy cases

| ID | Situation | Expected |
| --- | --- | --- |
| FR01 | all fresh Active (defaults) | `Accept` |
| FR02 | G `response_expires_at = 2026-10-15T09:59:58Z` (≤ now−ε) | `Indeterminate / X / StatusStale` |
| FR03 | G `status_known_at = 2026-10-15T08:00:00Z` (age_min > F) | `Indeterminate / X / StatusStale` |
| FR04 | G `Revoked`, fresh | `Reject / X / Revoked{G}` |
| FR05 | G `Revoked`, `response_expires_at = 2026-10-15T09:00:00Z` (expired) | `Reject / X / Revoked{G}` |
| FR06 | C_A `Superseded` | `Reject / X / Superseded{C_A}` |
| FR07 | no response for G's exact `StatusKey` | `Indeterminate / X / StatusUnknown{G}` |
| FR08 | responder/cache unavailable | `Indeterminate / X / StatusUnavailable` |
| FR09 | G `status_known_at = 2026-10-15T10:05:00Z` (> now+ε) | `Indeterminate / X / StatusTimestampInFuture` |
| FR11 | G valid Active, `status_epoch = 1`, `hwm = 2` (epoch < hwm) | `Indeterminate / X / StatusRollback` |
| FR12 | response bound to a different `StatusKey` (replay of another object's Active) | `Indeterminate / X / StatusUnknown{G}` |
| FR13 | G both `Revoked` and stale (expired) | `Reject / X / Revoked{G}` (Reject dominates) |
| FR14 | G response signed by a non-pinned key | `Indeterminate / X / StatusResponseInvalid` |
| FR15 | G timestamps out of order (`published_at < status_known_at`) | `Indeterminate / X / StatusResponseInvalid` |
| FR16 | G sticky: a `Revoked` was observed earlier, now a fresh `Active` (epoch 3) arrives | `Reject / X / Revoked{G}` (sticky) |

### Boundary cases (concrete timestamps; interval `[09:59:58Z, 10:00:02Z]`, F=3600 s)

| ID | Situation | Expected |
| --- | --- | --- |
| FB01 | G `status_known_at = 2026-10-15T09:00:02Z` → `age_max = 3600 = F` (edge-inclusive fresh) | `Accept` |
| FB02 | G `status_known_at = 2026-10-15T09:00:00Z` → `age_min = 3598 ≤ F < age_max = 3602` (freshness edge overlaps) | `Indeterminate / X / StatusFreshnessUncertain` |
| FB03 | G `response_expires_at = 2026-10-15T10:00:03Z` (> now+ε) | `Accept` |
| FB04 | G `response_expires_at = 2026-10-15T10:00:01Z` (`now−ε < exp ≤ now+ε`, expiry overlaps) | `Indeterminate / X / StatusFreshnessUncertain` |
| FB05 | G `response_expires_at = 2026-10-15T09:59:58Z` (= now−ε, expired for whole interval) | `Indeterminate / X / StatusStale` |
| FB06 | G `status_known_at = 2026-10-15T10:00:02Z` (= now+ε, not future, age_max=0) | `Accept` |
| FB07 | G `status_known_at = 2026-10-15T10:00:03Z` (= now+ε+1, future) | `Indeterminate / X / StatusTimestampInFuture` |
| FB08 | G valid Active, `status_epoch = 2`, `hwm = 2` (equal epoch, idempotent) | `Accept` |

### Session-issuance cases (RQ5 `issue`; reuse experiment.md §11 timings)

| ID | Situation | Expected |
| --- | --- | --- |
| FS01 | issue with all fresh Active | `Issued expires_at=2026-10-15T10:02:00Z` |
| FS02 | issue with G stale (`response_expires_at = 2026-10-15T09:59:58Z`) | `IssueRefused / Indeterminate / X / StatusStale` |
| FS03 | issue with G `Revoked` | `IssueRefused / Reject / X / Revoked{G}` |
| FS04 | issue with the responder unavailable (reported as IssueRefused for consistency with the chain decision; see §10 Q4) | `IssueRefused / Indeterminate / X / StatusUnavailable` |

### Session-redemption / mediation inheritance

| ID | Situation | Expected |
| --- | --- | --- |
| FR17 | session redemption with a stale-Active G | `SessionIndeterminate / chain / ChainIndeterminate(Indeterminate / X / StatusStale)` ; no consume |
| FR18 | RQ6 mediation with a stale-Active G | `Indeterminate / chain / ChainIndeterminate(Indeterminate / X / StatusStale) effects=0` |
| FR19 | RQ6 mediation with a `Revoked` G | `Deny / chain / ChainRejected(Reject / X / Revoked{G}) effects=0` |

**Count:** 30 proposed RQ7 labels (15 policy, 8 boundary, 4 session-issuance, 3
inheritance). None change the existing 94 / 15 / 34 / 28 reviewed outcomes. No runner, no code.

**FS04 note (open).** Whether an unavailable responder at issuance is reported as
`IssueRefused(Indeterminate/...)` (chain not Accept) or a distinct `IssueUnavailable` is an
open question; the table proposes `IssueRefused` for consistency with the chain decision.
Flagged in §10.

## 10. Open questions for owner review

1. Single responder per org (v0) vs also accepting an owner-signed stapled freshness token
   in the bundle (tighter, no responder round-trip).
2. `StatusRollback`: Indeterminate (v0, missing-fresh-evidence) vs Reject (treat a signed
   older epoch as hostile).
3. `F`: global (v0) vs per-org or per-object-type.
4. FS04: `IssueRefused(Indeterminate)` vs a distinct `IssueUnavailable` for an unavailable
   responder at issuance.
5. Persisting the high-water-mark across restarts without a liveness bottleneck (the §4
   restart limitation). Out of scope for the synthetic prototype.
