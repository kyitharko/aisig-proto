# RQ7 slice — status freshness and bounded revocation delay (DRAFT f2)

**Status:** DRAFT f2, revised 2026-10-17. **Implemented behind a separate runner; the 34
proposed labels in `tests/cases/freshness_cases.toml` are the oracle and remain `proposed`
pending owner review.** The design here was written first; the implementation
(`src/freshness.rs`, the status stage in `src/verifier.rs`) matches all 34 labels
(`results/freshness_cases.md`), gated in `cargo test` and by a nonzero `eval` exit on any
mismatch, and **no label was adjusted to match output**. The freshness
policy runs only where an oracle backed by the synthetic responder is wired in; the existing
chain / session / enforcement outcomes (94 / 15 / 34 / 28) are unchanged.
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

**f2 corrections (2026-10-17):** the future check now spans the **whole** interval, so a
`status_known_at`/`published_at` later than `now−ε` (future at the earliest decision instant)
is Indeterminate, never Accept (fixes FB06). Validation §3 and lookup are reconciled: **no
response filed under the requested exact `StatusKey` → `StatusUnknown`**; a response that *is*
filed for that key but is malformed, mis-ordered or wrongly signed → `StatusResponseInvalid`
(fixes the §3/FR12 contradiction). Equal-epoch behavior is made precise: an identical signed
response replays idempotently within the freshness limits, but a *different* signed response
at the same epoch is a **conflict** (`StatusEpochConflict`) and cannot make Active acceptable.
The §5 time bound names its starting event and its single clock assumption and is restated as
policy-only, not a revocation-delay guarantee. Proposed timestamps in FR05, FR09, FR13, FB06
and FB07 are made structurally coherent (`status_known_at ≤ published_at ≤
response_expires_at`), and a conflict case (FB09) is added.

## 1. Who is authoritative; what an exact-StatusKey response means

- **Authority.** A **status responder** R is authoritative for the liveness of an
  organization's objects. P pins R's public key `K_R` per org (an RQ1-style out-of-band
  step, assumed). R is not the owner O and not P. **One pinned responder per org in v0.**
- **A response is about one exact object.** P looks the status up by the object's exact
  `StatusKey` (spec §6: `org_id`, object type, `id`, `version`, and the SHA-256 digest of the
  type-separated signed bytes). A response answers only if its embedded `status_key` equals
  that key; a response whose `StatusKey` does not exactly match the object under decision —
  including an attacker's replay of another object's valid Active — **does not answer it and
  is treated as no answer → `StatusUnknown`**, not as an invalid response. (§3 distinguishes
  this from a response that *is* for the requested key but is malformed/wrongly signed.)
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

## 3. Lookup, then signed-response validation

**Lookup (decides `StatusUnknown` vs "have a candidate").** P asks the source for the
object's exact `StatusKey`.
- source unavailable → `Indeterminate(StatusUnavailable)`;
- no response filed under that exact key → `Indeterminate(StatusUnknown{obj})`;
- a candidate response is returned.

**Validation gate (decides `StatusResponseInvalid`).** A returned candidate is *usable
evidence* for this object only if all of the following hold; otherwise
`Indeterminate(StatusResponseInvalid)` (never Accept, never Reject on its own):

1. canonical bytes decode (spec §3), type tag `StatusResponse`;
2. R-signature verifies under the org's pinned `K_R`;
3. the three timestamps are canonical UTC `Z` (spec §2.1) and satisfy
   `status_known_at ≤ published_at ≤ response_expires_at`;
4. `status_epoch` is a non-negative integer;
5. `status` is one of `Active` / `Revoked` / `Superseded`.

**Exact-key reconciliation (no contradiction with FR12).** The embedded `status_key` is a
*matching* condition, not a validity condition: a candidate whose `status_key` does not equal
the requested key is **not an answer for this object → `StatusUnknown{obj}`** (it may be a
perfectly valid, correctly signed response *about a different object* that an attacker is
replaying). `StatusResponseInvalid` is reserved for a response that *is* bound to the
requested key but fails a gate check above (malformed, mis-ordered, wrong signer). So a bad
signature or bad ordering for G's own key → `StatusResponseInvalid` (FR14, FR15); any
other-object response offered for G → `StatusUnknown{G}` (FR12).

## 4. Decision policy at the status stage

`F` is a single **global, configurable** freshness bound (max tolerated answer age). All
comparisons use `(now, ε)` with half-open, saturating arithmetic (spec §6); write the
decision interval as `[now−ε, now+ε]`. Per object (C_A, D_U, G), after §3 validation, the
checks apply in this **precedence order** (the first that fires decides the object):

1. sticky-revoked flag set for this key → **Reject** (Revoked/Superseded) — §"sticky";
2. this response is `Revoked`/`Superseded` → **Reject** — §"sticky";
3. future timestamp (whole interval) → `Indeterminate(StatusTimestampInFuture)`;
4. epoch rollback or same-epoch conflict → `Indeterminate(StatusRollback | StatusEpochConflict)`;
5. expiry → `Indeterminate(StatusStale | StatusFreshnessUncertain)`;
6. freshness (age) → `Indeterminate(StatusStale | StatusFreshnessUncertain)`;
7. otherwise → Active accepted.

**Future check (whole interval).** The responder's as-of/publish instant must not be after
any instant in the decision interval. Let `latest = max(status_known_at, published_at)`
(= `published_at`, by the §3 ordering):
- `latest ≤ now−ε` → not future (every decision instant is at or after it): continue;
- `latest > now−ε` → `Indeterminate(StatusTimestampInFuture)`. This covers both the definite
  case `latest > now+ε` (future for the entire interval) **and** the boundary overlap
  `now−ε < latest ≤ now+ε` (future at the earliest decision instant only). An as-of time that
  is in the future for *part* of the interval cannot support Accept — this is why FB06
  (`status_known_at = now+ε`) is Indeterminate, not Accept. `response_expires_at` is expected
  to be in the future and is never a future-error.

**Revoked / Superseded (sticky, monotonic — highest precedence):**
a validated `Revoked` → `Reject(Revoked{obj})`; `Superseded` → `Reject(Superseded{obj})`,
**regardless of the response's age or expiry** (revocation is one-way; fail-closed). Once P
has observed a validated `Revoked`/`Superseded` for a `StatusKey`, that object is
**sticky-revoked**: every later decision is `Reject`, even if a later `Active` (stale,
rolled-back, or fresh) appears. This precedence dominates every Indeterminate below.

**Active — requires the ENTIRE decision interval to be fresh and unexpired.** Let
`age_max = (now+ε) − status_known_at`, `age_min = (now−ε) − status_known_at`:

(evaluated in the precedence order above; the first matching row decides)

| Condition on the interval | Outcome |
| --- | --- |
| rollback: `status_epoch < high-water-mark(StatusKey)` | `Indeterminate(StatusRollback)` |
| same-epoch conflict: `status_epoch = hwm` but a *different* signed response than the one at `hwm` | `Indeterminate(StatusEpochConflict)` |
| expired for the whole interval: `now−ε ≥ response_expires_at` | `Indeterminate(StatusStale)` |
| expiry overlaps the interval: `now−ε < response_expires_at ≤ now+ε` | `Indeterminate(StatusFreshnessUncertain)` |
| too old for the whole interval: `age_min > F` | `Indeterminate(StatusStale)` |
| freshness edge overlaps: `age_min ≤ F < age_max` | `Indeterminate(StatusFreshnessUncertain)` |
| otherwise — whole interval unexpired (`now+ε < response_expires_at`) **and** fresh (`age_max ≤ F`, edge-inclusive), not future, and epoch consistent | **ok** (Active accepted) |

So Active is accepted only when the *latest* possible decision instant (`now+ε`) is still
within `F` of `status_known_at` and strictly before expiry; any overlap of either boundary
with the interval is `StatusFreshnessUncertain`, never Accept. `Unknown` (no record) →
`Indeterminate(StatusUnknown{obj})`; source/cache unavailable →
`Indeterminate(StatusUnavailable)`.

**Reject-over-Indeterminate (explicit):** the Revoked/Superseded/sticky rule above is a
Reject and dominates every staleness, uncertainty, future, rollback, unknown, unavailable,
or invalid Indeterminate. An Indeterminate is **never** upgraded to Accept: missing fresh
evidence of liveness blocks Accept but does not prove revocation.

**Epoch / rollback / conflict & high-water-mark.** P keeps, per `StatusKey`, an **in-memory**
high-water-mark: `None` until the first Active is accepted, then `Some(epoch, digest)` — the
greatest `status_epoch` accepted and the digest of the exact signed response accepted at that
epoch — plus a sticky "revoked-seen" flag. **`status_epoch = 0` is a valid epoch:** the first
accepted response records its real `(0, digest)`; there is no sentinel epoch-0 entry, so an
identical epoch-0 response replays idempotently (FB10). For a validated `Active` against a
recorded `Some(hwm_epoch, hwm_digest)`:
- `status_epoch < hwm_epoch` → rollback → `Indeterminate(StatusRollback)`;
- `status_epoch = hwm_epoch` and the digest **equals** `hwm_digest` → idempotent replay,
  allowed (the same signed answer re-presented within its own freshness limits; FB08, FB10);
- `status_epoch = hwm_epoch` and the digest **differs** → two different signed answers claim
  the same epoch; conflict → `Indeterminate(StatusEpochConflict)` (FB09). A conflict never
  makes Active acceptable; it does not advance `hwm`;
- `status_epoch > hwm_epoch` → newer; accepted (becomes the new `hwm`).

**Atomic commit & linearization (concurrency).** The sticky re-check, the epoch comparison
and the `hwm` advance for an accepted Active happen under **one** lock acquisition, which is
the decision's **linearization point**. An Active that acquires the lock *after* a `Revoked`
has been recorded observes the sticky flag and is rejected (`Revoked`), never committed; two
competing Active epochs are ordered by whoever acquires the lock first, so an older response
cannot commit after a newer one (the loser rolls back). Recording a `Revoked`/`Superseded` is
likewise a single locked step. If an Active's lock precedes the `Revoked`'s, that ordering is
allowed (the Active linearizes first). The early epoch read (for the rollback/conflict
*reason* and its precedence over expiry) is only a hint; the atomic commit is authoritative.

The digest here is the SHA-256 of the response's signed bytes (the whole statement), distinct
from the object digest inside `StatusKey`. **Restart limitation (explicit):** the `hwm`
and the revoked-seen flag are in-memory only; on P restart they reset to empty, so until P
re-observes a `Revoked`, an attacker could replay an older `Active` that is still within its
own `F`/expiry. v0 does not persist the high-water-mark; a real design must persist it or
rely on a short `response_expires_at`. This is a stated limitation, not a solved problem.

## 5. Two different bounds — kept separate

The owner's distinction between *stopping reliance* and *detecting revocation*:

- **Stop accepting Active (policy-only).**
  - *Starting event.* `status_known_at` of the Active response P currently relies on — the
    instant R asserts the status was correct "as of". After that instant R has re-asserted
    nothing, so from P's standpoint the answer only ages.
  - *Clock assumption (the only one here).* a single bound `ε` covers the P-vs-responder
    clock skew (A3). **No** publishing bound (A1) or delivery/cache bound (A2) is used for
    this part; it is a property of P's own decision rule, not of any message arriving.
  - *Claim.* on P's own clock, §4 stops returning Active once `(now+ε) − status_known_at > F`,
    i.e. at `now = status_known_at + F − ε`, after which the object is at best
    `StatusFreshnessUncertain` (Indeterminate) and never Accept; expiry forces the same no
    later than `now = response_expires_at − ε`. Allowing for the ≤ ε skew between the two
    clocks, the elapsed *real* time from the starting event to "P no longer Accepts" is at
    most `F + 2ε` (the `2ε` is the conservative two-sided clock uncertainty). This is a bound
    on when P *ceases to Accept*, **not** a bound on detecting a revocation.
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
- Each object's response defaults: `status = Active`, `status_epoch = 1`, `hwm = None` (empty),
  `status_known_at = 2026-10-15T09:59:00Z`, `published_at = 2026-10-15T09:59:00Z`,
  `response_expires_at = 2026-10-15T11:00:00Z`.
- A case overrides only the fields it names. Session timings reuse experiment.md §11
  (issue at 10:00:00Z, redeem at 10:01:00Z).
- **Multi-step cases** (FB10–FB12, FR17) use one provider high-water-mark shared across the
  steps; their expected value joins the per-step outcomes with ` ; `.

## 9. Proposed case labels (all **proposed**; the implementation's oracle)

In `tests/cases/freshness_cases.toml`, written before the code and now matched by it
(`results/freshness_cases.md`). Labels stay `proposed` until owner review. Expected outcomes
are at the chain status stage (X) unless noted.

### Policy cases

| ID | Situation | Expected |
| --- | --- | --- |
| FR01 | all fresh Active (defaults) | `Accept` |
| FR02 | G `response_expires_at = 2026-10-15T09:59:58Z` (≤ now−ε) | `Indeterminate / X / StatusStale` |
| FR03 | G `status_known_at = 2026-10-15T08:00:00Z` (age_min > F) | `Indeterminate / X / StatusStale` |
| FR04 | G `Revoked`, fresh | `Reject / X / Revoked{G}` |
| FR05 | G `Revoked`; `status_known_at = 08:58:00Z`, `published_at = 08:59:00Z`, `response_expires_at = 09:00:00Z` (expired, structurally valid) | `Reject / X / Revoked{G}` |
| FR06 | C_A `Superseded` | `Reject / X / Superseded{C_A}` |
| FR07 | no response for G's exact `StatusKey` | `Indeterminate / X / StatusUnknown{G}` |
| FR08 | responder/cache unavailable | `Indeterminate / X / StatusUnavailable` |
| FR09 | G `status_known_at = published_at = 10:05:00Z` (> now+ε), `response_expires_at = 11:05:00Z` (ordered) | `Indeterminate / X / StatusTimestampInFuture` |
| FR11 | G valid Active, `status_epoch = 1`, `hwm = 2` (epoch < hwm) | `Indeterminate / X / StatusRollback` |
| FR12 | a valid, K_R-signed Active response for a *different* object is offered for G (its embedded `status_key` ≠ G's) | `Indeterminate / X / StatusUnknown{G}` (not an answer for G; see §3) |
| FR13 | G `Revoked`; `status_known_at = published_at = 08:00:00Z`, `response_expires_at = 08:30:00Z` (stale *and* expired, structurally valid) | `Reject / X / Revoked{G}` (Reject dominates) |
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
| FB06 | G `status_known_at = published_at = 10:00:02Z` (= now+ε), `response_expires_at = 11:00:02Z`: future at the earliest decision instant `now−ε` | `Indeterminate / X / StatusTimestampInFuture` |
| FB07 | G `status_known_at = published_at = 10:00:03Z` (= now+ε+1), `response_expires_at = 11:00:03Z` (future for the whole interval) | `Indeterminate / X / StatusTimestampInFuture` |
| FB08 | G valid Active, `status_epoch = 2`, `hwm = 2` recorded from **this same** signed response (idempotent replay) | `Accept` |
| FB09 | G valid Active, `status_epoch = 2`, `hwm = 2` recorded from a **different** signed response (same-epoch conflict) | `Indeterminate / X / StatusEpochConflict` |
| FB10 | shared HWM: accept an epoch-**0** Active, then replay the identical signed response | `Accept ; Accept` |
| FB11 | shared HWM: accept a newer epoch-2 Active, then present an older epoch-1 Active | `Accept ; Indeterminate / X / StatusRollback` |
| FB12 | shared HWM: a validated `Revoked`, then a newer epoch-2 Active | `Reject / X / Revoked{G} ; Reject / X / Revoked{G}` |

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
| FR17 | one shared HWM: issue with G fresh, advance the clock until the *same* signed G response is stale (challenge and grant still valid), redeem (no consume), then retry with a newer fresh G response | `SessionIndeterminate / chain / ChainIndeterminate(Indeterminate / X / StatusStale) ; SessionAccept` |
| FR18 | RQ6 mediation with a stale-Active G | `Indeterminate / chain / ChainIndeterminate(Indeterminate / X / StatusStale) effects=0` |
| FR19 | RQ6 mediation with a `Revoked` G | `Deny / chain / ChainRejected(Reject / X / Revoked{G}) effects=0` |

**Count:** 34 proposed RQ7 labels (15 policy, 12 boundary, 4 session-issuance, 3
inheritance). None change the existing 94 / 15 / 34 / 28 reviewed outcomes.

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
