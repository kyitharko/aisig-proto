# RQ6 slice — provider-mediated synthetic tool adapter (DRAFT e2, design only)

**Status:** DRAFT e2, 2026-10-16. **Design only — not implemented.** This document and the
proposed labels in `tests/cases/enforcement_cases.toml` are committed for owner review of
the action-to-TestClass mapping (§3) *before* any RQ6 code is written. The labels stay
**proposed**. Builds on the chain decision (spec r3.1, [spec.md](spec.md)) and the RQ5
session slice ([session.md](session.md)).

## 1. Question and scope

RQ6 asks whether a provider P can confine what an agent actually *does* to the scope a
grant permits. A chain `Accept` says the grant is valid; a `SessionAccept` says a holder of
K_T opened a session under the exact grant. Neither constrains the next tool call. This
slice adds a **provider-side mediation point** that every modeled effect must pass through.
Before any simulated effect occurs, the mediator validates the target, then checks the
server-held session authorization, re-verifies the chain, classifies the operation's
effects *from P's table* (not the agent's claim), checks the target against the grant's
effective scope and exclusions, and checks the permitted test classes.

**Everything here is synthetic.** Operations, targets, and effects are modeled values. No
real tool runs; nothing contacts or tests any real system. A "simulated effect" is a record
appended to an in-memory sink, nothing more.

**Not claimed (as in [session.md §8](session.md) and [limitations.md](limitations.md)):**
- live tool enforcement, or interception of real processes, syscalls, or network traffic;
- confinement of unmanaged or opaque tools whose effects P cannot observe (§6);
- that the modeled effect taxonomy is complete.

**Status is re-checked every action.** The chain stage (§4 stage 4) re-runs the full chain
verification, including the status stage (spec §6 stage X), on each mediation. A grant
revoked before the action is therefore denied. What remains unresolved (RQ7) is the
*freshness of the status source itself* — how current P's status fixture/service is, and
the bounded delay before a real revocation propagates — not whether status is consulted.

A mediator `Allow` means only: *within this synthetic model*, the target was canonical, the
operation was classified, its effects were bounded to a target inside the live grant scope,
the session was valid and unexpired, the chain re-verified (status included), and the
permitted class covered it. It is a provider-execution (`ProviderExec`) decision, still
distinct from the owner's authorization.

## 2. Actors and trust

| Item | Source | Trusted? |
| --- | --- | --- |
| mediation request | the agent/tester, untrusted | No. Its `claimed_class` is recorded and **never used** in the decision. |
| `session_ref` | P's **authenticated server-side session context** (§4a), not the request | Yes — P's own state. It is never an agent-supplied field. |
| operation id, target (wire form) | the request | The target is decoded and canonical-validated before use (§4 stage validate). |
| operation table | P's versioned config (`aisig-tooltable/v0`, §3) | Yes — P's own classification. The agent cannot change it. |
| session authorization | P's server-held session store (RQ5 `SessionAuthorization`) | Yes — P's own state, keyed by the server-held `session_ref`. |
| grant scope and test classes | the accepted G, re-verified from the raw bundle at mediation | Bound to the verified payload (spec §7.5); matched to the session's grant ref. |
| clock, chain evidence | P's injected fixtures (spec §6) | Yes. |
| effect sink | P-internal (`EffectSink`, a concrete in-memory type; its append is module-private, callable only by `perform`; external callers get read-only `len`/`receipts`) | Yes — the only place a simulated effect is recorded. There is no public sink trait to implement and no public append, so a cloned `EffectReceipt` cannot drive a second append. |

## 3. Versioned operation table `aisig-tooltable/v0`

The mediator classifies an operation **from this table**, never from any agent-supplied
class. This is the mapping the owner is asked to review.

| operation | primary TestClass | target type | modeled effects | footprint / secondary effects |
| --- | --- | --- | --- | --- |
| `web.head` | `recon` | Web | {ReadMetadata} | node; none |
| `web.get` | `read_only_data_access` | Web | {ReadMetadata, ReadData} | node; none |
| `web.auth_probe` | `auth_testing` | Web | {Authenticate, ReadMetadata} | node; none |
| `web.injection_probe` | `injection_testing` | Web | {Probe, ReadData} | subtree; bounded to the target subtree |
| `web.flood` | `availability_stress` | Web | {StressAvailability} | **unbounded** — reaches the whole origin, not confinable to a path |
| `db.read` | `read_only_data_access` | Db | {ReadData} | node; none |
| `db.write` | `data_modification` | Db | {WriteData} | subtree; bounded to the target schema |

- **Primary TestClass** is the single class the class stage checks against the grant
  (§4 stage class). `web.get` is `read_only_data_access` (it returns resource content, not
  only metadata); `web.head` is `recon` (metadata only). A grant must permit a GET's class
  to read a resource, but an **excluded or out-of-scope target is denied at the scope stage
  first, regardless of TestClass** (scope precedes class in §4).
- **Modeled effects** are descriptive: they drive the footprint and boundedness decisions
  (§4 stage effects). They are **not** separately re-mapped to TestClasses. In particular,
  `web.injection_probe` is a single `injection_testing` operation whose modeled effects are
  a `Probe` plus the `ReadData` of the probe's response; both are covered by the one
  `injection_testing` class, so reading a probe response does **not** additionally require
  `read_only_data_access`. The class stage checks only the primary class.
- **Effect** ∈ {`ReadMetadata`, `ReadData`, `WriteData`, `Authenticate`, `Probe`,
  `StressAvailability`}. The set is versioned and deliberately small.
- **Footprint.** *node* ops (`web.head`, `web.get`, `db.read`) touch only the target node;
  *subtree* ops (`web.injection_probe`, `db.write`) touch the target's subtree; an
  *unbounded* op (`web.flood`) can reach beyond the target (the whole origin, other tenants)
  and cannot be confined by scope. `web.flood`'s target type is `Web` (any web asset); a
  path target such as `/app` is type-valid, and it is the unbounded **footprint**, not the
  target, that reaches the origin — which is exactly why it is denied at the effects stage.
- **target type** fixes which `AssetRef` kind the operation applies to. A mismatch (e.g.
  `db.read` on a Web target) is a target-type mismatch (§4 stage effects).
- Adding or changing a row is a table-version change; v0 is frozen for this slice.

## 4. Mediation decision

Request (agent-supplied, untrusted): `MediationRequest { bundle, operation: String,
target_wire, claimed_class: Option<TestClass> }`. There is **no `session_ref` field**;
`claimed_class` is logged, never decisive. `target_wire` is the target in its canonical
wire form (the same form a grant target uses), not a pre-built `AssetRef` (§4a, stage
validate).

`Mediate = Allow(EffectReceipt) | Deny{stage, reason} | Indeterminate{stage, reason}`

Stages run in a fixed order; the first `Deny` ends evaluation, an `Indeterminate` is
recorded and evaluation continues only where the missing evidence is not required, and
`Allow` requires every stage positive. The effect sink is invoked **only** at `perform`,
exactly once, and never on `Deny`/`Indeterminate` (so a non-Allow performs zero effects).

1. **validate** — decode `target_wire` into an `AssetRef` through the *validated* decode
   path (spec §2.2 / §3: decode, then canonical re-encode and require byte equality). A
   malformed or non-canonical target (e.g. uppercase host, `..`, trailing slash, wildcard)
   → `Deny(DenyNoncanonicalTarget)`. The value produced here is the one used by the scope
   stage and by `perform`; no other target enters the pipeline (§4a).
2. **session** — load `SessionAuthorization` by the authenticated `session_ref` (§4a).
   - store unavailable → `Indeterminate(SessionStateUnavailable)`;
   - no authorization for `session_ref` → `Deny(DenyNoSession)`.
3. **expiry** — the mediator reads the clock **once** here, at the start of the
   decision, into a single snapshot `(now, ε)` used by this stage, by the chain-time check
   (stage 4), and by the receipt (stage 9). It is never re-read. ε is clamped to ≥ 0 and the
   `now ± ε` bounds saturate (no overflow). Check vs the session's `grant_window_end`
   (half-open, spec §6); in s1 `grant_window_end = G.window.end`, and the stage is kept
   explicit so a future session-scoped TTL (tighter than the grant) has a home.
   - clock unavailable → `Indeterminate(ClockUnavailable)` (recorded; the snapshot is then
     empty and stages 4 and 9 see the same absence);
   - `now − ε ≥ grant_window_end` → `Deny(DenySessionExpired)`;
   - straddling the edge → record `Indeterminate(ClockUncertainty)`.
4. **chain** — re-verify `bundle` with `ChainVerifier` (spec §7, status stage included)
   **against the stage-3 snapshot** (the mediator runs the chain verification with a clock
   frozen to that snapshot, so the chain-time check uses the same instant as expiry), as
   RQ5 redemption does.
   - chain `Reject` → `Deny(ChainRejected(<chain decision>))` (this is how a grant revoked
     before the action is denied: `ChainRejected(Reject / X / Revoked{G})`);
   - chain `Indeterminate` → record `Indeterminate(ChainIndeterminate(<chain decision>))`
     and continue only to find a `Deny`;
   - the bundle's G `StatusKey` must equal the session authorization's grant ref →
     else `Deny(DenyGrantMismatch)`.
5. **classify** — look `operation` up in `aisig-tooltable/v0`.
   - not present → `Deny(DenyUnknownOperation)` (fail closed; P mediates only modeled ops).
6. **effects** — using the table row:
   - target kind ≠ the row's target type → `Deny(DenyTargetTypeMismatch)`;
   - the row is unbounded → `Deny(DenyUnboundedSecondaryEffect)`.
7. **scope** — the validated target against the accepted G's effective scope (spec §4):
   - *node*-footprint ops: `exact_node_lookup(G, target)` — `Excluded` →
     `Deny(DenyTargetExcluded)`, `OutOfScope` → `Deny(DenyTargetOutOfScope)`;
   - *subtree*-footprint ops: `subtree_lookup(G, target)` — `PartiallyAllowed` →
     `Deny(DenySubtreePartiallyAllowed)`, `NoneAllowed` → `Deny(DenySubtreeNoneAllowed)`.
     These two reasons are exactly the two non-`WhollyAllowed` results the lookup returns, so
     the reason is always derivable from the lookup alone. The name says only what the lookup
     found — *part of the subtree is allowed* — not *why* the rest is not. A subtree can be
     `PartiallyAllowed` **with no explicit exclusion at all**: e.g. a grant that targets only
     `db:cluster1/main/billing` makes `db:cluster1/main` partially allowed (its `billing`
     child is in scope; its `hr` child is merely out of scope, not excluded).
     `subtree_lookup` does **not** separate "excluded" from "out of scope" for a whole
     subtree, so the reason stays at the granularity the lookup supports —
     `DenySubtreePartiallyAllowed` is the honest label.
8. **class** — the row's primary TestClass must be permitted by G's `test_scope`
   (`Unrestricted`, or a `Classes` set containing it) → else
   `Deny(DenyTestClassNotPermitted)`.
9. **perform** — reached only if nothing was recorded as Indeterminate. Append exactly one
   `EffectReceipt { session_ref, operation, target, test_class, effects, performed_at }`,
   using the **validated** target from stage 1, to the sink and return `Allow(receipt)`. The
   mediator does **not** read the clock here: `performed_at` is the stage-3 snapshot instant
   (the same `now` used for the expiry and chain-time checks), i.e. the single decision-time
   instant at which this action was authorized, not a separate post-decision read. (Reaching
   perform implies the snapshot was present, since an absent snapshot is recorded
   Indeterminate at expiry.) If an Indeterminate was recorded, return it instead (no
   effect).

`EffectReceipt` fields are private; the only constructor is a successful `perform`, so an
`Allow`/receipt cannot be fabricated (mirrors `SessionAuthorization`, spec §7.5).

**Display:** `Allow effects=1`, or `Deny / <stage> / <Reason> effects=0`, or
`Indeterminate / <stage> / <Reason> effects=0`. Every non-Allow carries `effects=0`, so the
"zero effects after denial" property is visible in every label.

### 4a. API boundary: who supplies `session_ref` and the target

- `session_ref` is **not** part of `MediationRequest`. The mediator's entry point takes it
  as a separate argument that P's server passes from its authenticated session context (the
  signed-in account / agent-run identity), exactly as RQ5 `redeem` takes `session_id`
  (session.md §7). An agent cannot name another session's `session_ref` by putting it in the
  request body, because there is no such field.
- The target enters as `target_wire` (canonical wire form), not as a constructed
  `AssetRef`. The mediator builds the `AssetRef` itself through the validated decode path
  (stage validate). A caller cannot hand the mediator an `AssetRef` assembled from public
  struct fields with a non-canonical host or path, because the mediator's input type is the
  wire form, not `AssetRef`. (Note for the eventual implementation: `AssetRef`'s inner
  structs currently expose public fields; the mediator must take `target_wire` and validate
  it, so a directly-constructed `AssetRef` never reaches scope or `perform`.)

## 5. Precise non-Allow outcomes

| Condition | Outcome |
| --- | --- |
| non-canonical or malformed target | `Deny / validate / DenyNoncanonicalTarget` |
| unknown operation (no table row) | `Deny / classify / DenyUnknownOperation` |
| target kind ≠ operation's target type | `Deny / effects / DenyTargetTypeMismatch` |
| operation is unbounded | `Deny / effects / DenyUnboundedSecondaryEffect` |
| node target excluded / out of scope | `Deny / scope / DenyTargetExcluded` / `DenyTargetOutOfScope` |
| subtree partly in scope / wholly out | `Deny / scope / DenySubtreePartiallyAllowed` / `DenySubtreeNoneAllowed` |
| primary class not in the grant's test scope | `Deny / class / DenyTestClassNotPermitted` |
| no session / grant mismatch / expired | `Deny / session / DenyNoSession`, `Deny / chain / DenyGrantMismatch`, `Deny / expiry / DenySessionExpired` |
| grant revoked / tampered (chain) | `Deny / chain / ChainRejected(...)` |
| session store unavailable | `Indeterminate / session / SessionStateUnavailable` |
| chain evidence unavailable (status/registry) | `Indeterminate / chain / ChainIndeterminate(...)` |
| clock unavailable (checked at expiry, before chain) | `Indeterminate / expiry / ClockUnavailable` |
| any Indeterminate | effect sink untouched (`effects=0`) |

Deny vs Indeterminate rule: **Deny** means the mediator refuses a fully-evidenced action.
**Indeterminate** means P could not decide because its own evidence was missing; it never
performs an effect and never becomes Allow. Reject/Deny dominates Indeterminate.

## 6. How every effect passes through the mediator; bypass paths

In this synthetic model the sink is append-only and private, and the single writer is
`perform` (stage 9). So a modeled effect exists iff a mediation returned `Allow`. The
property to test: over all non-Allow cases, the sink length is unchanged.

Bypass paths and their disposition:
- **An agent that calls a real tool directly, not through the mediator.** Outside the
  synthetic model: we model only mediated operations. Real enforcement would need the
  provider to be the sole execution path (sandbox, egress control); not claimed here.
- **Unmanaged or opaque tools whose effects P cannot observe or classify.** Outside the
  model. Where such an effect *is* surfaced to the mediator, it classifies as an unbounded
  or target-type-mismatched effect and is denied (stage effects).
- **An operation with a side effect the table does not list.** Modeled as the table being
  wrong; the mitigation is table review (this document) and the unbounded/type-mismatch
  denials, not a runtime guarantee.
- **A non-canonical target smuggled in to dodge scope.** Caught at validate (stage 1); the
  scope stage and `perform` only ever see the validated target.
- **A cloned receipt driving a second effect.** Impossible: the sink's append is
  module-private (only `perform` calls it); external code can read `len`/`receipts` but
  cannot append, so holding a cloned `EffectReceipt` grants no second effect.
- **Naming another session.** Impossible via the request: `session_ref` comes from P's
  authenticated context (stage session, §4a), not a request field.
- **Replaying a session after the grant expired.** Caught at expiry (stage 3).
- **Presenting a different bundle than the session was authorized for.** Caught at chain
  (grant-ref match, stage 4).

## 7. Reuse and boundaries

- Scope uses the existing `exact_node_lookup` / `subtree_lookup` (spec §4.4); no new scope
  math.
- The chain is re-verified through `ChainVerifier::verify` only; no pre-decoded path
  (spec §7.5).
- The session authorization is read from P's store by the authenticated `session_ref`,
  never from the request body.
- The mediator is a `ProviderExec` decision and does not alter `ValidChain_P` or
  `SessionAuth`; the 93 chain, 15 lookup, and 28 session labels are untouched by this slice.

## 8. Open questions for owner review

1. The `aisig-tooltable/v0` mapping in §3: are the primary classes and the
   node/subtree/unbounded calls right?
2. Subtree-footprint ops under `PartiallyAllowed` are denied whole (no partial effects). Is
   that the desired policy, or should v0 ever act on the allowed part? v0 denies.
3. Should a `claimed_class` that contradicts the table be merely ignored (current,
   audit-only) or itself a logged `Deny` for owner-visible misuse signals?
4. `availability_stress` / `web.flood` is treated as always unbounded. Is there a bounded
   form (a single rate-limited path) worth modeling later?
5. Expiry uses `grant_window_end` from the session authorization, and the chain stage
   re-checks status each action. The open RQ7 item is the status source's freshness and
   bounded revocation-propagation delay, not whether status is re-checked.
