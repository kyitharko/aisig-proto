# RQ6 slice — provider-mediated synthetic tool adapter (DRAFT e1, design only)

**Status:** DRAFT e1, 2026-10-16. **Design only — not implemented.** This document and the
proposed labels in `tests/cases/enforcement_cases.toml` are committed for owner review of
the action-to-TestClass mapping (§3) *before* any RQ6 code is written. Builds on the chain
decision (spec r3.1, [spec.md](spec.md)) and the RQ5 session slice ([session.md](session.md)).

## 1. Question and scope

RQ6 asks whether a provider P can confine what an agent actually *does* to the scope a
grant permits. A chain `Accept` says the grant is valid; a `SessionAccept` says a holder of
K_T opened a session under the exact grant. Neither constrains the next tool call. This
slice adds a **provider-side mediation point** that every modeled effect must pass through.
Before any simulated effect occurs, the mediator checks the server-held session
authorization, the operation's *classified* effects (not the agent's claim), the actual
target against the grant's effective scope and exclusions, and the permitted test classes.

**Everything here is synthetic.** Operations, targets, and effects are modeled values. No
real tool runs; nothing contacts or tests any real system. A "simulated effect" is a record
appended to an in-memory sink, nothing more.

**Not claimed (as in [session.md §8](session.md) and [limitations.md](limitations.md)):**
- live tool enforcement, or interception of real processes, syscalls, or network traffic;
- confinement of unmanaged or opaque tools whose effects P cannot observe (§6);
- RQ7 revocation freshness during a session;
- that the modeled effect taxonomy is complete.

A mediator `Allow` means only: *within this synthetic model*, the operation was classified,
its effects were bounded to a target inside the live grant scope, the session was valid and
unexpired, and the permitted class covered it. It is a provider-execution (`ProviderExec`)
decision, still distinct from the owner's authorization.

## 2. Actors and trust

| Item | Source | Trusted? |
| --- | --- | --- |
| mediation request | the agent/tester, untrusted | No. Its `claimed_class` is recorded and **never used** in the decision. |
| operation id, target | the request | Structurally validated; the target is a typed `AssetRef` (spec §2.2). |
| operation table | P's versioned config (`aisig-tooltable/v0`, §3) | Yes — P's own classification. The agent cannot change it. |
| session authorization | P's server-held session store (RQ5 `SessionAuthorization`) | Yes — P's own state, keyed by a server-held `session_ref`. |
| grant scope and test classes | the accepted G, re-verified from the raw bundle at mediation | Bound to the verified payload (spec §7.5); matched to the session's grant ref. |
| clock, chain evidence | P's injected fixtures (spec §6) | Yes. |
| effect sink | P-internal | Yes — the only place a simulated effect is recorded. |

## 3. Versioned operation table `aisig-tooltable/v0`

The mediator classifies an operation **from this table**, never from any agent-supplied
class. This is the mapping the owner is asked to review.

| operation | primary TestClass | target type | modeled effects | secondary effects |
| --- | --- | --- | --- | --- |
| `web.head` | `recon` | Web | {ReadMetadata} | none |
| `web.get` | `recon` | Web | {ReadMetadata, ReadData} | none (single resource) |
| `web.auth_probe` | `auth_testing` | Web | {Authenticate, ReadMetadata} | none |
| `web.injection_probe` | `injection_testing` | Web | {Probe, ReadData} | bounded to the target subtree |
| `web.flood` | `availability_stress` | Web origin | {StressAvailability} | **unbounded** — reaches the whole origin, not confinable to a path |
| `db.read` | `read_only_data_access` | Db | {ReadData} | none |
| `db.write` | `data_modification` | Db | {WriteData} | bounded to the target schema |

- **Effect** ∈ {`ReadMetadata`, `ReadData`, `WriteData`, `Authenticate`, `Probe`,
  `StressAvailability`}. The set is versioned and deliberately small.
- **Footprint.** An effect is *bounded* when its footprint ⊆ the target node's subtree
  (spec §2.2 `within`). `web.get`/`web.head`/`db.read` touch the target node;
  `web.injection_probe`/`db.write` touch the target subtree. *Unbounded* means the effect
  can reach beyond the target (other paths, other tenants) and cannot be confined by scope.
- **target type** fixes which `AssetRef` kind the operation applies to. A mismatch (e.g.
  `db.read` on a Web target) is unclassifiable (§4, stage effects).
- Adding or changing a row is a table-version change; v0 is frozen for this slice.

## 4. Mediation decision

Request: `MediationRequest { bundle, session_ref, operation: String, target: AssetRef,
claimed_class: Option<TestClass> }`. `claimed_class` is logged, never decisive.

`Mediate = Allow(EffectReceipt) | Deny{stage, reason} | Indeterminate{stage, reason}`

Stages run in a fixed order; the first `Deny` ends evaluation, an `Indeterminate` is
recorded and evaluation continues only where the missing evidence is not required, and
`Allow` requires every stage positive. The effect sink is invoked **only** at `perform`,
exactly once, and never on `Deny`/`Indeterminate` (so a non-Allow performs zero effects).

1. **session** — load `SessionAuthorization` by `session_ref` from P's session store.
   - store unavailable → `Indeterminate(SessionStateUnavailable)`;
   - no authorization for `session_ref` → `Deny(DenyNoSession)`.
2. **expiry** — clock `(now, ε)` vs the session's `grant_window_end` (half-open, spec §6).
   Checked here, before the chain re-verification, so it is reachable with the clock still
   in hand. In s1 `grant_window_end = G.window.end`, so a session that is past its window
   is caught here rather than at the chain's time stage; the stage is kept explicit so a
   future session-scoped TTL (tighter than the grant) has a home.
   - clock unavailable → `Indeterminate(ClockUnavailable)`;
   - `now − ε ≥ grant_window_end` → `Deny(DenySessionExpired)`;
   - straddling the edge → record `Indeterminate(ClockUncertainty)`.
3. **chain** — re-verify `bundle` with `ChainVerifier` (spec §7), as RQ5 redemption does.
   - chain `Reject` → `Deny(ChainRejected(<chain decision>))`;
   - chain `Indeterminate` → record `Indeterminate(ChainIndeterminate(<chain decision>))`
     and continue only to find a `Deny`;
   - the bundle's G `StatusKey` must equal the session authorization's grant ref →
     else `Deny(DenyGrantMismatch)`.
4. **classify** — look `operation` up in `aisig-tooltable/v0`.
   - not present → `Deny(DenyUnknownOperation)` (fail closed; P mediates only modeled ops).
5. **effects** — using the table row:
   - target kind ≠ the row's target type → `Deny(DenyUnclassifiableEffect)`;
   - the row has unbounded secondary effects → `Deny(DenyUnboundedSecondaryEffect)`.
6. **scope** — the effect footprint against the accepted G's effective scope (spec §4):
   - node-footprint ops: `exact_node_lookup(G, target)` — `Excluded` →
     `Deny(DenyTargetExcluded)`, `OutOfScope` → `Deny(DenyTargetOutOfScope)`;
   - subtree-footprint ops: `subtree_lookup(G, target)` — anything other than
     `WhollyAllowed` → `Deny(DenyTargetExcluded)` if any descendant is excluded, else
     `Deny(DenyTargetOutOfScope)`.
7. **class** — the row's primary TestClass must be permitted by G's `test_scope`
   (`Unrestricted`, or a `Classes` set containing it) → else
   `Deny(DenyTestClassNotPermitted)`.
8. **perform** — reached only if nothing was recorded as Indeterminate. Append exactly one
   `EffectReceipt { session_ref, operation, target, test_class, effects, performed_at }` to
   the sink and return `Allow(receipt)`. If an Indeterminate was recorded, return it instead
   (no effect).

`EffectReceipt` fields are private; the only constructor is a successful `perform`, so an
`Allow`/receipt cannot be fabricated (mirrors `SessionAuthorization`, spec §7.5).

**Display:** `Allow effects=1`, or `Deny / <stage> / <Reason> effects=0`, or
`Indeterminate / <stage> / <Reason> effects=0`. Every non-Allow carries `effects=0`, so the
"zero effects after denial" property is visible in every label.

## 5. Precise non-Allow outcomes

| Condition | Outcome |
| --- | --- |
| unknown operation (no table row) | `Deny / classify / DenyUnknownOperation` |
| target kind ≠ operation's target type (unclassifiable) | `Deny / effects / DenyUnclassifiableEffect` |
| operation has unbounded secondary effects | `Deny / effects / DenyUnboundedSecondaryEffect` |
| session store unavailable | `Indeterminate / session / SessionStateUnavailable` |
| chain evidence unavailable (status/clock/registry) | `Indeterminate / chain / ChainIndeterminate(...)` |
| clock unavailable (checked at expiry, before chain) | `Indeterminate / expiry / ClockUnavailable` |
| any of the above Indeterminates | effect sink untouched (`effects=0`) |

Deny vs Indeterminate rule: **Deny** means the mediator refuses a fully-evidenced action
(unknown/unclassifiable/unbounded/out-of-scope/wrong-class/expired/no-session/grant-
mismatch). **Indeterminate** means P could not decide because its own evidence was missing;
it never performs an effect and never becomes Allow. Reject/Deny dominates Indeterminate.

## 6. How every effect passes through the mediator; bypass paths

In this synthetic model the sink is append-only and private, and the single writer is
`perform` (stage 8). So a modeled effect exists iff a mediation returned `Allow`. The
property to test: over all non-Allow cases, the sink length is unchanged.

Bypass paths and their disposition:
- **An agent that calls a real tool directly, not through the mediator.** Outside the
  synthetic model: we model only mediated operations. Real enforcement would need the
  provider to be the sole execution path (sandbox, egress control); not claimed here.
- **Unmanaged or opaque tools whose effects P cannot observe or classify.** Outside the
  model. Where such an effect *is* surfaced to the mediator, it classifies as an unbounded
  or unclassifiable effect and is denied (stage effects).
- **An operation with a side effect the table does not list.** Modeled as the table being
  wrong; the mitigation is table review (this document) and the unbounded/unclassifiable
  denials, not a runtime guarantee.
- **Replaying an old session_ref after the grant expired.** Caught at expiry (stage 3).
- **Presenting a different bundle than the session was authorized for.** Caught at chain
  (grant-ref match, stage 2).

## 7. Reuse and boundaries

- Scope uses the existing `exact_node_lookup` / `subtree_lookup` (spec §4.4); no new scope
  math.
- The chain is re-verified through `ChainVerifier::verify` only; no pre-decoded path
  (spec §7.5).
- The session authorization is read from P's store by a server-held `session_ref`, never
  from the request body.
- The mediator is a `ProviderExec` decision and does not alter `ValidChain_P` or
  `SessionAuth`; the 93 chain, 15 lookup, and 28 session labels are untouched by this slice.

## 8. Open questions for owner review

1. The `aisig-tooltable/v0` mapping in §3: are the primary classes and the bounded/unbounded
   calls right? In particular, should `web.get` count as `ReadData` (so a read of an
   excluded page is denied at scope) or only `ReadMetadata`?
2. Subtree-footprint ops under `PartiallyAllowed`: deny (current proposal) or allow on the
   allowed part only? v0 denies, to avoid partial effects.
3. Should a `claimed_class` that contradicts the table be merely ignored (current) or itself
   a logged `Deny` for owner-visible misuse signals?
4. Is `availability_stress` always unbounded, or bounded when the target is a single path
   that P can rate-limit? v0 treats it as unbounded.
5. Expiry uses `grant_window_end` from the session authorization. Should the mediator also
   re-read live status (RQ7) rather than trust the session's window? Deferred to RQ7.
