# Threat model — RQ4 chain verifier and RQ5 session slice (DRAFT r3.1 + s1)

**Status:** DRAFT r3.1, 2026-10-15. See [spec.md](spec.md) for symbols.

## 1. System and trust boundary

```
 P registry (pinned R_O) ──► C_A  (K_O → K_admin, admin rights + bounds)
                              │
                              ▼
                             D_U  (K_admin → K_authorizer, may-issue envelope)
                              │
                              ▼
                              G   (K_authorizer → K_T, may-test scope + window)
                              │
                              ▼
         ValidChain_P(G,t) ── Accept / Reject / Indeterminate
```

Trusted for this slice: P's own root registry, asset-binding fixture, clock and status
fixture (trusted to answer honestly for the key it is asked, but the verifier still checks
that a returned registry record names O and Ed25519, and asks the status source only about
the exact signed object); the Ed25519 implementation; the secrecy of K_O, K_admin, K_authorizer unless a
case says otherwise.

Untrusted: every byte in the presented bundle, including the optional self-signed root
(which the chain-aware verifier never reads), envelope key hints, and payload contents
before their signature verifies.

## 2. Actors

| Actor | Role | May be adversarial? |
| --- | --- | --- |
| O | Owner; defines testing permission | Honest in v0 (owner fraud is RQ1/legal) |
| Admin (K_admin) | Holds C_A rights | Yes: may try to exceed C_A |
| Authorizer (K_authorizer) | Issues G under D_U | Yes: may try to exceed D_U |
| Tester T | Holds G | Yes: may edit, replay or re-target G |
| Outsider | No key in the chain | Yes: may forge roots or splice objects |
| Other tenant O' | Legitimate org with its own chain | Yes: may target O's assets |
| P | Verifier | Trusted for its own decisions |

## 3. Threats in scope (and where they are decided)

| ID | Threat | Expected defence (stage) | Case groups |
| --- | --- | --- | --- |
| TH1 | Self-signed or copied root claiming O | Registry pin; `root` slot never read (N) | R01, R02, V09, V10 |
| TH2 | Admin without explicit delegation right issues D_U | `may_delegate_grant_issuer` required (P) | D01 |
| TH3 | Admin or authorizer widens assets, test classes, duration, validity or constraints | ScopeWithin / ceilings (P) | D, M |
| TH4 | Tester edits a signed grant (adds targets) | Signature over exact bytes (S) | S |
| TH5 | Object splicing: wrong parent, wrong issuer key, skipped D_U | Linkage + required objects (F, L) | D |
| TH6 | Type confusion: D_U presented as G, or signature reused across types | Bundle slot type + domain-separated signed bytes (F, S) | S07, D10 |
| TH7 | Parser differentials: duplicate keys, reordering, whitespace, unknown fields, non-canonical times/assets | Strict decode + canonical re-encode (F) | S, F, M, T |
| TH8 | Path/name confusion: `/application` vs `/app`, `..`, case, wildcards, ports, scheme | Canonical assets + segment-prefix `within` (F, P) | M |
| TH9 | Include/exclude overlap misread | Allowed = Included \ Excluded, mandatory exclusions (P) | M, Q, U |
| TH10 | Cross-tenant use: sibling org assets or org_id swap | Linkage org_id + binding fixture (L, B) | M02, B02 |
| TH11 | Cross-provider replay | Audience = P (L) | A |
| TH12 | Expired / not-yet-valid / revoked / superseded authority | Time and status stages (T, X) | T, X |
| TH13 | Unknown critical constraint silently ignored (permission widened) | **Reject** at policy stage (`UnsupportedCriticalConstraint`), never Accept (P) | F01, F02 |
| TH14 | Missing evidence treated as approval | Indeterminate; Reject-dominates order; conditional evaluation never yields Accept (spec §7.2) | B, R04, X04, X05, T10, P |
| TH15 | Scope-shape differentials: redundant or self-cancelling targets read differently by different verifiers | Admissibility rule (P) | M20, SO1, SO2 |
| TH16 | Omitted test scope read as "unrestricted" | `test_scope` required; `unrestricted` must be explicit and signed (F, P) | M08, M21, V06 |
| TH17 | Status substitution: a newly signed object reuses another object's id/version (same or different type) to inherit its Active status | Status keyed by exact StatusKey incl. SHA-256 of type-separated signed bytes; no match → Indeterminate, never Accept (X) | X07, X08, X09, property |
| TH18 | Misfiled or mismatched registry record: the record returned for O names another org, or a different algorithm | Anchor checks record.org_id and record.algorithm, not just the lookup key; fails closed (N) | R07, R08 |
| TH19 | Exact-node lookup misread as a subtree permission (`/app` InScope although `/app/admin` is excluded) | Separate `exact_node_lookup` and `subtree_lookup` APIs with effective-set semantics for the latter; still not enforcement | Q11, U01–U04, SO3 |
| TH20 | API caller (integrating code) runs policy on a decoded body that differs from the verified payload | Single public entry point `verify(&Bundle)`; decoded objects read-only; pre-decoded evaluation private (spec §7.5) | tests/predecoded_api.rs, verifier doctests |

## 3a. RQ5 session-slice threats (s1, reviewed; see [session.md](session.md))

| ID | Threat | Expected defence (session stage) | Cases |
| --- | --- | --- | --- |
| TH21 | A copied bundle is used by someone without K_T's private key | Proof of possession over a P-issued challenge with K_T from the accepted G (proof, pop) | SS02, SS04 |
| TH22 | Replay of a valid proof, including concurrent replay | One-time atomic Pending→Consumed (challenge, consume) | SS05, SS22 |
| TH23 | A proof minted for one P session is used in another | session_id stored in the challenge and compared with P's own session (binding) | SS06 |
| TH24 | A proof for one grant is used with another grant | Challenge bound to the exact StatusKey of G, including the digest (binding) | SS07 |
| TH25 | A foreign-audience record present in the store (fault-injected; s1 assumes a P-private store) | Audience in the stored challenge rejected at binding; audience says which provider a challenge is *for*, not who wrote it — shared-store provenance is future work | SS08 |
| TH26 | Stale proofs; a challenge outliving its grant | Expiry with clock uncertainty; expiry clamped to G.window.end (time, issuance) | SS09–SS11, SI04 |
| TH27 | Rebinding by editing the challenge copy or the proof; cross-protocol signature reuse | Signed bytes rebuilt from P's stored record; distinct domain tag; strict proof parsing (pop, proof) | SS17, SS18, SS19 |
| TH28 | Grant altered, revoked or expired between issuance and redemption | Chain re-verified at redemption (chain) | SS14, SS23 |
| TH29 | An evidence outage yields SessionAccept, or burns the challenge | Indeterminate never accepts and never consumes; failed attempts do not consume (chain, challenge, time) | SS12, SS15, SS20, SS21, SS24 |

Out of scope for s1, stated so that no one reads them as defended:
- relay or phishing of a challenge into an attacker's own P session;
- TLS or channel binding;
- the session becoming a bearer state after redemption (no per-request proof of possession);
- compromise of K_T;
- RQ6 tool enforcement;
- RQ7 status freshness during a session.

## 3b. RQ6 enforcement-slice threats (e1, design only; see [enforcement.md](enforcement.md))

These are proposed with the design; **no RQ6 code exists yet**.

| ID | Threat | Expected defence (mediation stage) | Cases |
| --- | --- | --- | --- |
| TH30 | An agent acts outside the granted scope through a tool | Mediator checks the validated target against the live grant's effective scope/exclusions before any effect; a subtree only partly in scope is denied whole (scope) | EE05-EE09, EE24 |
| TH31 | An agent mislabels its action to dodge the class check | Operation classified from the versioned table `aisig-tooltable/v0`, never from the agent's claim (classify, class) | EE10-EE12 |
| TH32 | An unmodeled op or a wrong-typed target slips through | Unknown op and target-type mismatch fail closed (classify, effects) | EE13, EE14 |
| TH33 | An operation with effects beyond the target (whole origin, other tenants) | Unbounded secondary effects denied (effects) | EE15 |
| TH34 | Acting after the session/grant window, with no session, or naming another session | `session_ref` from P's authenticated context (not a request field); session-window expiry; grant-ref match (session, expiry, chain) | EE16, EE17, EE18 |
| TH35 | A tampered or revoked grant used at action time | Chain (status stage included) re-verified at mediation; the open RQ7 item is status-source freshness, not whether status is checked (chain) | EE22, EE26 |
| TH36 | An evidence outage produces an effect | Indeterminate never performs an effect; every non-Allow is effects=0 (session, expiry, chain) | EE19-EE21 |
| TH37 | A non-canonical target smuggled past scope, or a directly-built `AssetRef` bypassing validation | Target decoded and canonical-validated before scope; the mediator takes the wire form, not a pre-built `AssetRef` (validate) | EE25 |
| TH38 | A GET-style read of an excluded resource treated as mere metadata | `web.get` classed `read_only_data_access`, but an excluded/out-of-scope target is denied at scope before the class check (scope) | EE05-EE07, EE23 |

Out of scope for e1, stated so none is read as defended:
- interception of real tools, processes, syscalls or network traffic (only modeled effects);
- confinement of unmanaged/opaque tools P cannot observe;
- completeness of the modeled effect taxonomy;
- RQ7 status freshness during a session (the mediator trusts the session window).

## 3c. RQ7 status-freshness threats (f2; see [freshness.md](freshness.md))

Implemented behind the freshness-slice runner; the 31 labels remain `proposed` pending owner
review. The status stage is shared by all three decision paths (chain, session redemption,
mediation), so these apply everywhere status is checked.

| ID | Threat | Expected defence (status stage) | Cases |
| --- | --- | --- | --- |
| TH39 | Relying on a stale Active after a real revocation | Whole-interval freshness bound F + response expiry; any boundary overlap → Indeterminate, never Accept (X) | FR02, FR03, FR17, FR18, FB02, FB04, FB05 |
| TH40 | Revocation hidden by an expired/stale responder answer | Revoked/Superseded is monotonic and sticky → Reject regardless of freshness; Reject dominates Indeterminate (X) | FR04, FR05, FR13, FR16, FR19 |
| TH41 | Replay/rollback to an older Active, or two different signed answers at one epoch | Per-StatusKey monotonic high-water-mark with the accepted response's digest; older epoch → `StatusRollback`, same epoch + different signed response → `StatusEpochConflict`; identical replay is idempotent (X) | FR11, FB08, FB09 |
| TH42 | Replaying another object's Active | Exact StatusKey (incl. digest) must match → else StatusUnknown (X) | FR12 |
| TH43 | Future-dated, mis-ordered, or wrongly-signed responder statement | whole-interval future check (`max(status_known_at, published_at) ≤ now−ε`); ordered timestamps; responder signature under a pinned key → else Indeterminate (X) | FR09, FR14, FR15, FB06, FB07 |
| TH44 | Unavailable status source silently accepted | Unavailable/unknown → Indeterminate, never Accept (X) | FR07, FR08, FS04 |

Out of scope for f2, stated so none is read as defended:
- a real responder protocol (OCSP/CRL/transparency log), real network or cache behavior;
- a numeric revocation-detection bound: the U + Dd + ε figure is a conjecture conditional on unproved assumptions A1–A3 (freshness.md §6), withdrawn as a claim;
- persisting the high-water-mark across restarts in a real, non-bottleneck way;
- clock synchronization between the responder and P beyond the modeled ε.



- **Stolen-grant presentation** by someone other than T is addressed by RQ5 slice s1 (proof of possession, docs/session.md §8 limits): the chain-only v0 decision does **not** bind a presenter, while s1 adds a separate session proof of possession under its stated limits (no channel binding, no relay resistance).
- **Agent actions outside scope** at runtime against *real* tools; confinement of unmanaged/opaque tools; completeness of the effect taxonomy (RQ6). The synthetic mediator in [enforcement.md](enforcement.md) (§3b) is implemented for modeled operations only; it does not enforce real tools.
- **Revocation latency** and cache staleness in a real distributed status service (RQ7).
- **Real organization identity proof** and first-admin authority (RQ1).
- **Real asset ownership**, shared/third-party hosting, and legal testing rights (RQ2; legal).
- Compromise of K_O or of P itself; side channels; denial of service against the verifier.
- Privacy of chain metadata disclosed to P (RQ8).

## 5. What the evaluation can and cannot show

**Empirical: agreement with reviewed labels.** The test suite checks that the
implementation's decision, stage and reason equal the owner-reviewed label for each
case, and that property-based mutations behave as their mutation kind predicts. Passing
shows that this implementation agrees with these labels on these inputs. It does not
show that the spec is correct, that the labels are complete, or that untested inputs
behave well.

**Formal: not claimed.** No machine-checked proof of soundness or completeness exists.
The only formal argument is the proof sketch for the ScopeWithin/admissibility lemma
(spec §4.3), which a brute-force oracle cross-checks on a finite synthetic universe.
Soundness in the formal sense — every Accept is a valid chain under the spec, for every
input — remains a proof obligation.

**Baseline hypotheses (to be measured, not assumed).** The signature-only baseline is
*expected* to Accept TH1–TH3, TH5 and TH8–TH16 cases whose signatures are valid, and to
Reject V09/V10 because it needs the root slot. These are hypotheses about the baseline.
The measured counts in `results/` are authoritative, including any place where the
hypothesis turns out wrong.
