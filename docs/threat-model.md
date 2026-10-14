# Threat model — RQ4 chain verifier (DRAFT v0)

**Status:** DRAFT for owner review, 2026-10-15. See [spec.md](spec.md) for symbols.

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
fixture; the Ed25519 implementation; the secrecy of K_O, K_admin, K_authorizer unless a
case says otherwise.

Untrusted: every byte in the presented bundle, including any self-signed root, envelope
key hints, and payload contents before their signature verifies.

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
| TH1 | Self-signed or copied root claiming O | Registry pin; bundle root ignored (N) | R |
| TH2 | Admin without explicit delegation right issues D_U | `may_delegate_grant_issuer` required (P) | D01 |
| TH3 | Admin or authorizer widens assets, test classes, duration, validity or constraints | ScopeWithin / ceilings (P) | D, M |
| TH4 | Tester edits a signed grant (adds targets) | Signature over exact bytes (S) | S |
| TH5 | Object splicing: wrong parent, wrong issuer key, skipped D_U | Linkage + required objects (F, L) | D |
| TH6 | Type confusion: D_U presented as G, or signature reused across types | Bundle slot type + domain-separated signed bytes (F, S) | S07, D10 |
| TH7 | Parser differentials: duplicate keys, reordering, whitespace, unknown fields, non-canonical times/assets | Strict decode + canonical re-encode (F) | S, F, M, T |
| TH8 | Path/name confusion: `/application` vs `/app`, `..`, case, wildcards, ports, scheme | Canonical assets + segment-prefix `within` (F, P) | M |
| TH9 | Include/exclude overlap misread | Allowed = Included \ Excluded, mandatory exclusions (P) | M, Q |
| TH10 | Cross-tenant use: sibling org assets or org_id swap | Linkage org_id + binding fixture (L, B) | M02, B02 |
| TH11 | Cross-provider replay | Audience = P (L) | A |
| TH12 | Expired / not-yet-valid / revoked / superseded authority | Time and status stages (T, X) | T, X |
| TH13 | Unknown critical constraint silently ignored (permission widened) | Indeterminate, never Accept (P) | F01, F02 |
| TH14 | Missing evidence treated as approval | Indeterminate, Reject-dominates order (§7) | B, R04, X04, T10, P |

## 4. Out of scope (non-goals for v0)

- **Stolen-grant presentation** by someone other than T, and agent session/subagent binding (RQ5).
- **Agent actions outside scope** at runtime; tool mediation and bypass (RQ6).
- **Revocation latency** and cache staleness in a real distributed status service (RQ7).
- **Real organization identity proof** and first-admin authority (RQ1).
- **Real asset ownership**, shared/third-party hosting, and legal testing rights (RQ2; legal).
- Compromise of K_O or of P itself; side channels; denial of service against the verifier.
- Privacy of chain metadata disclosed to P (RQ8).

## 5. Security goals stated as test obligations

- **Soundness:** no case labelled Reject or Indeterminate is Accepted by the chain-aware verifier.
- **Conditional completeness:** every case labelled Accept is Accepted.
- **No silent widening:** unknown critical constraints and missing evidence never yield Accept.
- **Baseline gap:** the signature-only baseline is expected to Accept TH1, TH2, TH3, TH5,
  TH9–TH14 style cases whose signatures are valid. That gap is measured, not assumed.
