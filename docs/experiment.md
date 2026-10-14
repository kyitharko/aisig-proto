# Experiment design — RQ4 chain verifier (DRAFT v0)

**Status:** DRAFT for owner review, 2026-10-15. **Every expected label below is PROPOSED**
and must be independently reviewed by the research owner before it is used as an oracle.
No results exist yet; none are reported here.

## 1. Questions

- E1. On the same labelled cases, how many false accepts, false rejects and indeterminate
  decisions do the chain-aware verifier and a signature-only baseline produce?
- E2. Which stage (format, anchor, signature, linkage, policy, binding, time, status)
  decides each non-Accept case, and does it match the proposed reason?
- E3. What is the CPU cost of signature checking, typed policy evaluation and simulated
  status lookup, measured separately?

## 2. Base synthetic fixture

All names are synthetic. Hosts use the reserved `.test` TLD (RFC 6761). Nothing connects
to any network.

| Item | Value |
| --- | --- |
| P audience | `urn:aisig:provider:p-synthetic` (other provider Q: `urn:aisig:provider:q-synthetic`) |
| O | `org-acme-synthetic` |
| Sibling tenant O' | `org-globex-synthetic` |
| Keys | Ed25519 secret key = `SHA-256("aisig-synthetic-key:" ‖ label)` for labels `acme-root`, `acme-admin`, `acme-authorizer`, `tester-1`, `attacker`, `globex-root`, … Test-only; never real credentials. |
| Registry | acme → K_O(acme-root), validity 2026-01-01T00:00:00Z–2027-12-31T00:00:00Z, usage `org-delegation-root`, active. globex → its own root, active. |
| Bindings | acme: `web:https://app.acme.test:443/`, `db:cluster1`. globex: `web:https://shop.globex.test:443/`, `db:cluster2`. |
| C_A `ca-acme-001` v1 | rights {may_delegate_grant_issuer}; bounds.included {`web:https://app.acme.test:443/`, `db:cluster1`}; excluded ∅; test_ceiling {recon, auth_testing, injection_testing, read_only_data_access, data_modification}; max 2592000 s (30 d); validity 2026-10-01T00:00:00Z–2026-12-31T00:00:00Z |
| D_U `du-acme-001` v1 | right may_issue_engagement; parent ca-acme-001 v1; envelope.included {`web:…/app`, `db:cluster1/main/billing`}; mandatory_exclusions {`web:…/app/admin`}; test_ceiling {recon, auth_testing, injection_testing, read_only_data_access}; max 604800 s (7 d); validity 2026-10-10T00:00:00Z–2026-11-30T00:00:00Z |
| G `g-acme-001` v1 | tester K_T(tester-1); engagement `eng-acme-2026-10-15-01`; parent du-acme-001 v1; targets {`web:…/app`, `db:cluster1/main/billing`}; exclusions {`web:…/app/admin`, `web:…/app/private`}; test_scope {recon, injection_testing}; window 2026-10-15T09:00:00Z–2026-10-15T11:00:00Z |
| Clock | now = 2026-10-15T10:00:00Z, ε = 2 s |
| Status | ca-acme-001 v1, du-acme-001 v1, g-acme-001 v1 all active |

`web:…` abbreviates `web:https://app.acme.test:443`. All three objects carry
`audience = P`, `org_id = org-acme-synthetic`, `format = aisig/v0`, empty constraints.

## 3. How cases are built

Each case = base fixture + a named **mutation** (a data transform on payloads, envelopes,
fixtures or clock). Mutated objects are re-signed with the fixture key stated in the case
unless the case says the original signature is kept. Mutations are written by hand in
test code; they never call the verifier's comparators.

**Oracle independence:** the expected decision and reason are literal values typed from
this table into `tests/cases/reviewed_cases.toml` (Stage 3). Each entry carries
`label_status = "proposed"` until the owner reviews it, then `"reviewed"` with reviewer and
date. Disagreements are logged, not silently fixed. A case whose actual outcome differs
from its label is a **test failure to investigate**, not a label to update.

Decision notation: **A** = Accept, **R** = Reject, **I** = Indeterminate. Stage letters as
in spec §7 (F, N, S, L, P, B, T, X).

## 4. Proposed case table (chain decisions)

### V — valid chains

| ID | Mutation | Exp | Stage / reason |
| --- | --- | --- | --- |
| V01 | none (base) | A | — |
| V02 | G.targets = {`web:…/app/reports`}, G.exclusions = ∅ (mandatory exclusion does not overlap) | A | — |
| V03 | G.targets = {`db:cluster1/main/billing`}, G.exclusions = ∅ | A | — |
| V04 | G.exclusions += `web:…/app/search` | A | — |
| V05 | G.constraints = [{x-note, critical=false, "synthetic"}] | A | — |
| V06 | Remove test_ceiling from C_A and D_U; omit G.test_scope | A | — |
| V07 | G.window = 2026-10-15T09:00:00Z–2026-10-22T09:00:00Z (exactly 7 d) | A | — |
| V08 | G.constraints = [{max_requests_per_second, critical=true, "10"}] (no parent ceiling) | A | — |

### R — root / anchor

| ID | Mutation | Exp | Stage / reason |
| --- | --- | --- | --- |
| R01 | Attacker self-signs an OrganizationRoot for `org-acme-synthetic` with K(attacker), re-signs C_A with it (issuer_key_id = keyid(attacker)); D_U, G unchanged | R | N / RootKeyNotPinned |
| R02 | New org `org-initech-synthetic` with self-signed root, full chain re-signed, org_id changed throughout; not in registry | R | N / UnpinnedOrganization |
| R03 | Registry acme status = revoked | R | N / RootNotActive |
| R04 | Registry unavailable | I | N / RegistryUnavailable |
| R05 | Registry acme validity end = 2026-10-15T09:30:00Z | R | T / Expired{root} |
| R06 | Registry acme usage = `tls-server` | R | N / RootUsageMismatch |

### S — signature and encoding

| ID | Mutation | Exp | Stage / reason |
| --- | --- | --- | --- |
| S01 | Flip one bit of G.sig.value | R | S / InvalidSignature{G} |
| S02 | D_U signed with K(acme-authorizer) instead of K(acme-admin) | R | S / InvalidSignature{D_U} |
| S03 | C_A.bounds.included += `db:cluster2` after signing; original signature kept | R | S / InvalidSignature{C_A} |
| S04 | G.sig.alg = `Ed448` | R | F / UnsupportedAlgorithm |
| S05 | G payload pretty-printed with whitespace, validly signed over those bytes | R | F / NonCanonicalEncoding |
| S06 | G payload contains `engagement_id` twice, validly signed | R | F / DuplicateField |
| S07 | G signed with type tag `IssuerDelegation` in signed bytes; envelope type `EngagementGrant` | R | S / InvalidSignature{G} |

### D — delegation and linkage

| ID | Mutation | Exp | Stage / reason |
| --- | --- | --- | --- |
| D01 | C_A.rights = {account_administration} (handoff "immediate negative test") | R | P / MissingDelegationRight |
| D02 | D_U.issuer_key_id = keyid(attacker); still signed by K(acme-admin) | R | L / IssuerKeyMismatch{D_U} |
| D03 | D_U.parent.id = `ca-acme-999` | R | L / ParentMismatch{D_U} |
| D04 | C_A re-issued as version 2 (same content, re-signed); D_U.parent.version stays 1 | R | L / ParentVersionMismatch{D_U} |
| D05 | D_U.envelope.included += `db:cluster2` | R | P / DelegationAmplifies{assets} |
| D06 | D_U.envelope.test_ceiling += availability_stress | R | P / DelegationAmplifies{test_ceiling} |
| D07 | D_U.validity end = 2027-01-15T00:00:00Z | R | P / DelegationAmplifies{validity} |
| D08 | D_U.envelope.max_engagement_seconds = 5184000 (60 d) | R | P / DelegationAmplifies{max_duration} |
| D09 | Bundle omits D_U; G.parent = ca-acme-001 v1, G signed by K(acme-admin) | R | F / MissingRequiredObject{issuer} |
| D10 | D_U envelope placed in the grant slot | R | F / WrongObjectType{grant} |
| D11 | G.issuer_key_id = keyid(acme-admin); still signed by K(acme-authorizer) | R | L / IssuerKeyMismatch{G} |

### M — MayIssue, scope and asset syntax

| ID | Mutation | Exp | Stage / reason |
| --- | --- | --- | --- |
| M01 | G.targets += `db:cluster1/main/hr` (sibling schema) | R | P / TargetOutsideEnvelope |
| M02 | G.org_id = `org-globex-synthetic` | R | L / TenantMismatch |
| M03 | G.targets: replace `web:…/app` with `web:…/application` (string-prefix trap) | R | P / TargetOutsideEnvelope |
| M04 | G.targets = {`web:…/app/admin`} | R | P / TargetInMandatoryExclusion |
| M05 | G.exclusions = {`web:…/app/private`} (mandatory `/app/admin` dropped) | R | P / MissingMandatoryExclusion |
| M06 | G.exclusions = {`web:…/app/admin/settings`, `web:…/app/private`} (narrower than mandatory) | R | P / MissingMandatoryExclusion |
| M07 | G.test_scope += data_modification | R | P / TestScopeAmplifies |
| M08 | G.test_scope omitted (= no restriction) while D_U has a ceiling | R | P / TestScopeAmplifies |
| M09 | G.window = 2026-10-15T09:00:00Z–2026-10-23T09:00:00Z (8 d) | R | P / DurationExceedsMax |
| M10 | G target host `APP.acme.test` | R | F / NonCanonicalAsset |
| M11 | G target path `/app/../admin` | R | F / NonCanonicalAsset |
| M12 | G target host `*.acme.test` | R | F / UnsupportedAssetSyntax |
| M13 | G target `web:https://app.acme.test:8443/app` | R | P / TargetOutsideEnvelope |
| M14 | G target `web:http://app.acme.test:443/app` | R | P / TargetOutsideEnvelope |
| M15 | G.targets: replace billing with `db:cluster1/main` (wider than envelope) | R | P / TargetOutsideEnvelope |
| M16 | D_U.envelope.included = {`web:…/app`} only (re-signed); G unchanged | R | P / TargetOutsideEnvelope |
| M17 | D_U.constraints = [{max_requests_per_second, critical, "5"}]; G has "10" | R | P / ConstraintAmplifies |
| M18 | D_U.constraints = [{max_requests_per_second, critical, "5"}]; G has none | R | P / ConstraintAmplifies |
| M19 | G target path `/app/` (trailing slash) | R | F / NonCanonicalAsset |

### T — time

| ID | Mutation | Exp | Stage / reason |
| --- | --- | --- | --- |
| T01 | now = 2026-10-15T08:59:00Z | R | T / NotYetValid{G} |
| T02 | now = 2026-10-15T11:00:00Z, ε = 0 | R | T / Expired{G} |
| T03 | now = 2026-10-15T09:00:00Z, ε = 0 | A | — |
| T04 | now = 2026-10-15T10:59:59Z, ε = 2 | I | T / ClockUncertainty{G} |
| T05 | now = 2026-10-15T09:00:01Z, ε = 2 | I | T / ClockUncertainty{G} |
| T06 | G.window start 11:00:00Z, end 09:00:00Z | R | F / MalformedWindow |
| T07 | G.window.start = `2026-10-15T09:00:00` (no offset) | R | F / MalformedTime |
| T08 | G.window.start = `2026-10-15T15:30:00+06:30` (same instant) | R | F / NonCanonicalTime |
| T09 | D_U.validity end = 2026-10-15T10:30:00Z (re-signed); G unchanged | R | P / WindowExceedsParent |
| T10 | Clock unavailable | I | T / ClockUnavailable |
| T11 | G.window.start = `2026-10-15T09:00:00.000Z` | R | F / NonCanonicalTime |

### X — status

| ID | Mutation | Exp | Stage / reason |
| --- | --- | --- | --- |
| X01 | Status g-acme-001 v1 = revoked | R | X / Revoked{G} |
| X02 | Status du-acme-001 v1 = revoked | R | X / Revoked{D_U} |
| X03 | Status ca-acme-001 v1 = revoked | R | X / Revoked{C_A} |
| X04 | Status source unavailable | I | X / StatusUnavailable |
| X05 | Status source has no record for g-acme-001 | I | X / StatusUnknown{G} |
| X06 | Status ca-acme-001 v1 = superseded (D_U still references v1) | R | X / Superseded{C_A} |

### A — audience

| ID | Mutation | Exp | Stage / reason |
| --- | --- | --- | --- |
| A01 | G.audience = Q | R | L / WrongAudience{G} |
| A02 | D_U.audience = Q | R | L / WrongAudience{D_U} |
| A03 | G.audience field absent | R | F / MissingRequiredField |

### F — fields and constraints

| ID | Mutation | Exp | Stage / reason |
| --- | --- | --- | --- |
| F01 | G.constraints = [{x-geo-fence, critical=true, "zone-a"}] | I | P / UnsupportedCriticalConstraint{G} |
| F02 | D_U.constraints = [{x-geo-fence, critical=true, "zone-a"}] | I | P / UnsupportedCriticalConstraint{D_U} |
| F03 | G payload adds top-level `"scan_everything": true` | R | F / UnknownField |
| F04 | G.format = `aisig/v1` | R | F / UnsupportedVersion |
| F05 | G.tester_key absent | R | F / MissingRequiredField |
| F06 | G.constraints lists `max_requests_per_second` twice | R | F / DuplicateField |
| F07 | G.test_scope += `zero_day_deploy` (unknown class) | R | F / UnknownEnumValue |

### B — asset binding

| ID | Mutation | Exp | Stage / reason |
| --- | --- | --- | --- |
| B01 | Add `web:https://legacy.acme.test:443/` to C_A bounds, D_U envelope and G targets; no binding record | I | B / NoBindingEvidence |
| B02 | Add `web:https://shop.globex.test:443/` to C_A, D_U and G (bound to globex) | R | B / AssetBoundToOtherOrg |
| B03 | Binding fixture unavailable | I | B / BindingUnavailable |

### P — precedence (two factors at once, to pin Reject-dominates)

| ID | Mutation | Exp | Stage / reason |
| --- | --- | --- | --- |
| P01 | S01 + X04 | R | S / InvalidSignature{G} |
| P02 | B01 + now = 2026-10-15T11:00:00Z, ε = 0 | R | T / Expired{G} |
| P03 | R04 + M01 | R | P / TargetOutsideEnvelope |

**Count:** 84 chain cases (V 8, R 6, S 7, D 11, M 19, T 11, X 6, A 3, F 7, B 3, P 3).
Labels: 9 Accept (V01–V08, T03), 65 Reject, 10 Indeterminate (R04, T04, T05, T10, X04,
X05, F01, F02, B01, B03).

### Documented non-case

- **K01** — G presented by a party holding a key other than K_T. Not decidable in v0: there
  is no presenter proof (RQ5). Listed so the gap is explicit; not counted.

## 5. Proposed scope-query cases (on accepted base G; lookup, not enforcement)

| ID | Probe | Exp |
| --- | --- | --- |
| Q01 | `web:…/app/reports/q3` | InScope |
| Q02 | `web:…/app/private/report` | Excluded |
| Q03 | `web:…/app/private` | Excluded |
| Q04 | `web:…/app/privateer/x` | InScope |
| Q05 | `web:…/app/admin` | Excluded |
| Q06 | `web:…/app/admin/users/7` | Excluded |
| Q07 | `db:cluster1/main/hr` | OutOfScope |
| Q08 | `db:cluster1/main/billing` | InScope |
| Q09 | `web:https://app.acme.test:443/` | OutOfScope |
| Q10 | `web:http://app.acme.test:80/app/x` | OutOfScope |

## 6. Baseline and metrics

- **Signature-only baseline:** spec §7. Its outcomes are *measured*, never used as labels.
- Per verifier, over the 84 reviewed chain cases:
  - false accept = output A where label ≠ A;
  - false reject = output R where label = A;
  - indeterminate = output I (and split by label);
  - class mismatch = R vs I disagreement with the label;
  - for the chain-aware verifier only: stage and reason match rate.
- Output: `results/case_comparison.md` and `.json`, one row per case plus totals.

## 7. Property-based tests (after spec approval)

- `proptest` with a fixed, recorded `rng_seed`, overridable by `AISIG_PROPTEST_SEED`.
- Generators: valid chains with random narrower targets, extra exclusions, sub-windows and
  test-scope subsets → expected Accept.
- One-factor mutations whose expected class is fixed by mutation kind, e.g. any
  single-bit signature flip → R/S; any added target outside the envelope → R/P;
  clock outside window by more than ε → R/T.
- **Independent set oracle:** enumerate a finite synthetic universe of web paths (depth ≤ 4,
  small alphabet) and db names; compute Allowed(·) by direct membership in test code;
  compare `Allowed(child) ⊆ Allowed(parent)` with the verifier's `ScopeWithin`. This checks
  the prefix rule (spec §4) without reusing it.

## 8. Benchmark protocol (after spec approval)

- Release build, CPU only, no network. Separate timers for:
  1. signature verification of the three objects;
  2. typed policy evaluation (linkage + CanDelegate + MayIssue) on pre-decoded objects;
  3. simulated status lookup (in-memory fixture, 3 lookups).
  Full-chain end-to-end is reported as a fourth series for context.
- Warm-up iterations, then N timed iterations per run, R repeated runs (planned N = 10 000,
  R = 10). Report p50/p95/p99 per run and across runs.
- Record: rustc/cargo versions, crate versions (Cargo.lock), CPU model, core count, kernel,
  build profile, N, R and seeds. Results go to `results/bench_<timestamp>.json` and `.md`.
- Reported numbers are only what the run produced; nothing is extrapolated.

## 9. Review checklist for the owner

1. Base fixture values (§2) are acceptable.
2. Each label in §4 and §5: mark agree / disagree / change.
3. Open questions Q1–Q8 in [spec.md §10](spec.md#10-open-questions-for-owner-review).
4. Any missing threat class to add as cases.
