# Experiment design — RQ4 chain verifier (DRAFT r2)

**Status:** DRAFT r2, 2026-10-15. Each label carries a review status (§3). Labels marked
**Pr** (proposed) still need independent owner review. Results are reported only in
`results/` and [report.md](report.md) after they have been produced by a run.

## 1. Questions

- E1. On the same labelled cases, how many false accepts, false rejects and indeterminate
  decisions do the chain-aware verifier and a signature-only baseline produce?
- E2. Which stage (format, anchor, signature, linkage, policy, binding, time, status)
  decides each non-Accept case, and does it match the labelled reason?
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
| Keys | Ed25519 secret key = `SHA-256("aisig-synthetic-key:" ‖ label)` for labels `acme-root`, `acme-admin`, `acme-authorizer`, `tester-1`, `attacker`, `globex-root`, `initech-root`, `initech-admin`, `initech-authorizer`. Test-only; never real credentials. |
| Registry | acme → K(acme-root), validity 2026-01-01T00:00:00Z–2027-12-31T00:00:00Z, usage `org-delegation-root`, version 1, active. globex → K(globex-root), same validity, active. |
| Bindings | acme: `web:https://app.acme.test:443/`, `db:cluster1`. globex: `web:https://shop.globex.test:443/`, `db:cluster2`. |
| Bundle `root` slot | Self-signed `OrganizationRoot` for acme: root_key K(acme-root), key_id keyid(acme-root), algorithm Ed25519, validity as in the registry, usage `org-delegation-root`, version 1, signed by K(acme-root). **Ignored by the chain-aware verifier; parsed by the baseline** (spec §2.7). |
| C_A `ca-acme-001` v1 | signed by K(acme-root); subject K(acme-admin); rights {may_delegate_grant_issuer}; bounds.included {`web:https://app.acme.test:443/`, `db:cluster1`}; excluded ∅; test_ceiling {recon, auth_testing, injection_testing, read_only_data_access, data_modification}; max 2592000 s (30 d); validity 2026-10-01T00:00:00Z–2026-12-31T00:00:00Z |
| D_U `du-acme-001` v1 | signed by K(acme-admin); subject K(acme-authorizer); right may_issue_engagement; parent ca-acme-001 v1; envelope.included {`web:…/app`, `db:cluster1/main/billing`}; mandatory_exclusions {`web:…/app/admin`}; test_ceiling {recon, auth_testing, injection_testing, read_only_data_access}; max 604800 s (7 d); validity 2026-10-10T00:00:00Z–2026-11-30T00:00:00Z |
| G `g-acme-001` v1 | signed by K(acme-authorizer); tester K(tester-1); engagement `eng-acme-2026-10-15-01`; parent du-acme-001 v1; targets {`web:…/app`, `db:cluster1/main/billing`}; exclusions {`web:…/app/admin`, `web:…/app/private`}; test_scope `{kind: classes, classes: [injection_testing, recon]}`; window 2026-10-15T09:00:00Z–2026-10-15T11:00:00Z |
| Clock | now = 2026-10-15T10:00:00Z, ε = 2 s |
| Status | ca-acme-001 v1, du-acme-001 v1, g-acme-001 v1 all active |

`web:…` abbreviates `web:https://app.acme.test:443`. All three chain objects carry
`audience = P`, `org_id = org-acme-synthetic`, `format = aisig/v0`, and no constraints.

## 3. How cases are built and reviewed

Each case = base fixture + a named **mutation** (a data transform on payloads, envelopes,
fixtures or clock). Mutated objects are re-signed with the key stated in the case unless
the case says the original signature is kept, and `issuer_key_id` fields are updated by the
mutation when it changes a signer. Mutations are hand-written test code; they never call
the verifier's comparators.

**Oracle independence:** expected decision, stage and reason are literal values typed
from this table into `tests/cases/reviewed_cases.toml`. A case whose actual outcome
differs from its label is a **test failure to investigate**, never a label to update.

**Review status column:**

- **Rv** — label agreed by the owner as written on 2026-10-15.
- **Rv\*** — label set by explicit owner instruction on 2026-10-15 (changed from r1).
- **Pr** — proposed; needs owner review (new in r2, or depends on a rule still under review).

Decision notation: **A** = Accept, **R** = Reject, **I** = Indeterminate. Stage letters as
in spec §7 (F, N, S, L, P, B, T, X).

## 4. Chain cases

### V — valid chains

| ID | Mutation | Exp | Stage / reason | St |
| --- | --- | --- | --- | --- |
| V01 | none (base) | A | — | Rv |
| V02 | G.targets = {`web:…/app/reports`}, G.exclusions = ∅ (mandatory exclusion does not overlap) | A | — | Rv |
| V03 | G.targets = {`db:cluster1/main/billing`}, G.exclusions = ∅ | A | — | Rv |
| V04 | G.exclusions += `web:…/app/search` | A | — | Rv |
| V05 | G.constraints = [{x-note, critical=false, "synthetic"}] | A | — | Rv |
| V06 | Remove test_ceiling from C_A and D_U; G.test_scope = `{kind: unrestricted}` (explicit) | A | — | Rv\* |
| V07 | G.window = 2026-10-15T09:00:00Z–2026-10-22T09:00:00Z (exactly 7 d) | A | — | Rv |
| V08 | G.constraints = [{max_requests_per_second, critical=true, "10"}] (no parent ceiling) | A | — | Rv |
| V09 | Bundle `root` slot = the bytes `not an envelope` (malformed) | A | — | Pr |
| V10 | Bundle `root` slot absent | A | — | Pr |

### R — root / anchor

| ID | Mutation | Exp | Stage / reason | St |
| --- | --- | --- | --- | --- |
| R01 | Attacker self-signs an OrganizationRoot for `org-acme-synthetic` with K(attacker) and places it in the `root` slot; C_A re-signed with K(attacker), C_A.issuer_key_id = keyid(attacker); D_U, G unchanged | R | N / RootKeyNotPinned | Rv |
| R02 | New org `org-initech-synthetic`: self-signed initech root in the `root` slot, chain re-keyed with initech-root/admin/authorizer, org_id changed throughout; not in registry | R | N / UnpinnedOrganization | Rv |
| R03 | Registry acme status = revoked | R | N / RootNotActive | Rv |
| R04 | Registry unavailable | I | N / RegistryUnavailable | Rv |
| R05 | Registry acme validity end = 2026-10-15T09:30:00Z | R | T / Expired{root} | Rv |
| R06 | Registry acme usage = `tls-server` | R | N / RootUsageMismatch | Rv |

### S — signature and encoding

| ID | Mutation | Exp | Stage / reason | St |
| --- | --- | --- | --- | --- |
| S01 | Flip one bit of G.sig.value | R | S / InvalidSignature{G} | Rv |
| S02 | D_U signed with K(acme-authorizer) instead of K(acme-admin) | R | S / InvalidSignature{D_U} | Rv |
| S03 | C_A.bounds.included += `db:cluster2` after signing; original signature kept | R | S / InvalidSignature{C_A} | Rv |
| S04 | G.sig.alg = `Ed448` | R | F / UnsupportedAlgorithm | Rv |
| S05 | G payload pretty-printed with whitespace, validly signed over those bytes | R | F / NonCanonicalEncoding | Rv |
| S06 | G payload contains `engagement_id` twice, validly signed | R | F / DuplicateField | Rv |
| S07 | G signed with type tag `IssuerDelegation` in signed bytes; envelope type `EngagementGrant` | R | S / InvalidSignature{G} | Rv |

### D — delegation and linkage

| ID | Mutation | Exp | Stage / reason | St |
| --- | --- | --- | --- | --- |
| D01 | C_A.rights = {account_administration} (handoff "immediate negative test") | R | P / MissingDelegationRight | Rv |
| D02 | D_U.issuer_key_id = keyid(attacker); still signed by K(acme-admin) | R | L / IssuerKeyMismatch{D_U} | Rv |
| D03 | D_U.parent.id = `ca-acme-999` | R | L / ParentMismatch{D_U} | Rv |
| D04 | C_A re-issued as version 2 (same content, re-signed); D_U.parent.version stays 1 | R | L / ParentVersionMismatch{D_U} | Rv |
| D05 | D_U.envelope.included += `db:cluster2` | R | P / DelegationAmplifies{assets} | Rv |
| D06 | D_U.envelope.test_ceiling += availability_stress | R | P / DelegationAmplifies{test_ceiling} | Rv |
| D07 | D_U.validity end = 2027-01-15T00:00:00Z | R | P / DelegationAmplifies{validity} | Rv |
| D08 | D_U.envelope.max_engagement_seconds = 5184000 (60 d) | R | P / DelegationAmplifies{max_duration} | Rv |
| D09 | Bundle omits D_U; G.parent = ca-acme-001 v1, G signed by K(acme-admin) | R | F / MissingRequiredObject{issuer} | Rv |
| D10 | D_U envelope placed in the grant slot | R | F / WrongObjectType{grant} | Rv |
| D11 | G.issuer_key_id = keyid(acme-admin); still signed by K(acme-authorizer) | R | L / IssuerKeyMismatch{G} | Rv |

### M — MayIssue, scope and asset syntax

| ID | Mutation | Exp | Stage / reason | St |
| --- | --- | --- | --- | --- |
| M01 | G.targets += `db:cluster1/main/hr` (sibling schema) | R | P / TargetOutsideEnvelope | Rv |
| M02 | G.org_id = `org-globex-synthetic` | R | L / TenantMismatch | Rv |
| M03 | G.targets: replace `web:…/app` with `web:…/application` (string-prefix trap) | R | P / TargetOutsideEnvelope | Rv |
| M04 | G.targets = {`web:…/app/admin`}, **G.exclusions = ∅** (see note) | R | P / TargetInMandatoryExclusion | Pr |
| M05 | G.exclusions = {`web:…/app/private`} (mandatory `/app/admin` dropped) | R | P / MissingMandatoryExclusion | Rv |
| M06 | G.exclusions = {`web:…/app/admin/settings`, `web:…/app/private`} (narrower than mandatory) | R | P / MissingMandatoryExclusion | Rv |
| M07 | G.test_scope classes += data_modification | R | P / TestScopeAmplifies | Rv |
| M08 | G.test_scope field absent | R | F / MissingRequiredField | Rv\* |
| M09 | G.window = 2026-10-15T09:00:00Z–2026-10-23T09:00:00Z (8 d) | R | P / DurationExceedsMax | Rv |
| M10 | G target host `APP.acme.test` | R | F / NonCanonicalAsset | Rv |
| M11 | G target path `/app/../admin` | R | F / NonCanonicalAsset | Rv |
| M12 | G target host `*.acme.test` | R | F / UnsupportedAssetSyntax | Rv |
| M13 | G target `web:https://app.acme.test:8443/app` | R | P / TargetOutsideEnvelope | Rv |
| M14 | G target `web:http://app.acme.test:443/app` | R | P / TargetOutsideEnvelope | Rv |
| M15 | G.targets: replace billing with `db:cluster1/main` (wider than envelope) | R | P / TargetOutsideEnvelope | Rv |
| M16 | D_U.envelope.included = {`web:…/app`} only (re-signed); G unchanged | R | P / TargetOutsideEnvelope | Rv |
| M17 | D_U.constraints = [{max_requests_per_second, critical, "5"}]; G has "10" | R | P / ConstraintAmplifies | Rv |
| M18 | D_U.constraints = [{max_requests_per_second, critical, "5"}]; G has none | R | P / ConstraintAmplifies | Rv |
| M19 | G target path `/app/` (trailing slash) | R | F / NonCanonicalAsset | Rv |
| M20 | G.targets += `web:…/app/private` while G still excludes `web:…/app/private` (redundant target fully removed by G's own exclusion) | R | P / InadmissibleScope{G} | Pr |
| M21 | G.test_scope = `{kind: unrestricted}` while D_U has a test ceiling | R | P / TestScopeAmplifies | Pr |

**M04 note.** In r1 the mutation only replaced the targets, so G kept its base exclusions,
including `/app/admin`. The target `/app/admin` would then be fully removed by G's own
exclusion, and the r2 admissibility rule (spec §4.2, policy step 2) would reject it first
as `InadmissibleScope{G}`. M04 is meant to test a target that lies inside D_U's
*mandatory* exclusion, so the mutation now sets G.exclusions = ∅. G is then admissible,
MayIssue condition 1 holds (`/app/admin` ⊆ `/app`), and condition 2 fails because
`/app/admin` lies within the mandatory exclusion. The label is unchanged; status is **Pr**
until the clarified mutation is confirmed. M20 now covers the admissibility case.

### T — time

| ID | Mutation | Exp | Stage / reason | St |
| --- | --- | --- | --- | --- |
| T01 | now = 2026-10-15T08:59:00Z | R | T / NotYetValid{G} | Rv |
| T02 | now = 2026-10-15T11:00:00Z, ε = 0 | R | T / Expired{G} | Rv |
| T03 | now = 2026-10-15T09:00:00Z, ε = 0 | A | — | Rv |
| T04 | now = 2026-10-15T10:59:59Z, ε = 2 | I | T / ClockUncertainty{G} | Rv |
| T05 | now = 2026-10-15T09:00:01Z, ε = 2 | I | T / ClockUncertainty{G} | Rv |
| T06 | G.window start 11:00:00Z, end 09:00:00Z | R | F / MalformedWindow | Rv |
| T07 | G.window.start = `2026-10-15T09:00:00` (no offset) | R | F / MalformedTime | Rv |
| T08 | G.window.start = `2026-10-15T15:30:00+06:30` (same instant) | R | F / NonCanonicalTime | Rv |
| T09 | D_U.validity end = 2026-10-15T10:30:00Z (re-signed); G unchanged | R | P / WindowExceedsParent | Rv |
| T10 | Clock unavailable | I | T / ClockUnavailable | Rv |
| T11 | G.window.start = `2026-10-15T09:00:00.000Z` | R | F / NonCanonicalTime | Rv |

### X — status

| ID | Mutation | Exp | Stage / reason | St |
| --- | --- | --- | --- | --- |
| X01 | Status g-acme-001 v1 = revoked | R | X / Revoked{G} | Rv |
| X02 | Status du-acme-001 v1 = revoked | R | X / Revoked{D_U} | Rv |
| X03 | Status ca-acme-001 v1 = revoked | R | X / Revoked{C_A} | Rv |
| X04 | Status source unavailable | I | X / StatusUnavailable | Rv |
| X05 | Status source has no record for g-acme-001 | I | X / StatusUnknown{G} | Rv |
| X06 | Status ca-acme-001 v1 = superseded (D_U still references v1) | R | X / Superseded{C_A} | Rv |

### A — audience

| ID | Mutation | Exp | Stage / reason | St |
| --- | --- | --- | --- | --- |
| A01 | G.audience = Q | R | L / WrongAudience{G} | Rv |
| A02 | D_U.audience = Q | R | L / WrongAudience{D_U} | Rv |
| A03 | G.audience field absent | R | F / MissingRequiredField | Rv |

### F — fields and constraints

| ID | Mutation | Exp | Stage / reason | St |
| --- | --- | --- | --- | --- |
| F01 | G.constraints = [{x-geo-fence, critical=true, "zone-a"}] | R | P / UnsupportedCriticalConstraint{G} | Rv\* |
| F02 | D_U.constraints = [{x-geo-fence, critical=true, "zone-a"}] | R | P / UnsupportedCriticalConstraint{D_U} | Rv\* |
| F03 | G payload adds top-level `"scan_everything": true` | R | F / UnknownField | Rv |
| F04 | G.format = `aisig/v1` | R | F / UnsupportedVersion | Rv |
| F05 | G.tester_key absent | R | F / MissingRequiredField | Rv |
| F06 | G.constraints lists `max_requests_per_second` twice | R | F / DuplicateConstraintName | Rv\* |
| F07 | G.test_scope classes += `zero_day_deploy` (unknown class) | R | F / UnknownEnumValue | Rv |

### B — asset binding

| ID | Mutation | Exp | Stage / reason | St |
| --- | --- | --- | --- | --- |
| B01 | Add `web:https://legacy.acme.test:443/` to C_A bounds, D_U envelope and G targets; no binding record | I | B / NoBindingEvidence | Rv |
| B02 | Add `web:https://shop.globex.test:443/` to C_A, D_U and G (bound to globex) | R | B / AssetBoundToOtherOrg | Rv |
| B03 | Binding fixture unavailable | I | B / BindingUnavailable | Rv |

### P — precedence (two factors at once)

| ID | Mutation | Exp | Stage / reason | St |
| --- | --- | --- | --- | --- |
| P01 | S01 + X04 | R | S / InvalidSignature{G} | Rv |
| P02 | B01 + now = 2026-10-15T11:00:00Z, ε = 0 | R | T / Expired{G} | Rv |
| P03 | R04 + M01 | R | P / TargetOutsideEnvelope | Pr |

**P03 note.** P03 depends on the conditional-evaluation rule in spec §7.2. With the
registry unavailable, D_U and G are verified under keys asserted by unauthenticated C_A.
The sibling-schema target contradicts D_U under that assertion. Every possible registry
answer then yields Reject: either C_A fails to authenticate, or it does and the
contradiction is real. If the owner does not accept §7.2, P03's label becomes
`I / N / RegistryUnavailable`.

**Count:** 88 chain cases (V 10, R 6, S 7, D 11, M 21, T 11, X 6, A 3, F 7, B 3, P 3).
Labels: 11 Accept (V01–V10, T03), 69 Reject, 8 Indeterminate (R04, T04, T05, T10, X04,
X05, B01, B03). Of the original 84 r1 cases: 9 Accept, 67 Reject, 8 Indeterminate.
Review status: 82 Rv/Rv\*, 6 Pr (V09, V10, M04, M20, M21, P03); every label carries its status.

### Documented non-case

- **K01** — G presented by a party holding a key other than K_T. Not decidable in v0: there
  is no presenter proof (RQ5). Listed so the gap is explicit; not counted.

## 5. Scope-query cases (on accepted base G; lookup, not enforcement)

All Rv.

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

## 6. Scope-oracle tests (not counted as chain cases)

- **SO1 (named counterexample, spec §4.3).** Parent: include `/app`, exclude `/app/private`.
  Child: include `/app/reports`, `/app/private`; exclude `/app/private`. Expected:
  the oracle reports Allowed(child) ⊆ Allowed(parent) = true; the oracle reports the child
  inadmissible; the implementation reports the child inadmissible; the implementation's
  raw ScopeWithin is false. This documents why the equivalence is claimed only for
  admissible scopes.
- **SO2 (property).** Random scopes over a finite synthetic universe (one web origin, path
  segments from {a, b, c}, depth ≤ 3; db clusters {c1, c2} × databases {d1, d2} × schemas
  {s1, s2}). The oracle enumerates every node and computes membership with its own
  string-based containment code. Checks: implementation admissibility = oracle admissibility;
  for admissible children, ScopeWithin = oracle subset; ScopeWithin ⇒ oracle subset for all
  children.

## 7. Baseline and metrics

- **Signature-only baseline:** spec §7.4. Its outcomes are *measured*, never used as labels.
  Hypotheses to measure, not assumptions: it Accepts R01, R02 and every
  linkage/policy/binding/time/status case whose signatures are valid; it Rejects V09 and V10
  (no usable root slot).
- Per verifier, over the 88 chain cases:
  - false accept = output A where label ≠ A;
  - false reject = output R where label = A;
  - indeterminate = output I (split by label);
  - class mismatch = R vs I disagreement with the label;
  - chain-aware verifier only: exact stage + reason match rate.
- Totals are reported for all cases and separately for Rv/Rv\* cases only.
- Output: `results/case_comparison.md` and `.json`, one row per case plus totals.

## 8. Property-based tests

- `proptest` with a fixed, recorded `rng_seed`, overridable by `AISIG_PROPTEST_SEED`;
  failure persistence disabled so a seed fully determines the run.
- Generators: valid chains with random narrower targets, extra exclusions, sub-windows that
  contain now ± ε, test-scope subsets and optional rate constraints → expected Accept.
- One-factor mutations whose expected outcome is fixed by mutation kind:
  - single-bit flip of any chain signature → `R / S / InvalidSignature{obj}`;
  - single-bit flip of any signed payload byte, signature kept → Reject at F, N or S;
  - added target outside the envelope → `R / P / TargetOutsideEnvelope`;
  - clock moved past the window by more than ε → `R / T / Expired{G}` or `NotYetValid{G}`;
  - registry unavailable on a valid chain → `I / N / RegistryUnavailable` (never Accept).
- Scope-oracle properties SO2 (§6).

## 9. Benchmark protocol

- Release build, CPU only, no network. Separate timers for:
  1. signature verification of the three chain objects (pre-decoded payloads and keys);
  2. typed policy evaluation (linkage + policy stage) on pre-decoded objects;
  3. simulated status lookup (in-memory fixture, 3 lookups).
  Full-chain end-to-end (decode → status) is a fourth series for context; timer overhead
  (an empty timed call) is a fifth, so tiny series can be read against it.
- Warm-up iterations, then N timed iterations per run, R repeated runs (N = 10 000,
  R = 10). Report p50/p95/p99 per run and the median of each across runs.
- Record: rustc/cargo versions, crate versions (Cargo.lock), CPU model, core count, kernel,
  build profile, N, R and seeds. Results go to `results/bench_<timestamp>.json` and `.md`.
- Reported numbers are only what the run produced; nothing is extrapolated.
