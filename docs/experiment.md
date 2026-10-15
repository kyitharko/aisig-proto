# Experiment design — RQ4 chain verifier (DRAFT r3.1)

**Status:** DRAFT r3.1, 2026-10-15. All labels are owner-reviewed. Each label carries a review status (§3). Labels marked
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
| Status | C_A, D_U and G each registered **active** under their exact status key (spec §6: org_id, type, id, version, payload digest), following the registration rule in §3 |

`web:…` abbreviates `web:https://app.acme.test:443`. All three chain objects carry
`audience = P`, `org_id = org-acme-synthetic`, `format = aisig/v0`, and no constraints.

## 3. How cases are built and reviewed

Each case = base fixture + a named **mutation** (a data transform on payloads, envelopes,
fixtures or clock). Mutated objects are re-signed with the key stated in the case unless
the case says the original signature is kept, and `issuer_key_id` fields are updated by the
mutation when it changes a signer. Mutations are hand-written test code; they never call
the verifier's comparators.

**Status registration rule (r3).** The status source is keyed by the exact signed
object (spec §6). The fixture therefore registers status for each chain object *as
signed by its issuer in that case*: after the case's payload and signer mutations, and
before any post-signing tampering (bit flips, payload replaced after signing, raw slot
bytes, slot copies). This gives every case that represents a legitimately issued, re-signed
object (for example M01, D05, T09, B01) an exact Active record, so the case still reaches
its intended stage and reason. Defaults: C_A, D_U and G are registered Active. A case
changes this only explicitly:

- X01–X03 and X06 register the exact object with the stated status (revoked, superseded).
- X05 registers no record for G.
- X07 registers no record for its new G. X08 and X09 register only the *original* base G
  (Active), not the re-signed G under test.
- Tampering after signing (S01, S03, P01) does not change what was registered.

Status keys are derived from the scenario's own specs; no case registers an object by
running the verifier.

**Oracle independence:** expected decision, stage and reason are literal values typed
from this table into `tests/cases/reviewed_cases.toml`. A case whose actual outcome
differs from its label is a **test failure to investigate**, never a label to update.

**Review status column:**

- **Rv** — label agreed by the owner as written on 2026-10-15 (V09, V10, M04 with its
  clarified mutation, M20, M21 and P03 were approved in the owner's Stage 0–4 review,
  also on 2026-10-15; R07, R08, X07–X09, Q11 and U01–U04 were approved in the owner's
  r3 review, also on 2026-10-15).
- **Rv\*** — label set by explicit owner instruction on 2026-10-15 (changed from r1).
- **Pr** — proposed; needs owner review. None remain as of r3.1.

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
| V09 | Bundle `root` slot = the bytes `not an envelope` (malformed) | A | — | Rv |
| V10 | Bundle `root` slot absent | A | — | Rv |

### R — root / anchor

| ID | Mutation | Exp | Stage / reason | St |
| --- | --- | --- | --- | --- |
| R01 | Attacker self-signs an OrganizationRoot for `org-acme-synthetic` with K(attacker) and places it in the `root` slot; C_A re-signed with K(attacker), C_A.issuer_key_id = keyid(attacker); D_U, G unchanged | R | N / RootKeyNotPinned | Rv |
| R02 | New org `org-initech-synthetic`: self-signed initech root in the `root` slot, chain re-keyed with initech-root/admin/authorizer, org_id changed throughout; not in registry | R | N / UnpinnedOrganization | Rv |
| R03 | Registry acme status = revoked | R | N / RootNotActive | Rv |
| R04 | Registry unavailable | I | N / RegistryUnavailable | Rv |
| R05 | Registry acme validity end = 2026-10-15T09:30:00Z | R | T / Expired{root} | Rv |
| R06 | Registry acme usage = `tls-server` | R | N / RootUsageMismatch | Rv |
| R07 | Registry entry looked up for `org-acme-synthetic` has record `org_id = org-globex-synthetic` (key, usage, status otherwise acme's) | R | N / RootOrgMismatch | Rv |
| R08 | Registry acme record `algorithm = Ed448` (same key bytes) | R | N / RootAlgorithmMismatch | Rv |

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
| M04 | G.targets = {`web:…/app/admin`}, **G.exclusions = ∅** (see note) | R | P / TargetInMandatoryExclusion | Rv |
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
| M20 | G.targets += `web:…/app/private` while G still excludes `web:…/app/private` (redundant target fully removed by G's own exclusion) | R | P / InadmissibleScope{G} | Rv |
| M21 | G.test_scope = `{kind: unrestricted}` while D_U has a test ceiling | R | P / TestScopeAmplifies | Rv |

**M04 note.** In r1 the mutation only replaced the targets, so G kept its base exclusions,
including `/app/admin`. The target `/app/admin` would then be fully removed by G's own
exclusion, and the r2 admissibility rule (spec §4.2, policy step 2) would reject it first
as `InadmissibleScope{G}`. M04 is meant to test a target that lies inside D_U's
*mandatory* exclusion, so the mutation now sets G.exclusions = ∅. G is then admissible,
MayIssue condition 1 holds (`/app/admin` ⊆ `/app`), and condition 2 fails because
`/app/admin` lies within the mandatory exclusion. The label is unchanged. The clarified
mutation was approved in the owner's Stage 0–4 review. M20 covers the admissibility case.

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
| X07 | G re-issued with `id = ca-acme-001`, `version = 1` (C_A's id/version), validly signed by K(acme-authorizer); no status record for this G (C_A keeps its own Active record) | I | X / StatusUnknown{G} | Rv |
| X08 | G re-issued with the original `id = g-acme-001`, `version = 1` but `tester_key = K(tester-2)`, validly signed; only the original base G is registered Active | I | X / StatusUnknown{G} | Rv |
| X09 | G re-issued with the original id/version but test_scope classes {auth_testing, recon} instead of {injection_testing, recon}, validly signed; only the original base G is registered Active | I | X / StatusUnknown{G} | Rv |

**X07–X09 note.** Before r3 the status source was keyed only by (id, version), so each of
these G objects would have received another object's Active record and been accepted.
Under exact-object status keys (spec §6) no record matches, so the decision is
`Indeterminate / X / StatusUnknown{G}`. That keeps the existing policy for a missing status
record. Whether a record for the same (org, type, id, version) with a *different* digest
should instead be Reject (equivocation) is an open question (spec §10).

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
| P03 | R04 + M01 | R | P / TargetOutsideEnvelope | Rv |

**P03 note.** P03 depends on the conditional-evaluation rule in spec §7.2. With the
registry unavailable, D_U and G are verified under keys asserted by unauthenticated C_A.
The sibling-schema target contradicts D_U under that assertion. Every possible registry
answer then yields Reject: either C_A fails to authenticate, or it does and the
contradiction is real. The owner approved P03 together with the §7.2 rule in the
Stage 0–4 review.

**Count:** 93 chain cases (V 10, R 8, S 7, D 11, M 21, T 11, X 9, A 3, F 7, B 3, P 3).
Labels: 11 Accept (V01–V10, T03), 71 Reject, 11 Indeterminate (R04, T04, T05, T10, X04,
X05, X07, X08, X09, B01, B03). The 88 r2 cases are unchanged: 11 Accept, 69 Reject,
8 Indeterminate. Of the original 84 r1 cases: 9 Accept, 67 Reject, 8 Indeterminate.
Review status: 93 Rv/Rv\* (88 Rv, 5 Rv\*), 0 Pr; every label carries its status.

### Documented non-case

- **K01** — G presented by a party holding a key other than K_T. Not decidable in v0: there
  is no presenter proof (RQ5). Listed so the gap is explicit; not counted.

## 5. Scope-lookup cases (on accepted base G; lookup, not enforcement)

Two lookups exist (spec §4.4). Neither authorizes or enforces anything (RQ6).

**Exact-node lookup** (`exact_node_lookup`): where the single node named by the probe lies.
Its answer says nothing about the probe's descendants. Q01–Q10 are Rv (run under the r2
name `scope_query`; labels unchanged). Q11 is Rv (approved in the r3 review).

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
| Q11 | `web:…/app` (the node itself; its descendant `/app/admin` is excluded) | InScope |

**Subtree lookup** (`subtree_lookup`): how much of the probe's whole subtree lies in
Allowed(G), using effective-set semantics. All Rv (new in r3, approved in the r3 review).

| ID | Probe subtree | Exp |
| --- | --- | --- |
| U01 | `web:…/app` | PartiallyAllowed (`/app/admin` and `/app/private` are excluded) |
| U02 | `web:…/app/admin` | NoneAllowed |
| U03 | `web:…/app/reports` | WhollyAllowed |
| U04 | `db:cluster1/main` | PartiallyAllowed (only `billing` is targeted) |

## 6. Scope-oracle tests (not counted as chain cases)

- **SO1 (named counterexample, spec §4.3).** Parent: include `/app`, exclude `/app/private`.
  Child: include `/app/reports`, `/app/private`; exclude `/app/private`. Expected:
  the oracle reports Allowed(child) ⊆ Allowed(parent) = true; the oracle reports the child
  inadmissible; the implementation reports the child inadmissible; the implementation's
  raw ScopeWithin is false. This documents why the equivalence is claimed only for
  admissible scopes. In tests/scope_oracle.rs the paths are relabelled to the oracle
  universe (`/a` for `/app`, `/a/b` for `/app/private`, `/a/c` for `/app/reports`); the
  literal `/app` version is a unit test in src/asset.rs.
- **SO2 (property).** Random scopes over a finite synthetic universe (one web origin, path
  segments from {a, b, c}, depth ≤ 3; db clusters {c1, c2} × databases {d1, d2} × schemas
  {s1, s2}). The oracle enumerates every node and computes membership with its own
  string-based containment code. Checks: implementation admissibility = oracle admissibility;
  for admissible children, ScopeWithin = oracle subset; ScopeWithin ⇒ oracle subset for all
  children.
- **SO3 (property, r3).** Same universe. For a random scope and probe node, the subtree
  lookup must equal the oracle's classification of `nodes(probe) ∩ Allowed(scope)`:
  all nodes → WhollyAllowed, none → NoneAllowed, otherwise PartiallyAllowed. The exact-node
  lookup must equal the oracle's membership of the probe node alone.

## 7. Baseline and metrics

- **Signature-only baseline:** spec §7.4. Its outcomes are *measured*, never used as labels.
  Hypotheses to measure, not assumptions: it Accepts R01, R02 and every
  linkage/policy/binding/time/status case whose signatures are valid; it Rejects V09 and V10
  (no usable root slot).
- Per verifier, over all chain cases (93 in r3):
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
  - registry unavailable on a valid chain → `I / N / RegistryUnavailable` (never Accept);
  - any one evidence source unavailable → its Indeterminate (never Accept);
  - (r3) a valid G re-issued with a changed signed field (engagement_id) under the same
    id/version, with only the original G registered → `I / X / StatusUnknown{G}`.
- Scope-oracle properties SO2 and SO3 (§6).

## 9. Benchmark protocol

- Release build, CPU only, no network. Separate timers for:
  1. signature verification of the three chain objects (pre-decoded payloads and keys);
  2. typed policy evaluation (linkage + policy stage) on pre-decoded objects;
  3. (r3) exact-object status key derivation: SHA-256 digest of the three signed byte
     strings, plus key construction;
  4. simulated status lookup with precomputed keys (in-memory fixture, 3 lookups).
  Full-chain end-to-end (decode → status) is reported for context; timer overhead
  (an empty timed call) too, so tiny series can be read against it. Results from before
  r3 (status keyed by id/version only) are kept and marked historical.
- Warm-up iterations, then N timed iterations per run, R repeated runs (N = 10 000,
  R = 10). Report p50/p95/p99 per run and the median of each across runs.
- Record: rustc/cargo versions, crate versions (Cargo.lock), CPU model, core count, kernel,
  build profile, N, R and seeds. Results go to `results/bench_<timestamp>.json` and `.md`.
- Reported numbers are only what the run produced; nothing is extrapolated.

## 10. Public API boundary test (r3.1)

Not a labelled case. `tests/predecoded_api.rs` and the doctests in `src/verifier.rs` pin
the decision API boundary (spec §7.5). The reproduction (commit `bcfe70f`) showed that the
former public `verify_decoded` accepted a decoded grant whose body had been changed to
test_scope [auth_testing] while its signed payload still said [injection_testing, recon].
After the fix:

- the field assignment and the `verify_decoded` call no longer compile (E0616, E0599);
- decoded bodies equal the strict decoding of their signed payloads;
- the same alteration made in a raw bundle's grant payload, keeping the original
  signature, is `Reject / S / InvalidSignature{G}`.

## 11. RQ5 session cases (slice s1; all **Rv**, approved 2026-10-16)

Spec: [session.md](session.md). Labels live in `tests/cases/session_cases.toml`, a separate
file; the r3.1 chain and lookup labels file is not touched. They were written before the
implementation and approved by the owner on 2026-10-16 as written. A multi-step case lists the
outcome of each step in order, separated by ` ; `.

**Session fixture.**
- The chain is the base chain (§2), all objects registered Active.
- P's session id is `sess-p-0001`.
- The challenge is issued at now = 2026-10-15T10:00:00Z (ε = 2 s) with TTL 120 s, so it
  expires at 10:02:00Z.
- Redemption runs at now = 10:01:00Z, ε = 2 s, in session `sess-p-0001`.
- The proof is signed by K(tester-1) over the response bytes of the issued challenge.
- Any of these may be changed by the case.

### Redemption (kind `session`)

| ID | Mutation | Expected |
| --- | --- | --- |
| SS01 | none | `SessionAccept` |
| SS02 | copied bundle presented with no proof | `SessionReject / proof / MissingProof` |
| SS03 | proof signed by K(tester-2) (wrong key) | `SessionReject / pop / InvalidProofSignature` |
| SS04 | copied bundle; proof signed by K(attacker) | `SessionReject / pop / InvalidProofSignature` |
| SS05 | redeem the valid proof twice (replay) | `SessionAccept ; SessionReject / challenge / ChallengeAlreadyConsumed` |
| SS06 | redeem in session `sess-p-0002` (cross-session) | `SessionReject / binding / SessionMismatch` |
| SS07 | challenge issued for base G; redeemed with a bundle carrying G2 (engagement_id changed, re-signed, registered Active) (cross-grant) | `SessionReject / binding / GrantMismatch` |
| SS08 | stored challenge has audience Q (as if written by Q's issuer into a shared store), validly signed by K(tester-1) | `SessionReject / binding / ChallengeAudienceMismatch` |
| SS09 | redeem at 10:02:00Z, ε = 0 (expiry) | `SessionReject / time / ChallengeExpired` |
| SS10 | redeem at 10:01:59Z, ε = 2 (straddles expiry) | `SessionIndeterminate / time / ClockUncertainty` |
| SS11 | redeem at 10:01:57Z, ε = 2 (now + ε < expiry) | `SessionAccept` |
| SS12 | challenge store unavailable at redemption | `SessionIndeterminate / challenge / ChallengeStateUnavailable` |
| SS13 | proof names a challenge_id that P never issued | `SessionReject / challenge / UnknownChallenge` |
| SS14 | grant payload in the bundle replaced with test_scope [auth_testing], original signature kept (altered grant) | `SessionReject / chain / ChainRejected(Reject / S / InvalidSignature{G})` |
| SS15 | status source unavailable at redemption; valid proof | `SessionIndeterminate / chain / ChainIndeterminate(Indeterminate / X / StatusUnavailable)` |
| SS16 | status source unavailable; proof signed by K(tester-2) | `SessionReject / pop / InvalidProofSignature` |
| SS17 | tester signs a copy of the challenge with session_id `sess-attacker`, sends the real challenge_id | `SessionReject / pop / InvalidProofSignature` |
| SS18 | tester signs the right challenge bytes with type tag `EngagementGrant` | `SessionReject / pop / InvalidProofSignature` |
| SS19 | proof JSON has an extra field `session_id` | `SessionReject / proof / MalformedProof` |
| SS20 | first a K(tester-2) proof, then the valid proof (failed attempt must not consume) | `SessionReject / pop / InvalidProofSignature ; SessionAccept` |
| SS21 | first with status unavailable, then with status available (Indeterminate must not consume) | `SessionIndeterminate / chain / ChainIndeterminate(Indeterminate / X / StatusUnavailable) ; SessionAccept` |
| SS22 | 8 concurrent redemptions of the same valid proof (each on its own thread, released together by a barrier); the tally counts a loser only when it is specifically `SessionReject` with `ChallengeAlreadyConsumed` | `accepts=1 already_consumed=7 other=0` |
| SS23 | G marked revoked after issuance, before redemption | `SessionReject / chain / ChainRejected(Reject / X / Revoked{G})` |
| SS24 | clock unavailable at redemption | `SessionIndeterminate / chain / ChainIndeterminate(Indeterminate / T / ClockUnavailable)` |

### Issuance (kind `issue`)

| ID | Mutation | Expected |
| --- | --- | --- |
| SI01 | none | `Issued expires_at=2026-10-15T10:02:00Z` |
| SI02 | G status revoked | `IssueRefused / Reject / X / Revoked{G}` |
| SI03 | challenge store unavailable | `IssueUnavailable / ChallengeStateUnavailable` |
| SI04 | G re-signed with window end 10:01:00Z (expiry clamped to the grant) | `Issued expires_at=2026-10-15T10:01:00Z` |

**Count:** 28 session-slice cases (24 redemption, 4 issuance), all owner-reviewed on
2026-10-16. Reported separately from the 93 chain and 15 lookup labels, which are unchanged.

**TTL is fixed at 120 s** (no public override). With any RFC 3339 clock (max year 9999 ≪
`i64::MAX`) `issued_at + 120 s` never overflows, so `expires_at = min(issued_at + 120 s,
G.window.end)` exactly and the fixed-120 guarantee always holds. The implementation uses
checked arithmetic; the overflow branch (fall back to `G.window.end`) is an unreachable
fail-closed guard, not a second behaviour, and adds no new outcome or case.

**Issuance clock consistency (SI05 reviewed; SI06, SI07 proposed — defined before the
fix code).** The clock may return different readings on the chain check and the later
issuance read, and `Ts`/`ClockReading` are publicly constructible, so an invalid issuance
reading must be rejected (never silently clamped) with `IssueUnavailable / InvalidClockReading`
and no stored challenge. The validated conditions (session.md §4) are: `epsilon ≥ 0`;
`issued_at` and `expires_at` canonically representable; `G.window.start ≤ issued_at <
G.window.end`; and `expires_at > issued_at`. Cases, each with expected
`IssueUnavailable / InvalidClockReading`:

- **SI05** (reviewed): issuance reading at/after `G.window.end` (clock advanced past the
  grant between the chain check and issuance).
- **SI06** (proposed): issuance reading **before** `G.window.start` (the challenge would
  predate the grant).
- **SI07** (proposed): issuance reading with a **negative** uncertainty `epsilon`.

Their runners use a changing injected clock and are added with the clock-fix commit.

## 12. RQ6 enforcement cases (slice e2; implemented; EE01–EE27 **Rv**)

Spec: [enforcement.md](enforcement.md) (DRAFT e2). Labels live in
`tests/cases/enforcement_cases.toml`, a separate file. **Not implemented** — these are
implemented in `src/enforcement.rs`. EE01–EE27 are owner-reviewed (the tooltable/v0
mapping is approved, and EE27 — the PartiallyAllowed-without-exclusion boundary — is now
reviewed too).

**Enforcement fixture.**
- Base chain (§2), all objects Active; a session is authorized for the base G.
- G `test_scope = {injection_testing, read_only_data_access, recon}` (a subset of D_U's
  ceiling); targets `{/app, cluster1/main/billing}`; exclusions `{/app/admin, /app/private}`.
  So `web.get` (now `read_only_data_access`) and `web.injection_probe` are in class scope,
  while `db.write` (`data_modification`) and `web.auth_probe` (`auth_testing`) are not.
- The session's `grant_window_end` = G.window.end = 2026-10-15T11:00:00Z.
- Mediation runs at now = 2026-10-15T10:30:00Z, ε = 2; `session_ref` is supplied by P's
  authenticated server context (not a request field), `= sess-p-0001` unless noted.
- `web:…` abbreviates `web:https://app.acme.test:443`.

Display: `Allow effects=1`, or `<Deny|Indeterminate> / <stage> / <Reason> effects=0`.

| ID | Operation, target (note) | Expected |
| --- | --- | --- |
| EE01 | `web.get` `/app/reports` | `Allow effects=1` |
| EE02 | `web.head` `/app` | `Allow effects=1` |
| EE03 | `web.injection_probe` `/app/reports` (subtree wholly allowed) | `Allow effects=1` |
| EE04 | `db.read` `db:cluster1/main/billing` | `Allow effects=1` |
| EE05 | `web.get` `/app/admin` | `Deny / scope / DenyTargetExcluded effects=0` |
| EE06 | `web.get` `/app/admin/users/7` | `Deny / scope / DenyTargetExcluded effects=0` |
| EE07 | `web.get` `/app/private/report` | `Deny / scope / DenyTargetExcluded effects=0` |
| EE08 | `web.get` `/other` | `Deny / scope / DenyTargetOutOfScope effects=0` |
| EE09 | `web.get` `web:https://shop.globex.test:443/` | `Deny / scope / DenyTargetOutOfScope effects=0` |
| EE10 | `db.write` `db:cluster1/main/billing` (`data_modification` not in scope) | `Deny / class / DenyTestClassNotPermitted effects=0` |
| EE11 | `web.auth_probe` `/app/reports` (`auth_testing` not in grant scope) | `Deny / class / DenyTestClassNotPermitted effects=0` |
| EE12 | `db.write` `db:cluster1/main/billing` (claimed_class = recon; claim ignored) | `Deny / class / DenyTestClassNotPermitted effects=0` |
| EE13 | `fs.delete` `/app` (unknown operation) | `Deny / classify / DenyUnknownOperation effects=0` |
| EE14 | `db.read` `/app/reports` (target-type mismatch: a Db operation on a Web target) | `Deny / effects / DenyTargetTypeMismatch effects=0` |
| EE15 | `web.flood` `/app` (type-valid Web target; unbounded footprint) | `Deny / effects / DenyUnboundedSecondaryEffect effects=0` |
| EE16 | `web.get` `/app/reports`, now = 2026-10-15T11:00:00Z, ε = 0 (session window ended) | `Deny / expiry / DenySessionExpired effects=0` |
| EE17 | `web.get` `/app/reports`, authenticated `session_ref = sess-p-9999` (no authorization) | `Deny / session / DenyNoSession effects=0` |
| EE18 | `web.get` `/app/reports`, session authorized for base G but the bundle presents G2 (engagement_id changed, re-signed, Active); StatusKey differs | `Deny / chain / DenyGrantMismatch effects=0` |
| EE19 | `web.get` `/app/reports`, session store unavailable | `Indeterminate / session / SessionStateUnavailable effects=0` |
| EE20 | `web.get` `/app/reports`, status source unavailable | `Indeterminate / chain / ChainIndeterminate(Indeterminate / X / StatusUnavailable) effects=0` |
| EE21 | `web.get` `/app/reports`, clock unavailable | `Indeterminate / expiry / ClockUnavailable effects=0` |
| EE22 | `web.get` `/app/reports`, grant payload altered with the original signature kept | `Deny / chain / ChainRejected(Reject / S / InvalidSignature{G}) effects=0` |
| EE23 | `web.get` `/app/reports`, session authorized for a recon-only grant (G.test_scope = {recon}, re-signed within the D_U ceiling) | `Deny / class / DenyTestClassNotPermitted effects=0` |
| EE24 | `web.injection_probe` `/app` (subtree contains the excluded `/app/admin`, `/app/private`; partially allowed via exclusion) | `Deny / scope / DenySubtreePartiallyAllowed effects=0` |
| EE25 | `web.get` with target host `APP.acme.test` (non-canonical) | `Deny / validate / DenyNoncanonicalTarget effects=0` |
| EE26 | `web.get` `/app/reports`, G status set revoked before mediation | `Deny / chain / ChainRejected(Reject / X / Revoked{G}) effects=0` |
| EE27 | `db.write` `db:cluster1/main`, grant targets only `db:cluster1/main/billing` (no exclusion); `cluster1/main` subtree is partly in scope (`billing`) and partly out (`hr`); scope precedes class | `Deny / scope / DenySubtreePartiallyAllowed effects=0` |

Zero-effect property: every non-Allow label carries `effects=0`; a future runner must
assert the effect sink length is unchanged for EE05–EE26.

**Count:** 27 enforcement cases (4 allow, 20 deny, 3 indeterminate), all owner-reviewed. EE27 demonstrates a `PartiallyAllowed` subtree arising with no explicit
exclusion and that the scope stage precedes the class stage. Reported separately from the
93 chain, 15 lookup and 28 session labels, which are unchanged.
