# Provider-verified authorization chains — specification (DRAFT r2)

**Status:** DRAFT r2, 2026-10-15. Owner decisions on r1 open questions are applied (§10).
This is a research working hypothesis, not a final protocol or a proven contribution.
Case labels carry an explicit review status in [experiment.md](experiment.md).

**Scope of this slice:** RQ4 — how an issuer delegation and an engagement grant express
asset, time, exclusion and constraint scope, and how provider P checks that the chain
O → admin → authorizer → tester never amplifies authority. RQ1 and RQ2 are *assumed*
(trusted fixtures). RQ5, RQ6 and RQ7 are *unresolved* and are not implemented (§9).

---

## 1. Where-glossary

| Symbol | Meaning |
| --- | --- |
| P | AI agent service provider. Verifies evidence and signed scope; decides only about its own execution. Identified to signed objects by an **audience** string, e.g. `urn:aisig:provider:p-synthetic`. |
| O | Organization / target owner. The only party that defines testing permission. Identified by `org_id`. |
| A | A typed asset (`AssetRef`): in v0 a `WebOriginPath` or a `DatabaseSchema`. |
| T | Tester who accepted an engagement. Distinct from an agent runtime/session (RQ5). |
| K_O, K_admin, K_authorizer, K_T | Ed25519 **public** keys of O's root, O's admin, O's internal authorizer, and the tester. Signing uses the matching secret keys. |
| keyid(K) | Lowercase hex SHA-256 of the raw 32-byte Ed25519 public key. |
| R_O | P's registry record pinning (org_id, K_O). Not a signed object; P stores it after manual review (RQ1 assumed). |
| C_A | `AdminDelegation`, signed by K_O: gives K_admin explicitly listed admin rights and bounds. |
| D_U | `IssuerDelegation`, signed by K_admin: gives K_authorizer the right **to issue** engagement grants inside an envelope. Not a permission to test. |
| G (G_T) | `EngagementGrant`, signed by K_authorizer: gives tester key K_T permission **to test** a scope. |
| t | P's trusted UTC decision instant, from an injected clock. |
| ε | The clock's stated uncertainty bound (seconds, ≥ 0). |
| Allowed(X) | Included(X) minus Excluded(X), as sets of concrete assets (§4). |
| Admissible(X) | No included entry of X is fully removed by X's own exclusions (§4.2). |
| Anchor_P(O,K_O,t) | P's registry holds an active, correctly-typed record pinning K_O for O, valid at t. |
| Bind_P(O,A,t) | P's binding fixture records that O may grant testing on A. **Assumed trusted fixture (RQ2).** |
| V_K(X) | The Ed25519 signature on object X verifies with public key K over X's exact signed bytes (§3). Says nothing about authority or scope. |
| CanDelegate(C_A,D_U) | C_A lets K_admin issue issuer delegations, and D_U stays within C_A (§5.2). |
| MayIssue(D_U,G) | D_U lets K_authorizer issue G as written (§5.3). |
| Active(C_A,D_U,G,t) | Every object is inside its validity window at t and the status source reports it Active at its version (§6). |
| H | The hypothesis "the presented C_A is authentic under O's pinned key", used only when the registry is unavailable (§7.2). |
| ValidChain_P(G,t) | The decision rule (§7). Accept means "chain-valid for P"; it is **not** a ProviderExec decision, not a session proof, not tool enforcement. |

---

## 2. Data model

All signed payloads carry `format = "aisig/v0"`. Field names are snake_case. Required
fields must be present. Optional fields have the documented default when absent and must
be **absent** (not `null`, not an empty list) when unused.

### 2.1 Common types

- **Time**: RFC 3339 string, UTC, literal uppercase `Z`, second precision, e.g.
  `2026-10-15T09:00:00Z`. Only this canonical form is accepted in signed payloads.
  A string without an offset is `MalformedTime`; a parseable RFC 3339 string in any other
  form (non-`Z` offset, fractional seconds, lowercase `z`/`t`) is `NonCanonicalTime`.
  Signer tooling must normalize to `Z` **before signing**; the verifier never normalizes.
- **Validity / window**: `{ "end": Time, "start": Time }`, half-open `[start, end)`,
  `start < end` required (else `MalformedWindow`).
- **PublicKey**: base64url (no padding) of 32 raw Ed25519 bytes that decode to a valid point.
- **ObjRef**: `{ "id": string, "version": integer ≥ 1 }`.
- **TestClass** — vocabulary `aisig-testclass/v0`, bound to `format = aisig/v0`:
  `recon`, `auth_testing`, `injection_testing`, `read_only_data_access`,
  `data_modification`, `availability_stress`. O chooses which classes it permits.
  These are technique classes, **not tool names**. Unknown values are rejected at decode
  (`UnknownEnumValue`). How a class maps to concrete agent actions, and how that mapping
  is enforced, is **unresolved** (RQ6); v0 only compares sets of classes.
- **TestScope** (grant field, required): either `{ "kind": "unrestricted" }` — O's explicit,
  signed choice to place no class restriction — or
  `{ "classes": [TestClass…], "kind": "classes" }` with a non-empty set.
- **Constraint**: `{ "critical": bool, "name": string, "value": string }`. Lists are sorted
  by `name`; a name may appear once (else `DuplicateConstraintName`). The only constraint
  known in v0 is `max_requests_per_second` (value: decimal integer ≥ 1, no leading zeros).

### 2.2 Assets (`AssetRef`)

Tagged by `kind`.

**WebOriginPath** — `{ "host", "kind": "web", "path", "port", "scheme" }`

- `scheme`: `https` or `http` (other schemes: `UnsupportedAssetSyntax`).
- `host`: lowercase ASCII LDH labels joined by `.`, each 1–63 chars, total ≤ 253, no
  trailing dot, no IDN/Unicode (punycode `xn--` labels are plain LDH).
  A wildcard (`*`) anywhere in the host is `UnsupportedAssetSyntax` in v0.
  Uppercase letters are `NonCanonicalAsset`.
- `port`: integer 1–65535, always explicit.
- `path`: `/` or `/seg1/seg2…` with no trailing slash. Segments match `[A-Za-z0-9._~-]+`,
  are case-sensitive, and must not be `.` or `..`. A trailing slash, empty segment, `.`/`..`
  segment or `%` is `NonCanonicalAsset`; other characters are `MalformedAsset`.
- Shorthand used in docs: `web:https://app.acme.test:443/app`.

**DatabaseSchema** — `{ "cluster", "database"?, "kind": "db", "schema"? }`

- Names match `[a-z0-9_]{1,63}`. `schema` requires `database`.
- Denotes the whole cluster, one database, or one schema.
- Shorthand: `db:cluster1/main/billing`.

**within(x, y)** — "every concrete asset denoted by x is denoted by y":

- Web: same scheme, host and port, and y's path segments are a **segment prefix** of x's.
  So `/app` covers `/app` and `/app/x`, but not `/application`.
- Db: same cluster, and y's components (database, schema) are a prefix of x's.
- Web vs Db: always false. Never an error.

Every asset denotes a subtree of a forest of concrete nodes, so any two assets are either
nested or disjoint (laminar). §4 relies on this.

### 2.3 Provider root registry (P-local, unsigned)

`RootRecord = { org_id, root_key: PublicKey, key_id, algorithm: "Ed25519",
validity: Validity, usage: "org-delegation-root", version, evidence_ref, accepted_at,
status: active | suspended | revoked }`

The registry is P's own trust store. Presenting a self-signed root never adds an entry.

### 2.4 AdminDelegation — C_A (signed by K_O)

| Field | Req | Meaning |
| --- | --- | --- |
| format | R | `aisig/v0` |
| id, version | R | Object identity and revision |
| org_id | R | Tenant |
| audience | R | Provider P this chain is addressed to |
| issuer_key_id | R | keyid(K_O) |
| subject_key | R | K_admin |
| rights | R | Non-empty set of `may_delegate_grant_issuer`, `account_administration` |
| bounds.included | R | Non-empty set of AssetRef |
| bounds.excluded | O | Set of AssetRef; default empty |
| bounds.test_ceiling | O | Non-empty set of TestClass; **absent = no class ceiling** |
| bounds.max_engagement_seconds | O | Integer ≥ 1; absent = no limit |
| validity | R | Validity |
| constraints | O | Constraint list; default empty |

### 2.5 IssuerDelegation — D_U (signed by K_admin)

| Field | Req | Meaning |
| --- | --- | --- |
| format, id, version, org_id, audience | R | As above |
| issuer_key_id | R | keyid(K_admin) |
| subject_key | R | K_authorizer |
| right | R | Exactly `may_issue_engagement` |
| parent | R | ObjRef of C_A |
| envelope.included | R | Non-empty set of AssetRef that grants may target |
| envelope.mandatory_exclusions | O | Set of AssetRef every grant must exclude where it overlaps; default empty |
| envelope.test_ceiling | O | Non-empty set of TestClass; absent = no class ceiling |
| envelope.max_engagement_seconds | O | Integer ≥ 1; absent = no limit |
| validity | R | Window in which D_U may be relied on |
| constraints | O | Constraint list |

Ceilings on delegations stay optional: an absent ceiling on C_A or D_U is a documented
"no ceiling" default chosen by the signer of that delegation. Only the final grant must
state its test scope explicitly (§2.6).

### 2.6 EngagementGrant — G (signed by K_authorizer)

| Field | Req | Meaning |
| --- | --- | --- |
| format, id, version, org_id, audience | R | As above |
| issuer_key_id | R | keyid(K_authorizer) |
| tester_key | R | K_T. Recorded and signed; **presenter proof is RQ5, not checked** |
| engagement_id | R | Engagement reference |
| parent | R | ObjRef of D_U |
| targets | R | Non-empty set of AssetRef |
| exclusions | O | Set of AssetRef; default empty |
| test_scope | R | TestScope: explicit `unrestricted` or an explicit non-empty set of classes. **No default.** |
| window | R | Engagement window |
| constraints | O | Constraint list |

Tool names, tool brands and call sequences are deliberately not fields.

### 2.7 Chain bundle and the optional root slot

`Bundle = { root?: bytes, admin?: bytes, issuer?: bytes, grant?: bytes }`, each slot holding
the raw bytes of one envelope (§3).

- `admin`, `issuer`, `grant` are required. A missing one is `Reject / F /
  MissingRequiredObject{slot}`. v0 supports exactly this three-link depth.
- `root` is optional and carries a self-signed `OrganizationRoot` envelope
  (`{ algorithm, format, key_id, org_id, root_key, usage, validity, version }`,
  signed by the key it names).
- **The chain-aware verifier ignores the `root` slot completely.** It never reads, parses,
  decodes or verifies those bytes. Absent, well-formed, malformed, mismatched or
  attacker-supplied root bytes all produce the same decision as each other. Its only trust
  input for K_O is P's registry.
- **The signature-only baseline parses the `root` slot** and takes K_O from it (§7.3). A
  missing or unparseable root slot makes the baseline Reject.

---

## 3. Signed bytes (versioned, deterministic)

**Envelope (unsigned wrapper):**
`{ "payload": base64url(payload_bytes), "sig": { "alg": "Ed25519", "key_id": hex,
"value": base64url(64 bytes) }, "type": TypeTag }`

TypeTag ∈ `OrganizationRoot`, `AdminDelegation`, `IssuerDelegation`, `EngagementGrant`.
`sig.key_id` is a lookup hint only. Verification keys always come from chain context.

**Signed bytes:** `"aisig-v0" || 0x00 || TypeTag || 0x00 || payload_bytes`, where TypeTag is
the type **expected for the bundle slot**. The type tag gives domain separation, so a
signature made for one object type never verifies as another type.

**Canonical payload** (a JSON subset intended to match RFC 8785 on this restricted domain;
not yet conformance-tested against JCS):

1. UTF-8; all identifier and string values printable ASCII.
2. No insignificant whitespace; object keys sorted bytewise; no duplicate keys.
3. Values are strings, booleans, integers with |n| < 2^53, arrays, objects. No floats, no `null`.
4. Set-valued arrays (rights, assets, test classes) are sorted by the canonical encoding of
   each element, bytewise, with no duplicates. Constraint lists are sorted by `name`.

**Per-object decoding (stage F), in order:**

1. Parse the envelope (`MalformedEnvelope`); `type` must match the slot (`WrongObjectType{slot}`);
   `sig.alg` must be `Ed25519` (`UnsupportedAlgorithm`).
2. Strictly parse the payload: duplicate keys → `DuplicateField`; `null` → `NonCanonicalEncoding`;
   floats or out-of-range integers → `MalformedField`.
3. `format` present and ≠ `aisig/v0` → `UnsupportedVersion`.
4. Decode into the typed struct: unknown field → `UnknownField`; missing required field →
   `MissingRequiredField`; unknown enum value → `UnknownEnumValue`; time, window, key and
   asset rules of §2 → their named reasons; other type errors → `MalformedField`.
5. Set rules: duplicate constraint names → `DuplicateConstraintName`; empty required sets or
   malformed known-constraint values → `MalformedField`; unsorted or duplicated set
   elements → `NonCanonicalEncoding`.
6. Re-encode the typed value canonically; it must equal `payload_bytes` exactly
   (`NonCanonicalEncoding`).

Slots are decoded in the order admin, issuer, grant. Decoding runs before signature
verification only to find key references. No authorization or scope decision uses an
object's fields until its signature verifies (or, under H in §7.2, until it verifies under
the asserted key, and then only to derive a Reject).

The implementation uses a maintained Ed25519 library (`ed25519-dalek` 2.x, `verify_strict`)
and SHA-256 from `sha2`. It does not implement primitives.

---

## 4. Scope set semantics

### 4.1 Effective permission

For an object X with included set I and excluded set E:
`Allowed(X) = { a : ∃i∈I. within(a,i) } \ { a : ∃e∈E. within(a,e) }`.

### 4.2 Admissibility

`Admissible(I,E)` ⇔ there is no `i ∈ I` and `e ∈ E` with `within(i, e)`. That is, no included
entry is fully removed by the object's own exclusions. Exclusions that do not overlap any
included entry are inert and allowed.

An inadmissible C_A.bounds, D_U.envelope or G scope is `Reject / P / InadmissibleScope{obj}`.
This rejects some objects whose effective permission is harmless (for example a redundant
target that is also excluded). That is a deliberate, conservative choice: it keeps the
subset test below exact and gives every verifier one unambiguous reading.

### 4.3 Subset test

`ScopeWithin(child(I_c,E_c), parent(I_p,E_p))` holds iff for every `g ∈ I_c`:

1. ∃ `p ∈ I_p` with `within(g, p)`;
2. no `e ∈ E_p` with `within(g, e)`;
3. for every `e ∈ E_p` with `within(e, g)`, ∃ `e' ∈ E_c` with `within(e, e')`.

**Claim (for laminar asset sets).** If the child is admissible, then
`ScopeWithin(child, parent) ⇔ Allowed(child) ⊆ Allowed(parent)`. The equivalence is
**not** claimed for inadmissible children.

*Proof sketch (not machine-checked).* Write root(g) for the node at the top of subtree g.
(⇒, no admissibility needed) Take x ∈ Allowed(child) with x ∈ g ∈ I_c. Condition 1 puts x in
some p. If x ∈ e ∈ E_p then e and g are nested (laminar). within(g,e) is ruled out by
condition 2, so within(e,g), and condition 3 gives e' ∈ E_c containing x, contradicting
x ∈ Allowed(child).
(⇐, uses admissibility) Take g ∈ I_c. Admissibility puts root(g) in Allowed(child), hence in
Allowed(parent), which gives conditions 1 and 2. For condition 3, if e ∈ E_p and within(e,g),
then root(e) ∈ Included(child) and root(e) ∉ Allowed(parent), so root(e) ∉ Allowed(child),
so some e' ∈ E_c contains root(e), i.e. within(e, e').

**Counterexample without admissibility.** Parent: include `/app`, exclude `/app/private`.
Child: include `/app/reports` and `/app/private`, exclude `/app/private`.
Allowed(child) = `/app/reports` subtree ⊆ Allowed(parent), but condition 2 fails for the
included `/app/private`. Under v0 the child is inadmissible, so it is rejected as
`InadmissibleScope` before ScopeWithin runs. Stage 3 tests this counterexample and the
claim against an independent brute-force set oracle.

### 4.4 Scope query

`scope_query(G, probe) → InScope | Excluded | OutOfScope` reports where a probe asset lies
relative to an accepted grant: OutOfScope if no target contains it, Excluded if some
exclusion contains it, otherwise InScope. It is a lookup, **not enforcement** of agent
actions (RQ6).

---

## 5. Authorization predicates (pure; no cryptography)

### 5.1 Linkage (stage L), in order

1. org_id equal across C_A, D_U, G (else `TenantMismatch`).
2. audience of C_A, D_U, G (in that order) equals P's own audience (else `WrongAudience{obj}`).
3. `D_U.issuer_key_id == keyid(C_A.subject_key)` (else `IssuerKeyMismatch{D_U}`);
   `D_U.parent.id == C_A.id` (else `ParentMismatch{D_U}`), then version (`ParentVersionMismatch{D_U}`).
4. The same three checks for G against D_U (`IssuerKeyMismatch{G}`, `ParentMismatch{G}`,
   `ParentVersionMismatch{G}`).

### 5.2 Policy stage (stage P), in order

1. **Critical constraints.** For C_A, D_U, G in order, an unknown constraint with
   `critical = true` → `Reject(UnsupportedCriticalConstraint{obj})`. An unknown non-critical
   constraint is ignored. Known constraints are evaluated by their semantics regardless of
   the flag.
2. **Admissibility** of C_A.bounds, D_U.envelope, G (in that order) → `InadmissibleScope{obj}`.
3. **CanDelegate(C_A, D_U):**
   1. `may_delegate_grant_issuer ∈ C_A.rights` (else `MissingDelegationRight`). The label
      "admin" or `account_administration` alone does not confer it.
   2. `ScopeWithin(D_U.envelope(included, mandatory_exclusions), C_A.bounds(included, excluded))`
      (else `DelegationAmplifies{assets}`).
   3. If C_A has a test ceiling, D_U must have one that is a subset (`{test_ceiling}`).
   4. If C_A has a max duration, D_U must have one that is ≤ (`{max_duration}`).
   5. `D_U.validity ⊆ C_A.validity` (`{validity}`).
   6. Each known constraint on C_A must appear on D_U with value ≤ (`{constraints}`).
4. **MayIssue(D_U, G):**
   1. `ScopeWithin(G(targets, exclusions), D_U.envelope)`, reporting per target the first
      failing condition: 1 → `TargetOutsideEnvelope`, 2 → `TargetInMandatoryExclusion`,
      3 → `MissingMandatoryExclusion`.
   2. Test scope: if D_U has a ceiling, G.test_scope must be `classes` with a subset of it.
      An explicit `unrestricted` under a ceiling → `TestScopeAmplifies`.
   3. `G.window ⊆ D_U.validity` (`WindowExceedsParent`).
   4. If D_U has max_engagement_seconds: `end − start ≤ max` (`DurationExceedsMax`).
   5. Each known constraint on D_U must appear on G with value ≤ (`ConstraintAmplifies`).

The provider evaluates only what the owner signed. It never adds, removes or reinterprets
the owner's test classes or targets.

---

## 6. Evidence, time and status (injected fixtures)

- **Anchor (stage N):** registry lookup by C_A.org_id.
  - Registry unavailable → `Indeterminate(RegistryUnavailable)` and §7.2 applies.
  - Registry available, no record for org_id → `Reject(UnpinnedOrganization)`.
  - `C_A.issuer_key_id ≠ record.key_id` → `Reject(RootKeyNotPinned)`;
    usage ≠ `org-delegation-root` → `Reject(RootUsageMismatch)`;
    status suspended or revoked → `Reject(RootNotActive)`.
- **Binding (stage B):** for each G target in canonical order, find bindings whose asset
  contains it. Bound to O → ok. Bound only to other orgs → `Reject(AssetBoundToOtherOrg)`.
  No binding → `Indeterminate(NoBindingEvidence)`. Fixture unavailable →
  `Indeterminate(BindingUnavailable)`.
- **Time (stage T):** clock gives `(now, ε)` or Unavailable (`Indeterminate(ClockUnavailable)`).
  For the root record's validity (only if the registry answered), then C_A.validity,
  D_U.validity, G.window, each `[s,e)`:
  - `s ≤ now−ε` and `now+ε < e` → ok;
  - `now+ε < s` → `Reject(NotYetValid{obj})`; `now−ε ≥ e` → `Reject(Expired{obj})`;
  - otherwise → `Indeterminate(ClockUncertainty{obj})`.
  The root record's validity is checked against t only; it need not contain C_A's window.
- **Status (stage X):** status source answers for (id, version) of C_A, D_U, G in order.
  Active → ok. Revoked → `Reject(Revoked{obj})`. Superseded → `Reject(Superseded{obj})`
  (in v0 a superseded parent invalidates all its descendants). Unknown →
  `Indeterminate(StatusUnknown{obj})`. Unavailable → `Indeterminate(StatusUnavailable)`.
  The fixture is a simulation; real freshness and revocation delay are RQ7.

---

## 7. Decision rule

`Decision = Accept | Reject{stage, reason} | Indeterminate{stage, reason}`

### 7.1 Order and dominance

Stages in fixed order: **F** format/decoding (§3) → **N** anchor → **S** signatures
(C_A with registry K_O, D_U with C_A.subject_key, G with D_U.subject_key) → **L** linkage →
**P** policy → **B** binding → **T** time → **X** status.

- The first **Reject** ends evaluation and is the decision.
- An **Indeterminate** is recorded and evaluation continues, so a later Reject still wins.
- If no Reject occurs, the first recorded Indeterminate is the decision.
- **Accept** only if every stage completed positively with all evidence available.

### 7.2 Unavailable evidence: what may still be checked

*Principle:* with some evidence unavailable, the verifier may return Reject only if
every possible answer that evidence could give would also lead to Reject. Nothing checked
in the absence of evidence ever counts towards Accept.

**Registry unavailable (the only case that affects authentication).** C_A cannot be
authenticated, so K_admin and K_authorizer are only *asserted* by unauthenticated content.
The verifier records `Indeterminate(N, RegistryUnavailable)` and continues under H.

- *Proceeds under H:* signatures of D_U (with asserted K_admin) and G (with asserted
  K_authorizer); linkage; policy (CanDelegate, MayIssue, constraints, admissibility); binding;
  time for C_A, D_U, G; status.
- *Becomes Indeterminate:* the anchor itself, C_A's signature, and the root record's
  time check (all subsumed by the recorded `RegistryUnavailable`).
- *Why a Reject under H is consistent:* any registry answer either (i) fails to
  authenticate C_A — no record, key mismatch, wrong usage, inactive root, or bad C_A
  signature — and is then a Reject; or (ii) authenticates C_A, in which case H is true and
  every failure found under H is a real failure, again a Reject. So a contradiction found
  under H implies Reject for every registry answer.
- *Reason reported:* the first contradiction found under H. In outcome (i) a different
  reason would also apply. The reason is therefore "sufficient for rejection", not
  necessarily "the only defect".
- If no contradiction is found under H, the decision is `Indeterminate(N, RegistryUnavailable)`.

**Binding, clock or status unavailable/unknown.** These affect only their own conjunct.
All other stages run on real evidence; a Reject elsewhere wins, otherwise the recorded
Indeterminate is the decision.

### 7.3 Formula

```
ValidChain_P(G,t) = Accept  ⇔
   Anchor_P(O,K_O,t) ∧ ∀A∈targets(G): Bind_P(O,A,t)
 ∧ V_{K_O}(C_A) ∧ V_{K_admin}(D_U) ∧ V_{K_authorizer}(G)
 ∧ Linkage ∧ Admissible(C_A,D_U,G) ∧ CanDelegate(C_A,D_U) ∧ MayIssue(D_U,G)
 ∧ Active(C_A,D_U,G,t)
```

**Test obligations (not proofs):** every case labelled non-Accept is not Accepted; every
case labelled Accept is Accepted; Indeterminate is never treated as Accept. Agreement with
reviewed labels is empirical evidence about this implementation, not a formal soundness
proof of the spec.

### 7.4 Signature-only baseline (deliberately weak)

1. Parse the `root` slot leniently (envelope JSON, base64, payload JSON); read `root_key`.
   Missing or unparseable → Reject.
2. For root, admin, issuer, grant: verify the signature over signed bytes built with the
   **envelope's own** `type`, using K_O = root.root_key for root and admin,
   K_admin = admin.subject_key for issuer, K_authorizer = issuer.subject_key for grant
   (keys read leniently from payload JSON).
3. Accept iff all four verify; otherwise Reject. It never returns Indeterminate.

It performs no registry, canonical-form, linkage, scope, binding, time or status checks.
It exists only as a comparison point; its outcomes are measured, never used as labels.

---

## 8. Assumptions

- **RQ1 (assumed):** P has manually verified O and pinned K_O. The registry fixture stands in for that.
- **RQ2 (assumed):** the asset-binding fixture is trusted evidence of O's right over assets.
- P's registry, binding fixture, clock and status source are honest (P is trusted for its own decisions).
- Secret keys are not compromised, except where a case says otherwise.
- All organizations, hosts (`.test`, RFC 6761), databases and keys are synthetic.

## 9. Unresolved (not implemented in v0)

- **RQ5:** binding G to a presenting tester/session (proof of possession of K_T). `tester_key` is signed but not challenged.
- **RQ6:** enforcing actual agent/tool effects, including how a TestClass maps to actions. `scope_query` is a lookup, not mediation.
- **RQ7:** status freshness and bounded revocation delay. Status is an in-memory fixture.
- RQ3 is partially exercised (fixed depth-3 chain, non-amplification); arbitrary depth and multi-admin policy are not.
- RQ8 (privacy, onboarding cost) is out of scope; CPU latency is measured only for this prototype.
- ProviderExec (P's own service policy) is separate from ValidChain and not modelled.

## 10. Owner decisions (r1 open questions, 2026-10-15)

| # | Question | Decision |
| --- | --- | --- |
| Q1 | Unknown critical constraint | Reject / P / UnsupportedCriticalConstraint. Indeterminate is reserved for unavailable or inconclusive evidence. |
| Q2 | Time offsets other than `Z` | Only canonical UTC `Z` accepted in signed payloads. Normalize before signing, never during verification. |
| Q3 | Superseded parent | Invalidates its descendants in v0 (Reject). |
| Q4 | org_id absent from P's registry | Registry available and no record → Reject. Registry unavailable → Indeterminate. |
| Q5 | Wildcard host | Reject as unsupported v0 syntax (`UnsupportedAssetSyntax`). |
| Q6 | Test-scope vocabulary | Keep the small versioned TestClass vocabulary. O chooses permitted classes; not tool names. Class-to-action interpretation and enforcement remain unresolved. |
| Q7 | Root record validity | Checked at t only; need not contain C_A's window. |
| Q8 | Unknown TestClass value | Reject at decode. |

**r2 corrections:** admissibility rule and a corrected equivalence claim (§4); G.test_scope
made required with an explicit `unrestricted` choice (§2.6); optional root slot defined
and the baseline's use of it specified (§2.7, §7.4); dependency rule for unavailable evidence
(§7.2).

**Open for owner review in r2:** the §7.2 rule (P03 depends on it); M04's clarified
mutation; new cases V09, V10, M20, M21.
