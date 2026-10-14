# Provider-verified authorization chains — specification (DRAFT v0)

**Status:** DRAFT for owner review, 2026-10-15. This is a research working hypothesis, not a
final protocol or a proven contribution. Every decision rule and expected label here is
*proposed* until the research owner signs it off. No verifier code exists yet.

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
| Anchor_P(O,K_O,t) | P's registry holds an active, correctly-typed record pinning K_O for O, valid at t. |
| Bind_P(O,A,t) | P's binding fixture records that O may grant testing on A. **Assumed trusted fixture (RQ2).** |
| V_K(X) | The Ed25519 signature on object X verifies with public key K over X's exact signed bytes (§3). Says nothing about authority or scope. |
| CanDelegate(C_A,D_U) | C_A lets K_admin issue issuer delegations, and D_U stays within C_A (§5.2). |
| MayIssue(D_U,G) | D_U lets K_authorizer issue G as written (§5.3). |
| Active(C_A,D_U,G,t) | Every object is inside its validity window at t and the status source reports it Active at its version (§6). |
| ValidChain_P(G,t) | The decision rule (§7). Accept means "chain-valid for P"; it is **not** a ProviderExec decision, not a session proof, not tool enforcement. |

---

## 2. Data model

All signed payloads carry `format = "aisig/v0"`. Field names are snake_case. Required
fields must be present; optional fields have the documented default when absent and
must be **absent** (not `null`) when unused.

### 2.1 Common types

- **Time**: RFC 3339 string, UTC, literal uppercase `Z`, second precision, e.g.
  `2026-10-15T09:00:00Z`. Any other form (no offset, non-`Z` offset, fractional seconds,
  lowercase `z`) is rejected as malformed or non-canonical (open question Q2).
- **Validity / window**: `{ "start": Time, "end": Time }`, half-open `[start, end)`,
  `start < end` required.
- **PublicKey**: base64url (no padding) of 32 raw Ed25519 bytes.
- **ObjRef**: `{ "id": string, "version": integer ≥ 1 }`.
- **TestClass** (owner-chosen technique classes; never tool names):
  `recon`, `auth_testing`, `injection_testing`, `read_only_data_access`,
  `data_modification`, `availability_stress`. Unknown values are rejected (open question Q6).
- **Constraint**: `{ "name": string, "critical": bool, "value": string }`. Lists are sorted
  by `name`; a name may appear once. The only constraint known in v0 is
  `max_requests_per_second` (value: decimal integer string ≥ 1).

### 2.2 Assets (`AssetRef`)

Tagged by `kind`.

**WebOriginPath** — `{ "kind": "web", "scheme", "host", "port", "path" }`

- `scheme`: `https` or `http`.
- `host`: lowercase ASCII LDH labels joined by `.`, each 1–63 chars, total ≤ 253, no
  trailing dot, no wildcard, no IDN/Unicode (punycode `xn--` labels are allowed as plain LDH).
- `port`: integer 1–65535, always explicit (no scheme default inference).
- `path`: `/` or `/seg1/seg2…` with no trailing slash. Segments match `[A-Za-z0-9._~-]+`,
  are case-sensitive, and must not be `.` or `..`. No percent-encoding, query, or fragment.
- Shorthand used in docs: `web:https://app.acme.test:443/app`.

**DatabaseSchema** — `{ "kind": "db", "cluster", "database"?, "schema"? }`

- Names match `[a-z0-9_]{1,63}`. `schema` requires `database`.
- Represents the whole cluster, one database, or one schema.
- Shorthand: `db:cluster1/main/billing`.

**within(x, y)** — "every concrete asset denoted by x is denoted by y":

- Web: same scheme, host and port, and y's path segments are a **segment prefix** of x's.
  So `/app` covers `/app` and `/app/x`, but not `/application`.
- Db: same cluster, and y's components (database, schema) are a prefix of x's.
- Web vs Db: always false. Never an error.

### 2.3 Provider root registry (P-local, unsigned)

`RootRecord = { org_id, root_key: PublicKey, key_id, algorithm: "Ed25519",
validity: Validity, usage: "org-delegation-root", version, evidence_ref, accepted_at,
status: active | suspended | revoked }`

The registry is P's own trust store. Presenting a self-signed root does not add an entry.
In v0 the bundle may carry a self-signed `OrganizationRoot` (same fields minus
evidence_ref/accepted_at/status); the chain-aware verifier **ignores it**, and only the
signature-only baseline uses it.

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
| bounds.test_ceiling | O | Set of TestClass; **absent = no restriction** |
| bounds.max_engagement_seconds | O | Integer; absent = no limit |
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
| envelope.mandatory_exclusions | O | Set of AssetRef every grant must exclude; default empty |
| envelope.test_ceiling | O | Set of TestClass; absent = no restriction |
| envelope.max_engagement_seconds | O | Integer; absent = no limit |
| validity | R | Window in which D_U may be relied on |
| constraints | O | Constraint list |

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
| test_scope | O | Set of TestClass the owner permits; **absent = no restriction** |
| window | R | Engagement window |
| constraints | O | Constraint list |

Tool names, tool brands and call sequences are deliberately not fields.

### 2.7 Chain bundle

`Bundle = { root?: Envelope<OrganizationRoot>, admin: Envelope<C_A>,
issuer: Envelope<D_U>, grant: Envelope<G> }`. A missing `admin`, `issuer` or `grant`
is a Reject (`MissingRequiredObject`). v0 supports exactly this three-link depth.

---

## 3. Signed bytes (versioned, deterministic)

**Envelope (unsigned wrapper):**
`{ "type": TypeTag, "payload": base64url(payload_bytes), "sig": { "alg": "Ed25519",
"key_id": hex, "value": base64url(64 bytes) } }`

TypeTag ∈ `OrganizationRoot`, `AdminDelegation`, `IssuerDelegation`, `EngagementGrant`.
`sig.key_id` is a lookup hint only. Verification keys always come from chain context.

**Signed bytes:** `"aisig-v0" || 0x00 || TypeTag || 0x00 || payload_bytes`.
The type tag gives domain separation, so a signature made for one object type never
verifies as another type.

**Canonical payload** (a JSON subset intended to match RFC 8785 on this restricted domain;
not yet conformance-tested against JCS):

1. UTF-8; all identifier and string values printable ASCII.
2. No insignificant whitespace; object keys sorted bytewise; no duplicate keys.
3. Values are strings, booleans, integers with |n| < 2^53, arrays, objects. No floats, no `null`.
4. Set-valued arrays (rights, assets, test classes) are sorted by the canonical encoding of
   each element, bytewise, with no duplicates. Constraint lists are sorted by `name`.

**Per-object processing:**

1. Parse the envelope; check `type` matches the bundle slot, `sig.alg == "Ed25519"`.
2. Strictly decode the payload into the typed struct: unknown fields, duplicate keys,
   wrong types, missing required fields, unknown enum values → Reject.
3. Re-encode the decoded struct canonically; it must equal `payload_bytes` exactly
   (this rejects key reordering, whitespace, unsorted/duplicated sets, `null`).
4. Verify the signature over the signed bytes with the key resolved from chain context.

Decoding (steps 1–3) runs before signature verification only to find the key reference.
No authorization or scope decision uses an object's fields until its signature verifies.

The implementation will use a maintained Ed25519 library (`ed25519-dalek` 2.x, strict
verification) and SHA-256 from `sha2`. It will not implement primitives.

---

## 4. Scope set semantics

For an object X with included set I and excluded set E:
`Allowed(X) = { a : ∃i∈I. within(a,i) } \ { a : ∃e∈E. within(a,e) }`.

**Subset test** `ScopeWithin(child(I_c,E_c), parent(I_p,E_p))` — intended to equal
`Allowed(child) ⊆ Allowed(parent)` for prefix-tree assets. It holds iff for every `g ∈ I_c`:

1. ∃ `p ∈ I_p` with `within(g, p)`;
2. no `e ∈ E_p` with `within(g, e)` (target lies entirely inside a parent exclusion);
3. for every `e ∈ E_p` with `within(e, g)`, ∃ `e' ∈ E_c` with `within(e, e')`.

Exclusions in the parent that do not overlap any child target impose nothing on the child.
Exactness of this rule is a claim to be checked: Stage 3 cross-checks it against a
brute-force enumeration over a finite synthetic asset universe.

**Scope query** `scope_query(G, probe) → InScope | Excluded | OutOfScope` reports where a
probe asset lies relative to Allowed(G): OutOfScope if no target contains it, Excluded if
some exclusion contains it, otherwise InScope. It is a lookup on an already-accepted grant,
**not enforcement** of agent actions (RQ6).

---

## 5. Authorization predicates (pure; no cryptography)

### 5.1 Linkage (stage L)

- org_id equal across C_A, D_U, G (else `TenantMismatch`).
- audience of C_A, D_U and G equals P's own audience (else `WrongAudience{obj}`).
- `D_U.issuer_key_id == keyid(C_A.subject_key)`, `G.issuer_key_id == keyid(D_U.subject_key)`
  (else `IssuerKeyMismatch{obj}`).
- `D_U.parent == (C_A.id, C_A.version)`, `G.parent == (D_U.id, D_U.version)`
  (else `ParentMismatch{obj}` / `ParentVersionMismatch{obj}`).

### 5.2 CanDelegate(C_A, D_U)

1. `may_delegate_grant_issuer ∈ C_A.rights` (else `MissingDelegationRight`). The label
   "admin" or `account_administration` alone does not confer it.
2. `ScopeWithin(D_U.envelope(included, mandatory_exclusions), C_A.bounds(included, excluded))`.
3. Test ceiling: if C_A has a ceiling, D_U must have one and it must be a subset.
4. Max duration: if C_A has one, D_U must have one and it must be ≤.
5. `D_U.validity ⊆ C_A.validity`.
6. Known constraints: for each known constraint on C_A, D_U must carry it with value ≤.
Failures 2–6 → `DelegationAmplifies{aspect}`.

### 5.3 MayIssue(D_U, G)

1. `ScopeWithin(G(targets, exclusions), D_U.envelope(included, mandatory_exclusions))`;
   reasons: `TargetOutsideEnvelope`, `TargetInMandatoryExclusion`, `MissingMandatoryExclusion`.
2. Test scope: if D_U has a ceiling, G must have `test_scope` ⊆ ceiling. An absent
   `test_scope` means "no restriction" and therefore amplifies (`TestScopeAmplifies`).
3. `G.window ⊆ D_U.validity` (`WindowExceedsParent`).
4. If D_U has max_engagement_seconds: `end − start ≤ max` (`DurationExceedsMax`).
5. Known constraints inherited as ceilings (`ConstraintAmplifies`), including absence.

### 5.4 Critical constraints

On any object, an unknown constraint with `critical = true` → `Indeterminate
(UnsupportedCriticalConstraint{obj})` (open question Q1). An unknown non-critical one is
ignored. Known constraints are evaluated by their semantics regardless of the flag.

The provider evaluates only what the owner signed. It never adds, removes or reinterprets
the owner's test classes or targets.

---

## 6. Evidence, time and status (injected fixtures)

- **Anchor (stage N):** registry lookup by C_A.org_id.
  - Unavailable → `Indeterminate(RegistryUnavailable)`.
  - No record for org_id → `Reject(UnpinnedOrganization)` (open question Q4).
  - `C_A.issuer_key_id ≠ record.key_id` → `Reject(RootKeyNotPinned)`.
  - Status revoked or suspended → `Reject(RootNotActive)`; usage mismatch → `Reject(RootUsageMismatch)`.
- **Binding (stage B):** for each G target, find a binding whose asset contains it.
  - Bound to O → ok. Bound only to another org → `Reject(AssetBoundToOtherOrg)`.
  - No binding record → `Indeterminate(NoBindingEvidence)`. Fixture unavailable →
    `Indeterminate(BindingUnavailable)`.
- **Time (stage T):** clock gives `(now, ε)` or Unavailable (`Indeterminate(ClockUnavailable)`).
  For each of root record validity, C_A.validity, D_U.validity, G.window `[s,e)`:
  - `s ≤ now−ε` and `now+ε < e` → ok;
  - `now+ε < s` → `Reject(NotYetValid{obj})`; `now−ε ≥ e` → `Reject(Expired{obj})`;
  - otherwise (interval straddles an edge) → `Indeterminate(ClockUncertainty{obj})`.
- **Status (stage X):** status source answers for (id, version) of C_A, D_U, G.
  - Active → ok. Revoked → `Reject(Revoked{obj})`. Superseded → `Reject(Superseded{obj})`
    (open question Q3). Unknown → `Indeterminate(StatusUnknown{obj})`.
    Unavailable → `Indeterminate(StatusUnavailable)`.
  - The fixture is a simulation. Real freshness and revocation delay are RQ7.

Static nesting (D_U ⊆ C_A, G ⊆ D_U) is checked in §5; the root record's validity is only
checked against t, not nested.

---

## 7. Decision rule and check order

`Decision = Accept | Reject{stage, reason} | Indeterminate{stage, reason}`

Stages in fixed order: **F** format/decoding (§3) → **N** anchor → **S** signatures
(C_A with registry K_O, D_U with C_A.subject_key, G with D_U.subject_key) → **L** linkage →
**P** policy (CanDelegate, MayIssue, constraints) → **B** binding → **T** time → **X** status.

- Stop at the first **Reject**; it is the decision.
- An **Indeterminate** is recorded and checking continues, so a later Reject still wins.
  (If the anchor is unavailable, the C_A signature cannot be checked and is recorded
  Indeterminate; later stages still run.)
- If no Reject: the first recorded Indeterminate is the decision.
- **Accept** only if every stage completed positively. Missing evidence never becomes Accept.

```
ValidChain_P(G,t) = Accept  ⇔
   Anchor_P(O,K_O,t) ∧ ∀A∈targets(G): Bind_P(O,A,t)
 ∧ V_{K_O}(C_A) ∧ V_{K_admin}(D_U) ∧ V_{K_authorizer}(G)
 ∧ Linkage ∧ CanDelegate(C_A,D_U) ∧ MayIssue(D_U,G)
 ∧ Active(C_A,D_U,G,t)
```

**Proof obligations (to be tested, not claimed):** *soundness* — every Accept is a valid
chain under this spec; *conditional completeness* — every supported, unambiguous valid
chain is Accepted; Indeterminate is never treated as Accept.

### Signature-only baseline (deliberately weak)

Decodes the bundle, takes K_O from the **presented** self-signed root, and checks
V_{K_O}(root), V_{K_O}(C_A), V_{K_admin}(D_U), V_{K_authorizer}(G) using keys found in the
bundle. Accept if all verify, else Reject. No registry, linkage, scope, binding, time or
status checks. It exists only as a comparison point.

---

## 8. Assumptions

- **RQ1 (assumed):** P has manually verified O and pinned K_O. The registry fixture stands in for that.
- **RQ2 (assumed):** the asset-binding fixture is trusted evidence of O's right over assets.
- P's registry, binding fixture, clock and status source are honest (P is trusted for its own decisions).
- Secret keys are not compromised, except where a case says otherwise.
- All organizations, hosts (`.test`, RFC 6761), databases and keys are synthetic.

## 9. Unresolved (not implemented in v0)

- **RQ5:** binding G to a presenting tester/session (proof of possession of K_T). `tester_key` is signed but not challenged.
- **RQ6:** enforcing actual agent/tool effects. `scope_query` is a lookup, not mediation.
- **RQ7:** status freshness and bounded revocation delay. Status is an in-memory fixture.
- RQ3 is partially exercised (fixed depth-3 chain, non-amplification); arbitrary depth and multi-admin policy are not.
- RQ8 (privacy, onboarding cost) is out of scope; CPU latency is measured only for this prototype.
- ProviderExec (P's own service policy) is separate from ValidChain and not modelled.

## 10. Open questions for owner review

| # | Question | Proposed |
| --- | --- | --- |
| Q1 | Unknown critical constraint | Indeterminate (could be Reject) |
| Q2 | Time offsets other than `Z` | Reject as non-canonical (could normalize) |
| Q3 | Parent version marked Superseded | Reject (could allow until explicit revoke) |
| Q4 | org_id absent from P's registry | Reject, since P's pinned set is authoritative (could be Indeterminate) |
| Q5 | Wildcard host | Reject as malformed (could be Indeterminate as unsupported) |
| Q6 | Test-scope vocabulary | Fixed enum of technique classes (could be opaque owner strings compared by subset) |
| Q7 | Root record validity | Checked at t only, not nested around C_A |
| Q8 | Unknown TestClass value | Reject at decode |
