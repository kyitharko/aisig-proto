# Provider-verified authorization chains — specification (DRAFT r3.1)

**Status:** DRAFT r3.1, 2026-10-15. Owner decisions on r1 open questions are applied, and r3
adds exact-object status identity, registry-record checks and named scope lookups. r3.1
records decisions Q9–Q11 and the public API trust boundary (§7.5, §10).
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
| StatusKey(X) | (org_id, object type, id, version, digest(X)) — the identity under which the status source records exactly one signed object (§6). |
| digest(X) | SHA-256 over X's type-separated signed bytes `"aisig-v0" ‖ 0x00 ‖ TypeTag ‖ 0x00 ‖ payload` (§3, §6). |
| Active(C_A,D_U,G,t) | Every object is inside its validity window at t and the status source reports Active for its exact StatusKey (§6). |
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

The implementation uses a maintained Ed25519 library (`ed25519-dalek` 3.x, `verify_strict`)
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

### 4.4 Scope lookups (not enforcement)

An `AssetRef` denotes a subtree, so a question about a probe asset has two different
readings. v0 exposes both under distinct names. Neither authorizes or enforces anything;
both are lookups on an already-accepted grant (RQ6 remains unresolved).

**Exact-node lookup.** `exact_node_lookup(G, probe) → InScope | Excluded | OutOfScope`
classifies only the single concrete node at the top of the probe: OutOfScope if no target
contains it, Excluded if some exclusion contains it, otherwise InScope. **It says nothing
about the probe's descendants.** Example: in the base grant the node `/app` is InScope
while its descendant `/app/admin` is Excluded. An InScope answer must not be read as
"the subtree `/app` is permitted".

**Subtree lookup.** `subtree_lookup(G, probe) → WhollyAllowed | PartiallyAllowed |
NoneAllowed` classifies the probe's whole subtree N(probe) against the effective set:
WhollyAllowed iff N(probe) ⊆ Allowed(G); NoneAllowed iff N(probe) ∩ Allowed(G) = ∅;
otherwise PartiallyAllowed.

- WhollyAllowed is computed as `ScopeWithin(({probe}, ∅), G)`. The child scope has no
  exclusions, so it is admissible and §4.3 makes this exact.
- NoneAllowed holds iff, for every target i that overlaps the probe (one is within the
  other), the deeper of i and probe lies within some exclusion of G. *Sketch:* by laminarity
  N(i) ∩ N(probe) is the subtree of the deeper node d, and a subtree minus a union of
  subtrees is empty iff root(d) is removed, i.e. d lies within some exclusion.

Both lookups are cross-checked against the enumeration oracle (experiment.md §6, SO3).

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

- **Anchor (stage N):** registry lookup by C_A.org_id, then checks on the returned record
  itself, in order. The lookup key alone never establishes that a record names O.
  - Registry unavailable → `Indeterminate(RegistryUnavailable)` and §7.2 applies.
  - Registry available, no record for org_id → `Reject(UnpinnedOrganization)`.
  - `record.org_id ≠ C_A.org_id` → `Reject(RootOrgMismatch)` (r3).
  - `record.algorithm ≠ "Ed25519"` → `Reject(RootAlgorithmMismatch)` (r3).
  - `C_A.issuer_key_id ≠ record.key_id`, or `record.key_id ≠ keyid(record.root_key)` →
    `Reject(RootKeyNotPinned)`;
    usage ≠ `org-delegation-root` → `Reject(RootUsageMismatch)`;
    status suspended or revoked → `Reject(RootNotActive)`.
  All of these fail closed: no mismatch falls through to a later stage.
- **Binding (stage B):** for each G target in canonical order, find bindings whose asset
  contains it. Bound to O → ok. Bound only to other orgs → `Reject(AssetBoundToOtherOrg)`.
  No binding → `Indeterminate(NoBindingEvidence)`. Fixture unavailable →
  `Indeterminate(BindingUnavailable)`.
- **Time (stage T):** clock gives `(now, ε)` or Unavailable (`Indeterminate(ClockUnavailable)`).
  A reading with `ε < 0` is invalid evidence (spec §6 requires ε ≥ 0; `ClockReading` has
  public fields, so an invalid ε can be supplied): it is **rejected, not clamped** →
  `Indeterminate(InvalidClockReading)`, and the window checks are skipped. For a valid
  reading (`ε ≥ 0`), for the root record's validity (only if the registry answered), then
  C_A.validity, D_U.validity, G.window, each `[s,e)` (bounds saturate, no overflow):
  - `s ≤ now−ε` and `now+ε < e` → ok;
  - `now+ε < s` → `Reject(NotYetValid{obj})`; `now−ε ≥ e` → `Reject(Expired{obj})`;
  - otherwise → `Indeterminate(ClockUncertainty{obj})`.
  The root record's validity is checked against t only; it need not contain C_A's window.
- **Status (stage X):** the status source is queried for C_A, D_U, G in order, each by its
  exact **StatusKey** (r3):

  ```
  StatusKey(X) = ( org_id(X), type(X), id(X), version(X), digest(X) )
  digest(X)    = SHA-256( "aisig-v0" ‖ 0x00 ‖ type(X) ‖ 0x00 ‖ payload_bytes(X) )
  ```

  `type(X)` is the TypeTag of X's bundle slot (`AdminDelegation`, `IssuerDelegation`,
  `EngagementGrant`); `org_id`, `id` and `version` come from X's decoded payload;
  `payload_bytes` are the exact canonical bytes that were signed. The digest is the SHA-256
  of the same type-separated byte string the signature covers, so it binds the type and
  every signed field. The signature bytes are not included: the status identifies the
  signed content, and the signer is already fixed by the chain and by `issuer_key_id`
  inside the payload. The explicit org/type/id/version fields are redundant with the digest
  but let a status service index and audit records. **Content-identity choice (Q10):** the
  digest identifies the signed content, not a particular signature. The signer is fixed by
  the signed `issuer_key_id` and the verified chain, so signature bytes are not hashed.

  **Issuance rule:** an issuer that changes any signed content must issue it under a new
  `version` or a new `id`. Re-signing different content under an existing
  (org, type, id, version) is not a supported way to amend an object; it yields an
  unregistered object (Q9).

  The status source answers a record's status **only for an exact key match**. A record for
  another object never answers, even with the same id and version, or the same id in
  another type. Active → ok. Revoked → `Reject(Revoked{obj})`. Superseded →
  `Reject(Superseded{obj})` (in v0 a superseded parent invalidates all its descendants).
  No matching record → `Indeterminate(StatusUnknown{obj})`, never Accept. This holds even
  when a record exists for the same (org, type, id, version) with a different digest. v0
  does not infer equivocation from a digest difference alone (Q9). Unavailable →
  `Indeterminate(StatusUnavailable)`. The fixture is a simulation; real freshness and
  revocation delay are RQ7.

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


### 7.5 Public API trust boundary (r3.1)

The decision procedure has exactly one public entry point,
`ChainVerifier::verify(&Bundle)`, which takes raw envelope bytes and performs stages F
through X itself. Inside it, every policy field is read from a body that the verifier
obtained by strictly decoding the very payload bytes it then verifies and hashes.

- `decode_chain` is public for inspection only. Its result (`DecodedChain`, `Signed<T>`)
  is read-only: private fields, getters only, no constructor other than decoding. A
  `Signed<T>` body is always the decoding of its own `payload`.
- There is no public way to submit a pre-decoded chain for a decision. In r3 the public
  `verify_decoded` let a caller change a decoded body after decoding while the signature
  and status digest still covered the original payload. Policy then ran on unsigned
  content (reproduced at commit `bcfe70f`). That entry point is now private.
- If a pre-decoded API is needed later, it must accept only values produced by the
  verifier's own decoding (an unforgeable, immutable type), and it must derive every policy
  field from the verified payload.
- This issue concerned the pre-decoded API. No bypass of `verify(&Bundle)` was shown:
  the same alteration made in raw bundle bytes fails signature verification.

---

## 8. Assumptions

- **RQ1 (assumed):** P has manually verified O and pinned K_O. The registry fixture stands in for that.
- **RQ2 (assumed):** the asset-binding fixture is trusted evidence of O's right over assets.
- P's registry, binding fixture, clock and status source are honest (P is trusted for its own decisions).
- Secret keys are not compromised, except where a case says otherwise.
- All organizations, hosts (`.test`, RFC 6761), databases and keys are synthetic.

## 9. Unresolved (not implemented in v0)

- **RQ5:** binding G to a presenting tester/session (proof of possession of K_T). `tester_key` is signed but not challenged.
- **RQ6:** enforcing actual agent/tool effects, including how a TestClass maps to actions. `exact_node_lookup` and `subtree_lookup` are lookups, not mediation.
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

**r2 review outcome (owner, 2026-10-15):** the §7.2 rule, P03, M04's clarified mutation
and V09, V10, M20, M21 were approved.

**r3 changes (owner review of Stages 0–4):**

- Status identity binds the exact signed object (§6, StatusKey). Under the r2 key
  (id, version) a newly signed object could inherit another object's Active status.
- The anchor stage checks the returned registry record's org_id and algorithm (§6) and
  fails closed (`RootOrgMismatch`, `RootAlgorithmMismatch`).
- `scope_query` is replaced by `exact_node_lookup` and `subtree_lookup` (§4.4).

**Open questions after r3:**

| # | Question | Current behaviour |
| --- | --- | --- |
| Q9 | A status record exists for the same (org, type, id, version) but a different digest — equivocation by the issuer, or a stale cache? Should that be Reject rather than Indeterminate? | Treated as no matching record → `Indeterminate(StatusUnknown)`. |
| Q10 | Should the status digest also cover the signature bytes, or the issuer key id explicitly? | Covers type-separated signed bytes only (issuer_key_id is inside them). |
| Q11 | Multiple root records per org (key rotation) | Not modelled: one record per org_id. |
| Q12 | Labels for R07, R08, X07–X09, Q11, U01–U04 | Proposed. |

**r3.1 owner decisions (2026-10-15):**

| # | Decision |
| --- | --- |
| Q9 | Keep an unmatched exact StatusKey as `Indeterminate / X / StatusUnknown` in v0. Do not infer equivocation from a different digest under the same (org, type, id, version). A future authoritative, complete status service may expose a distinct, evidenced *conflict* result; that result must be defined separately before any Reject is assigned to it. Issuance must use a new version or id for changed content (§6). |
| Q10 | Keep the digest over the type-separated signed payload bytes; do not add signature bytes. The signed `issuer_key_id` and the verified chain determine the signer. Documented as a content-identity choice (§6). |
| Q11 | Root rotation and multiple root records per org are deferred beyond v0. The verifier must not silently accept any available key for an organization; a future design needs explicit record versions, validity and retirement rules. v0 keeps exactly one record per org_id, checked as in §6. |
| Q12 | R07, R08, X07–X09, Q11 and U01–U04 approved; all labels are now reviewed. |

**r3.1 change:** public pre-decoded decision API removed; decoded objects read-only (§7.5).
