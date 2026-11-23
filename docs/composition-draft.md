# Composition of AISIG decisions — stage 1 design draft

**Status:** proposal for review, 2026-11-23; **not implemented**. This document answers the first open question in the [stage 1 protocol profile](protocol-profile-draft.md). It changes no case label, expected outcome, signed bytes, API or effect path. The other stage 1 questions—wire format, trust bootstrap and byte-exact test vectors—remain separate work under the [five-stage guideline](research-roadmap.md).

**Review question:** How could P combine the existing RQ1–RQ3 `AssetAuthority` decision with the RQ4 `ValidChain_P`, RQ5 `SessionAuth`, RQ6 provider mediator and optional RQ7 freshness, without granting authority that no signer intended?

## 1. Existing contracts (source of truth)

| Existing component | What it proves in its synthetic fixture | What it does not provide |
| --- | --- | --- |
| [`AuthorityVerifier::verify`](../src/asset_authority.rs), [RQ1–RQ3 design](rq123.md) | For one *presented*, exactly three-edge root → CTO → Senior → Junior path, a signed AssetRecord and signed Junior AssetRequest match one declared manifest, asset and requested TestClass. Returns `Outcome::{Accept, Reject, Indeterminate}`. | It returns no immutable validated authority context to a caller; no real asset control, session, action mediation or RQ7 freshness. The in-memory status lookup covers three role edges and the record, not a separately revocable AssetRequest. |
| [`ChainVerifier::verify`](../src/verifier.rs), [RQ4 spec](spec.md) | A separately signed admin → issuer → tester G chain fits P's trusted binding fixture and other RQ4 rules. | It does not incorporate the AssetRecord or replace the trusted binding fixture with proof of real asset ownership. |
| [`SessionService`](../src/session.rs), [RQ5 design](session.md) | The holder of G's tester key signed a provider challenge for P's server-held session and the exact G, with one-time redemption and chain re-verification. | A signed AssetRequest is not a session proof; a SessionAccept alone permits no tool effect or real account entitlement. |
| [`Mediator::mediate`](../src/enforcement.rs), [RQ6 design](enforcement.md) | It validates an operation/target, looks up server-held session authorization, re-verifies G, applies the provider-owned operation table, and appends a *modeled* effect on Allow. | It has no AssetAuthority gate. It **writes the effect before returning Allow**; calling it first and then checking AssetAuthority would be too late. |
| [RQ7 freshness oracle](freshness.md) | When explicitly wired, signed responses for exact StatusKeys and a shared in-memory high-water mark govern liveness of RQ4 objects. | Default chain/session/mediator cases use an always-current fixture; AssetAuthority does not use the RQ7 oracle, and HWM state resets on restart. |

The same Rust `RootRegistry` and `StatusSource` traits are used in both lines, but shared interfaces by themselves do not imply one snapshot, one key provenance, or composition. No code path currently performs the proposed conjunction below.

## 2. Proposed conservative composition rule

**A proposed future decision, not a description of current behavior:**

`CompositeAllow(P, session, G, AA, operation, target)` requires all of these to hold **before** the sole effect-producing step:

1. P has an authenticated **server-held** session reference; no model-supplied session ID or root can name it. P's mapping from account/workload to that session is an additional deployment assumption to specify.
2. The unmodified raw RQ4 bundle is accepted by `ValidChain_P`. RQ4's trusted `Bind_P` fixture remains an *additional* gate in this initial proposal. Do not silently replace it with the synthetic manifest hash.
3. A complete raw RQ1–RQ3 `AuthorityBundle` is accepted for **one** declared asset/class/path. Neither a result for Asset A nor a Junior key alone licenses Asset B. The signed request is checked on its matching path, not a second path assembled from unrelated edges.
4. The two accepted contexts have the same P-pinned organization root **identity**, `org_id` and provider `audience`. G's signed `tester_key` matches the validated Junior `subject_key`; the signed Junior `subject_user_id` and P's authenticated account mapping are bound by a specified provider policy, not by name similarity.
5. An explicit **cross-line link** binds this exact G to the validated AssetRecord and Junior leaf. The Junior signs its AssetRequest later, with exact references to that record and leaf. The selected link construction must be approved before any composite Accept; coincidental equality of asset names, key IDs or a copied manifest is insufficient.
6. P derives the operation's class and footprint from its own versioned tool table. For a **first narrow profile**, require a single node-effect operation, the canonical proposed target exactly equal to the signed `AssetRequest.asset`/`AssetRecord.asset`, and the table's class exactly equal to `AssetRequest.class`. The target must also be in G's effective allowed set, the class in G's `test_scope`, and the effect bounded. Subtree and multi-asset effects require separate scope-intersection semantics and tests.
7. Both lines' relevant root/time/status checks and the G session authorization remain valid at the action decision instant. Missing or uncertain evidence blocks the effect. The status policy for the new AssetAuthority objects must be designed and tested before claiming RQ7 coverage for them.
8. P's own service policy may still refuse. Only a final composite Allow inside the **sole provider-owned perform path** may produce one modeled effect.

This is a **conjunctive** gate: an Accept from either line alone never becomes CompositeAllow. For the first experiment, keep the existing RQ4 binding fixture and the RQ1–RQ3 declared-snapshot assumption visible. There is no new claim of legal asset ownership.

### Result combination for the proposed gate

| Observed inputs before effect | Proposed composite outcome | Effect |
| --- | --- | --- |
| All required decisions Accept, the exact link/subject/target/class checks pass, and provider policy permits | Allow | One modeled effect through the sole perform path |
| Any definitely evidenced Reject/Deny or a definitive cross-line mismatch | Deny with the originating reason preserved | None |
| No definite Deny, but registry, clock, status, session or link evidence is unavailable/uncertain | Indeterminate with the originating reason preserved | None |
| Model emits no valid proposed operation | No mediation | None |

As in [spec `7.1–7.2](spec.md), a justified Reject can dominate an Indeterminate; a missing prerequisite can never justify Allow. The exact precedence and error spelling **across** the two decision lines need a new reviewed case table; this table is a design invariant, not an implemented outcome list.

## 3. How to bind the two lines (design choice)

| Candidate | Mechanism | Advantage | Cost / unresolved risk |
| --- | --- | --- | --- |
| **A — signed G reference (recommended for review)** | In a **future version** of G, its issuer signs an exact reference to the AssetRecord (`org_id, type, id, version, signed-content digest`) and an exact reference to the Junior leaf; P verifies both chains and matches the references. The later Junior-signed AssetRequest must itself name the same record and leaf. | The G issuer's intent to use this AssetAuthority is signed and auditably linked to the record. Cross-path or same-name substitution cannot silently select another record. | The current `aisig/v0` parser rejects unknown fields. This requires a new version, signer workflow, owner-approved semantics, and byte-exact vectors. A signed link does **not** make the AssetRecord fresh or establish real asset control. |
| **B — P-held explicit link** | P creates a protected mapping between exact G and AssetRecord/leaf identities only after independent verification and an explicit authorization step. | Could prototype the decision join without changing existing signed G bytes. | It makes P's mapping and approval process a new trust input; a mutable mapping or stale status can substitute a record. It cannot be presented as owner-signed intent unless that intent is separately evidenced. |

**Recommendation:** specify A first for an interoperable *proposal*, while using B only as a clearly marked synthetic bridge if an integration experiment needs to run before the versioned wire decision. Neither candidate is selected as a normative format here. An unlinked pair of independent Accept decisions is not an acceptable composite positive case.

## 4. Effect-boundary and time hazards

The current [mediator](enforcement.md) owns the only in-memory sink append. The composition check has to become part of its pre-perform decision path (or a new sole mediator replacing it), **not** a wrapper that calls `mediate()` and inspects the returned decision. The future API would need an unforgeable, read-only verified authority context constructed only from raw bytes and internally verified fields; today `AuthorityVerifier::verify` returns only `Outcome`. No caller-provided decoded body may supply those fields.

A single frozen clock reading across both verifiers and mediation is a design target; current `Mediator` freezes its own chain snapshot but `AuthorityVerifier` reads its clock separately. A common clock instant alone does not make *multiple status answers* an atomic snapshot. Status could change between the independent checks and the append. Before claiming a revocation/effect race guarantee, specify a decision linearization or authoritative status snapshot, revalidation strategy, persistence across restarts, and the behavior when a revocation arrives during a pending action. Avoid describing RQ7's in-memory per-key atomic HWM as a global transaction.

## 5. Relation to existing standards

- [MCP authorization (2026-07-28)](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) can authenticate an HTTP client to a resource server. A future MCP `tools/call` handler could enforce the composite gate *inside* the only tool execution path, using its authenticated principal and validated arguments. MCP transport authorization alone does not verify AISIG asset ownership or provide the proposed signed link. No MCP adapter exists.
- [AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0-final.html) separates subject, action, resource and context for a PDP/PEP decision. A future adapter could carry both exact authorization references as P-validated context and permit only CompositeAllow; AuthZEN's `decision` is boolean, so Indeterminate must block execution and its evidence-failure reason needs an explicitly designed representation. No AuthZEN API exists here.
- [OAuth Rich Authorization Requests, RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html) illustrates resource/action-specific authorization details and narrowing; it does not define AISIG's signed delegation or asset proof. An OAuth integration would need its own authorization-details type and semantics rather than reusing a string scope.
- [OAuth Token Exchange, RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html) distinguishes subject and acting party in delegated token contexts. This informs a future account/workload/Junior/tester mapping, but an exchanged token is not automatically a valid AISIG path or asset record.

These are **alignment points**, not compliance, endorsement, or a claim that standards mandate the AISIG composition.

## 6. Proposed negative controls before code

Write independent expected labels and a real runner **before** changing `Mediator` or adding G fields. Keep all existing reviewed AA/RQ4/RQ5/RQ6/RQ7 labels unchanged. At minimum:

| Case to pre-register | Necessary observation |
| --- | --- |
| A's path + genuine B record/request/manifest, where B succeeds on its own path | Deny before effect; positive B-path control still Accepts in its own decision. |
| G and AssetAuthority each accept independently but cross-line link absent or points to another exact record/digest | No composite Allow; definitive mismatch Deny, unavailable link evidence Indeterminate. |
| Same asset name but different org, audience, pinned root or tester/Junior key | Deny before effect. |
| AssetRequest class differs from provider-derived operation class; target differs from signed asset; G excludes the target | Deny before effect even if each standalone decision Accepted its own fixture. |
| AssetAuthority status Unknown/Revoked while RQ4 is Accept; RQ4 G Revoked while AssetAuthority is Accept | Indeterminate or Deny as justified; no effect, including mixed Reject/Indeterminate cases. |
| Clock or status changes between eligibility and perform; two concurrent requests | Verify the chosen linearization rule and exactly-once effect behavior; do not infer this from the current single-key HWM test. |
| Existing `mediate()` Allow in isolation with a missing or failed AssetAuthority | The new composite entry point produces **no** effect; demonstrate there is no alternate route to the same sink. |

No case IDs or expected strings are assigned here: they belong in a label-first design round after the cross-line link and scope policy have been reviewed.

## 7. Decisions for owner review

1. **Link:** prefer a future signed G exact authority reference (A), or a P-held, explicitly approved bridge (B) for the first synthetic composition experiment?
2. **Subject:** should `K_T == Junior.subject_key` be mandatory for the first composition, with P separately binding the authenticated account to the same subject?
3. **Asset/operation:** start with exact-target node effects only, then separately design subtree/secondary effects and multiple assets?
4. **Status:** keep the additive RQ4 `Bind_P` fixture and mark RQ7-for-AssetAuthority as pending until a reviewed shared status design exists?
5. **Race:** what should be the accepted decision instant/linearization contract if revocation arrives during the combined check?

**Next design step after this review:** choose the link/subject rules, write a versioned composition contract and proposed case labels, then make a failing reproduction **before** implementation. The second major stage 1 topic—wire format—is addressed separately and must not be silently decided by this draft.
