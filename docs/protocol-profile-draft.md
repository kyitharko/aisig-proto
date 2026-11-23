# AISIG protocol profile — stage 1 working draft

**Status:** proposal for technical review, 2026-11-23. AISIG is an AI-assisted, synthetic research prototype, not an interoperable standard, a security certification, or production tool enforcement. This draft adds no code, wire format, expected case, or claim of conformance. For a contradiction, the existing per-slice specification and its reviewed cases take precedence; record a proposed correction explicitly before changing them.

**Purpose:** describe the smallest evidence-backed authorization profile visible in this repository, expose the seams between its separate slices, and identify the decisions needed before specifying an interoperable protocol. The five-stage [research roadmap](research-roadmap.md) is the project guideline. This page is **stage 1**.

## 1. Sources and scope

| Decision line | Implemented synthetic behavior | Source and evidence | Outside this line |
| --- | --- | --- | --- |
| Organization and asset authority (RQ1–RQ3) | One assumed provider-pinned organization root; a presented root → CTO → Senior → Junior path; a signed AssetRecord/AssetRequest and declared manifest digest; two paths checked independently. | [RQ1–RQ3](rq123.md), [AA cases](../tests/cases/rq123_cases.toml), [25-case result](../results/rq123_cases.md) | Real vetting, live asset control, arbitrary path discovery and composition with the main chain. |
| Grant authorization (RQ4) | Fixed C_A → D_U → G chain, signature/linkage, non-amplifying scope, trusted registry/binding fixtures, time and exact-object status. | [spec r3.1](spec.md), [reviewed cases](../tests/cases/reviewed_cases.toml), [experiment method](experiment.md) | Proof the presenter holds the tester key or an effect can run. |
| Session binding (RQ5) | Provider-issued challenge, tester key proof, one-time redemption and chain re-verification. | [session s1](session.md), [session cases](../tests/cases/session_cases.toml) | TLS/channel binding, per-action proof, real account entitlement. |
| Provider mediation (RQ6) | Versioned provider-owned tool table, target/class/effects checks; only modeled, private in-memory effect sink. | [enforcement e2](enforcement.md), [enforcement cases](../tests/cases/enforcement_cases.toml) | Real tool execution, external network effects and unmediated bypasses. |
| Signed status freshness (RQ7) | Separate responder-backed oracle with whole-clock-interval Active checks and in-memory sticky revocation/high-water mark. | [freshness f2](freshness.md), [freshness cases](../tests/cases/freshness_cases.toml) | Persistent high-water mark, bounded delivery, real status network. Default chain runs use an always-current fixture. |
| Evaluation (RQ8 and demo) | Fixture-specific observation/benchmark slices and a small-model controller demonstration. | [RQ8](rq8.md), [manual-02 evidence](../results/model_demo/manual_replication_20261022/README.md) | Real deployment privacy, end-to-end latency, operational cost and security statistics. |

The RQ1–RQ3 `AssetAuthority` decision **does not feed** the existing `ValidChain_P`, `SessionAuth` or RQ6 mediator. Its status source does not use the RQ7 signed-response freshness oracle. The two lines share ideas, not one composite authorization result. The [architecture overview](architecture-overview.md) illustrates them separately.

## 2. Trust and attacker model

**Trusted inputs in the modeled decisions:** P's own registry pin, binding fixture, authenticated server-side session reference, clock with nonnegative uncertainty, status fixture or configured responder public key, operation table and private effect sink. In the RQ1–RQ3 slice, manual organization vetting and safe root-key issuance/delivery are *assumed*, and organization authority over a declared synthetic asset is *assumed*. A key signed by a pinned root proves which key made a declaration; a manifest digest proves equality with supplied snapshot bytes. Neither proves ownership or present control of a real domain/database.

**Untrusted inputs:** model outputs and claimed class, presented bundle/root slot, envelope key hints, operation/target wire data, request-supplied path and manifest, and response bytes before validation. The verifier selects signing keys from the pinned registry and verified parent chain, not from an envelope hint or a request-supplied root. The provider controls the session reference and effect sink. Attacker goals include forged authority, scope widening, cross-path splicing, cross-tenant use, exact-status substitution, stale/replayed Active status, copied challenge proofs, and unmediated effect execution. See [the scoped threat table](threat-model.md), [RQ1–RQ3 path rules](rq123.md), and [limitations](limitations.md).

## 3. Existing synthetic decision contract

**3.1 Signed chain bytes.** The RQ4 profile uses `format = "aisig/v0"`; Ed25519 signatures cover `"aisig-v0" || 0x00 || TypeTag || 0x00 || payload_bytes`. The strict decoder checks a canonical JSON *subset*: printable ASCII strings, sorted object keys, no duplicates, null or floats, bounded integers, and sorted unique set arrays. It re-encodes the typed body and compares the bytes before relying on signed fields. The unsigned envelope's `sig.key_id` is a hint; `keyid(K)` is lowercase SHA-256 over the 32 raw public-key bytes. The exact grammar, base64url rules, field definitions, slot order and errors are in [spec ``2–3](spec.md). The RQ1–RQ3 slice uses the same domain-separated signing construction with its own type tags, record/request fields and manifest hash in [rq123.md](rq123.md). The JSON subset is **not yet JCS/RFC 8785 conformance-tested**. Do not relabel it “JCS compliant” or treat the experimental envelope as JWS/COSE.

**3.2 Delegation and assets.** The existing main line checks P's pinned root record, admin's explicit delegation right, issuer's issue right, signed parent references, matching organization/audience, effective assets `Included \ Excluded`, non-amplification of class/window/constraints, and exact-node versus subtree scope. Only the listed web path and database schema asset syntax is accepted; grant `test_scope` must be explicit. The RQ1–RQ3 line checks each complete path independently: parent/subject and exact signed-content references, registrar authorization, attenuation at each edge, a matching signed Junior request and one declared manifest. Another Senior's B record/request under A's path rejects (`AA25`); a valid B path is an independent positive control. Neither line establishes arbitrary-depth graph search or a two-signature threshold policy.

**3.3 Evidence, time and status.** Main-chain status is looked up by exact `StatusKey = (org_id, type, id, version, SHA-256(type-separated signed bytes))`. RQ4 time windows are half-open; the provider uses its clock reading `(now, ε)`, rejects negative ε as invalid evidence (Indeterminate), and accepts a window only if the whole uncertainty interval is inside it. The RQ7 oracle is an *opt-in synthetic slice*: one pinned responder per org signs object key, state, epoch, known/published/expiry times; freshness of Active requires the whole interval to be fresh and unexpired. Validated Revoked/Superseded is sticky within the in-memory store. Restart loses that state, so replay may be possible before expiry; publishing/delivery bounds are unproved. Full policy and precedence are in [freshness.md](freshness.md).

**3.4 Decisions and the effect boundary.** Chain `Accept` requires every positive stage (F → N → S → L → P → B → T → X). First evidenced Reject wins; absent/unavailable evidence records Indeterminate, which never becomes Accept; a later justified Reject may dominate it under [spec `7.2](spec.md). `SessionAccept` is a separate proof for P's exact session and grant at redemption; it is not tool permission. RQ6 `Allow` is another separate decision: the provider validates target and operation, derives TestClass from its own `aisig-tooltable/v0` row (ignoring model `claimed_class` for policy), rechecks session/chain and writes only a modeled effect if every check passes. `Deny`, `Indeterminate` or no proposed tool call means no modeled effect. This does not mediate a real tool.

## 4. Security properties and regression anchors

These are **test obligations and observed fixture results**, not proofs of formal soundness:

| Property to preserve | Named regression anchors | Boundary |
| --- | --- | --- |
| A self-presented root cannot replace P's pinned root; malformed optional root does not affect the chain decision. | RQ4 `V09/V10`; RQ1–RQ3 `AA04` | RQ1 vetting is still assumed. |
| Delegation cannot add targets/classes/time; a B record/request cannot ride an A path. | RQ4 `D/M` groups; `AA06/AA07/AA25` | Fixed paths and synthetic assets. |
| Re-signing different content cannot inherit an earlier object's Active status. | RQ4 `X07–X09` and status-key property test | No real status service. |
| Copied/replayed proof cannot authorize a different session or grant. | RQ5 `SS05–SS07` | In-memory one-time store; no channel binding. |
| Status stale/unknown/unavailable never supplies Accept; validated Revoked rejects. | RQ7 `FR02/FR04/FR07/FR08` | In-memory responder and HWM. |
| Only provider `Allow` appends to the modeled sink; excluded target is denied. | RQ6 `EE01/EE05`; 13 deterministic controller controls | No real target contacted. |

The current reviewed synthetic totals are reported in the [results index](../results/README.md), including RQ1–RQ3 25/25 separately. The small-model matrix demonstrates how proposed actions encounter a deterministic modeled boundary; its observations are not a population-level model safety rate.

## 5. Standards and solution alignment (comparison, no conformance claim)

| Existing work | Relationship to this profile | Still needed before an integration claim |
| --- | --- | --- |
| [MCP 2026-07-28 authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization) | MCP specifies transport authorization for HTTP MCP clients/servers and OAuth integration. AISIG's object chain and per-effect scope evaluation would be an additional provider/tool-handler policy. | Design an MCP adapter that binds an authenticated principal, actual `tools/call` arguments and execution to the decision; respect MCP auth requirements. No MCP adapter exists here. |
| [SPIFFE workload identity](https://spiffe.io/docs/latest/deploying/svids/) | SVIDs and trust bundles can authenticate *workloads* over a channel; they are distinct from AISIG's assumed organization root and signed grant for an asset. | Decide who may attest O and assets, and bind the workload identity to P's trusted context; no SPIFFE integration exists. |
| [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0-final.html) | Its subject/action/resource/context shape is a possible external PDP/PEP interface. AISIG has separate Accept/Reject/Indeterminate reasons; AuthZEN's evaluation decision is boolean. | Specify truthful mapping: only Accept could permit; Reject or Indeterminate must never execute, with Indeterminate/unavailable reported distinctly if the interface allows. No AuthZEN-conformant API exists here. |
| [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html), [RFC 8032 Ed25519](https://www.rfc-editor.org/rfc/rfc8032.html) | The implementation uses Ed25519 via a library and a constrained canonical JSON subset intended to resemble JCS. | Cross-implementation canonicalization/signature vectors and a deliberate JWS/COSE-versus-existing-envelope choice; no JCS conformance or standard wire format claim. |
| [NIST NCCoE agent identity project](https://pages.nist.gov/nccoe-ai-identity/summary-of-comments.html) and [OWASP secure MCP server guidance](https://genai.owasp.org/resource/a-practical-guide-for-secure-mcp-server-development/) | These are context for reusing identity standards and requiring a trusted execution boundary. They do not endorse this project. | Compare concrete use cases and attacker assumptions, submit a bounded draft for community review; the original NIST concept-paper comment deadline passed. |

## 6. Stage 1 test-vector plan

**Existing case tables are the current oracle, not portable byte-exact vectors.** A subsequent profile revision should provide a versioned fixture schema containing: signer public key or public test seed, exact canonical payload bytes (hex/base64url), expected domain-separated signed bytes, signature, expected `StatusKey` digest, trusted P-side context, and expected stage/reason. Include a positive case and one mutation per boundary (wrong signer/type, noncanonical JSON, scope amplification, different path, expired/uncertain clock, unknown/stale/revoked status, reused challenge, excluded target). For generated signatures, pin library/version and deterministic *public* test-only keys; never publish production secrets.

Run the same vector corpus against the Rust verifier and a genuinely independent decoder/SDK before stating cross-language interoperability. Document byte-level disagreements instead of editing labels to fit an implementation. Test vectors for composed AssetAuthority → session → mediation are **pending a composition design** and must not be generated as if the composition exists.

## 7. Decisions required for a normative revision

1. **Authority:** real organization/asset vetting, proof of live control, key custody, rotation and accountable registry updates. A signed manifest hash alone cannot settle this.
2. **Composition:** exactly how the two current decision lines join, which identities and status evidence they share, and conflict semantics for multiple paths. The implementation currently has no such join.
3. **Wire format:** freeze fields, canonicalization and signature grammar, and choose whether to retain the research envelope or profile an existing JWS/COSE format; obtain independent vectors.
4. **Status:** persistent sticky revocation/HWM, response distribution, freshness bound per deployment, caching/restart behavior, and the difference between “stop accepting” and “learn Revoked.”
5. **Real PEP:** bind authenticated session/workload, operation target and bounded side effects to a sole execution path; specify time-of-check/use, bypass and fail-closed behavior.
6. **External API:** versioned typed outcomes and a precise mapping to MCP/AuthZEN if used, without treating an error/Indeterminate as an Allow.

**Stage 1 exit criterion:** the owner and an external reviewer can identify each existing synthetic rule and each unimplemented decision from this draft, agree on the proposed changes as separate issues, and reproduce current labels. Only then promote selected clauses into a versioned normative protocol. Next implementation work follows [stage 2 of the roadmap](research-roadmap.md); this draft changes no existing behavior.
