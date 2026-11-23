# AISIG research roadmap: five-stage guideline

**Status:** working guideline, 2026-11-23. This page orders future work; it is not a claim that every stage is implemented. The existing [research release](../README.md), [documentation map](README.md), and [limitations](limitations.md) remain the source of truth about current behavior.

## Rules that apply to every stage

1. State the trust assumption, attacker capability, decision boundary, and failure behavior before building an adapter.
2. Write expected cases and a negative control before implementation; keep owner-reviewed labels separate from new proposed labels. Preserve earlier reviewed outcomes unless a documented correction is approved.
3. Distinguish a cryptographic signature from authority, an in-memory effect from a real tool effect, and a local measurement from deployment evidence.
4. Let the provider derive operation class, validate the target, and control the effect path. Model-supplied claims and self-presented roots never create authority.
5. Publish reproducible fixtures, exact version/commit, failures and limitations. Do not claim conformance, independent security review, or production enforcement from passing synthetic cases.

## Stages and exit evidence

| Stage | Purpose | Current foundation | Completion gate |
| --- | --- | --- | --- |
| **1. Protocol specification draft** | Align the two existing decision lines, failure semantics, wire/crypto choices, threat model, and test-vector plan with existing standards. | [RQ4 spec](spec.md), [RQ1–RQ3 slice](rq123.md), [RQ5](session.md), [RQ6](enforcement.md), [RQ7](freshness.md), [threat model](threat-model.md). | A reviewable [profile draft](protocol-profile-draft.md) identifies exact implemented behavior versus proposals, maps standards, links tests, and records unresolved decisions. External feedback and any normative protocol version come later. |
| **2. Real enforcement boundary** | Build a minimal, isolated mock tool or MCP gateway with a provider-controlled execution path. | RQ6 privately appends to an in-memory sink; the n8n/Ollama controller never contacts a real target. | Demonstrate that every *mock* effect is mediated, with bypass/TOCTOU/side-effect tests and an explicit adapter threat model. This does not prove control over arbitrary external tools. |
| **3. Developer integration** | Expose a small, versioned SDK/API (Python first) and a reproducible demo. | Rust decision procedures and local scripts exist; there is no published Python AISIG SDK. | Cross-language canonicalization/signature vectors, typed outcomes, integration example and compatibility tests; no package or framework support claimed before it exists. |
| **4. Independent review** | Invite public scrutiny through issues, a draft RFC, threat-model review, and reproduction instructions. | Apache-2.0, contribution/security policy, CI, reviewed synthetic labels and evidence already exist. | Log questions and fixes with attributable versions, rerun negative controls, distinguish owner review from independent audit. |
| **5. Outreach and adoption** | Explain the use case with an accurate demo and comparisons to adjacent standards. | Public research release and documentation site exist. | Publish a short technical walkthrough and bounded findings; only request standards/community feedback after the profile's open questions and limitations are prominent. No certification or standards endorsement implied. |

**Dependency:** Stage 1 sets the contract for stages 2–3. Stage 2 supplies an actual mock enforcement integration, and stage 3 makes it reproducible for developers. Stages 4–5 can invite feedback early, but broad security or compatibility claims wait for evidence.

## Stage 1 review questions

- Should a future interoperable profile retain the experimental envelope/canonical JSON subset or adopt JWS/COSE with independently tested canonicalization?
- How will manual organization vetting, real asset control, key delivery and root rotation be specified and evidenced?
- What exact composition joins the RQ1–RQ3 `AssetAuthority` line to the RQ4/RQ5/RQ6/RQ7 line without changing accepted decisions silently?
- How will a real provider bind a session and authenticated workload to the execution path, handle unmodeled side effects, and persist revocation/epoch state?
- Which failure categories map into an external API, and how will a third party reproduce byte-exact test vectors?

Answers require their own reviewed design and tests. This roadmap does not decide them.
