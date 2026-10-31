# Documentation map

AISIG is an **AI-assisted, synthetic research prototype**. The provider checks signed
authority and decides whether a proposed operation may append to a modeled
in-memory effect sink. It has not been independently audited and does not
enforce actions against real tools or prove control of a real asset.

**New reader:** [research questions](#research-questions) → [method and evidence](#method-and-evidence)
→ [limits](limitations.md). **Trying the demo:** [scripted local setup](automated-experiments.md)
→ [manual workbook](experiment-workbook.md). **Recorded result:**
[manual-02 visual report](../results/model_demo/manual_replication_20261022/visual_report.html).

## Research questions

The RQ number names a *question*, and each linked page describes the implemented
slice and its limits. A matching synthetic test case does not establish a
production security guarantee.

| Question | Read first | Implementation and evidence |
| --- | --- | --- |
| RQ1 — organization identity and trust anchor | [RQ1–RQ3 slice](rq123.md) | Manually vetted organization and pinned root are assumptions; a separate synthetic chain is exercised. [25 reviewed case outcomes](../results/rq123_cases.md). |
| RQ2 — asset binding | [RQ1–RQ3 slice](rq123.md) | Signed record and request bind a declared synthetic snapshot hash; real asset ownership/control is unproven. |
| RQ3 — independent delegation paths | [RQ1–RQ3 slice](rq123.md) | Two fixed paths to one junior are verified independently; no arbitrary path discovery or threshold policy. |
| RQ4 — grant scope and non-amplification | [chain specification](spec.md), [experiment design](experiment.md) | 94 chain cases and 15 scope lookups; [result index](../results/README.md). |
| RQ5 — tester/session binding | [session slice](session.md) | Separate proof-of-possession decision; 34 reviewed session cases. |
| RQ6 — action mediation | [enforcement slice](enforcement.md) | Provider-owned operation mapping with modeled effects only; 28 reviewed cases. |
| RQ7 — status freshness | [freshness slice](freshness.md) | Signed responder statements and in-memory rollback state; 34 reviewed cases, with restart and delivery limits. |
| RQ8 — privacy, latency, onboarding | [measurement plan](rq8.md) | 16 field/linkability, 6 modeled delay, 17 step/byte observations. Real deployment measurements remain open. |

## Method and evidence

1. [Specification](spec.md) and [threat model](threat-model.md): objects,
   boundaries, assumptions, and threats. The original chain specification is
   marked draft r3.1; later slices have their own documents.
2. [Experiment design](experiment.md): cases were labelled and reviewed
   separately from the code, then compared to its outputs.
3. [Results index](../results/README.md) and [prototype report](report.md):
   current reviewed counts and historical measurements. A case match means
   agreement with a stated expected outcome, within its fixture.
4. [Prepublication protocol](prepublication-protocol.md): 13 fixed controls
   and a 3 × 5 × 2 small-model matrix.
5. [Manual-02 evidence and discussion](../results/model_demo/manual_replication_20261022/README.md)
   and [visual report](../results/model_demo/manual_replication_20261022/visual_report.html):
   one recorded synthetic replication, separate from the Rust case harness.

## Reproduce the demo

- [Automated installation and experiments](automated-experiments.md) is the
  shortest route to a local run.
- [Manual experiment guide](manual-experiments.md) and [workbook](experiment-workbook.md)
  give a procedure and result checklist for each experiment.
- [Remote access on a trusted private host](remote-manual-access.md) is optional;
  the controller has no authentication.
- [Demo model and controller details](model-demo.md),
  [short walkthrough](demo-walkthrough.md), and
  [publication candidate preparation](manual-02-publication.md) cover recording
  and sharing sanitized results.

## Limits, history, and release

- [Limitations](limitations.md): the meaning of an Accept and unmeasured work.
- [Public release checklist](public-release.md) and
  [research release notes](release-notes-v0.1.0-research.md).
- [Website maintenance](site-publishing.md) explains the GitHub Pages build
  and its explicit publication scope.
- Older benchmark and report sections are **historical**; follow the current
  result index before quoting a number.

The [repository README](https://github.com/kyitharko/aisig-proto) has build
commands, license, and contact details. For a security finding use
[SECURITY.md](https://github.com/kyitharko/aisig-proto/blob/main/SECURITY.md).
