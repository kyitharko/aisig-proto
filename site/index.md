---
title: AISIG research guide
---

# Provider-verified authorization for AI-agent tool proposals

AISIG is a **synthetic research prototype**. A model proposes an action and a
provider-side controller checks the signed authorization chain, session,
scope, and status evidence before recording a modeled in-memory effect.
The demo does not call a real tool or contact a target.

[Read the documentation map](docs/) ·
[Explore the recorded visual report](results/model_demo/manual_replication_20261022/visual_report.html) ·
[View the GitHub repository](https://github.com/kyitharko/aisig-proto)

## Choose a path

| I want to… | Start here |
| --- | --- |
| Understand the research questions | [RQ1–RQ8 map](docs/) and [specification](docs/spec.md) |
| Assess the security claims | [Threat model](docs/threat-model.md) and [limitations](docs/limitations.md) |
| Check the evidence | [Results index](results/README.md), [prototype report](docs/report.md), and [manual-02 discussion](results/model_demo/manual_replication_20261022/README.md) |
| Run the demonstration | [Automated local setup](docs/automated-experiments.md), [manual procedure](docs/manual-experiments.md), and [experiment workbook](docs/experiment-workbook.md) |
| Inspect the public release | [Release notes](docs/release-notes-v0.1.0-research.md) and [repository](https://github.com/kyitharko/aisig-proto) |

## What the published observations say

The separate Rust case harness matches **94 chain, 15 lookup, 34 session,
28 enforcement, 34 freshness, and 16/6/17 RQ8** reviewed expected outcomes.
The RQ1–RQ3 slice matches **25 reviewed cases**. These are synthetic
case agreements, not field validation.

In the recorded manual-02 small-model replication, **13/13 fixed controls**
matched and **30/30 model cells** completed: 4 Allow, 13 Deny,
8 Indeterminate, and 5 no mediation. An Allow appended one modeled
effect; every other category appended zero. The
[visual report](results/model_demo/manual_replication_20261022/visual_report.html)
discusses those observations and their limits.

**Research boundary:** organization vetting, real asset control, live tool
enforcement, and real deployment latency/cost are not established here.
This AI-assisted code has not received an independent security audit.
Read the [limitations](docs/limitations.md) before adapting it.
