# Small-model API simulation — local infrastructure and implementation plan

**Status: implemented and run (CPU-only).** The provider controller, an importable n8n workflow
and a deterministic excluded-target control workflow are in the repository, and the workflow has
been imported into n8n and executed against the real local `qwen3:1.7b` model; the recorded
results are in [`results/model_demo/`](../results/model_demo/) (`n8n_runs.json`,
`exec_*_n8n.json`, `model_runs.md`). The separate `eval` results concern deterministic synthetic
fixtures and must not be described as live-model results, and the live-model runs are a small
illustrative sample, not a benchmark or a determinism proof.

## Question and boundary

Can a small tool-using model propose actions while the provider's existing chain, session,
freshness and RQ6 mediator decide whether each proposed action may produce a **modeled** effect?
Measure the model's proposed actions separately from the provider's decisions. A model refusal
is not a mediator denial, and an allowed modeled effect is not a real tool invocation.

Use **n8n** to orchestrate the experiments. It sends prompts to a local model API (Ollama's
`/api/chat` tool-call interface is one option; <https://docs.ollama.com/api/chat>) and passes
the model's proposed call to the provider controller. Configure the model name and endpoint in
the local workflow, not from an external experiment request. Pin the exact model tag/digest,
n8n workflow revision and model runtime version in every result.
Do not bundle weights in this repository; check their separate license.
For the owner's i7-6700 (4 cores/8 threads, 30 GiB RAM, about 21 GiB available), start
with `qwen3:0.6b` as a connectivity check and `qwen3:1.7b` for the first recorded
experiments. The current Ollama library lists downloads of about 523 MB and 1.4 GB,
respectively (<https://ollama.com/library/qwen3>). A `qwen3:4b` comparison is optional
after observing CPU latency. Record the exact model digest; these sizes say nothing about
actual inference speed or total runtime memory. Keep the adapter model-agnostic.

## n8n workflow and local provider API

The workflow is: Manual Trigger or local Webhook → select a fixed synthetic scenario → call
Ollama with an action-proposal tool schema → parse the proposal or refusal → send it to the
provider controller → show/store the controller's decision and trace. Export the n8n workflow
JSON with the demo, without credentials or personal data. The n8n workflow **must not** include
nodes that directly fetch a proposed target, write a database, or execute a model-selected
command. n8n may invoke only the controller's bounded API for an action proposal.

The demo controller binds `127.0.0.1` by default. In [`demo/compose.cpu.yml`](../demo/compose.cpu.yml)
it runs as a Compose service that binds `0.0.0.0` **inside its container only, with no published
host port**, so it is reachable solely by other services on the private network as
`http://controller:8787` — never from the host or the outside. Only n8n's editor UI is published,
on host loopback. Do not bind the unauthenticated controller to a routable address, and do not
mistake container `localhost` for the host or another service. The controller has these routes:

| Route | Input / output |
| --- | --- |
| `GET /v1/scenarios` | IDs, descriptions, and synthetic fixture versions; no private fixture key bytes |
| `POST /v1/runs` | Fixed `scenario_id`, model proposal/refusal, prompt-variant ID and untrusted model metadata; return run ID and complete trace, or bounded error |
| `GET /v1/runs/{id}` | The recorded trace and summary for one run |

The client and the model may propose only `operation`, `target` and an audit-only
`claimed_class`. The model cannot supply a trusted bundle, evidence source, authenticated
`session_ref`, challenge, or authorization. The provider builds these from the selected
synthetic fixture. Obtain `SessionAuthorization` through real challenge issuance and redemption;
call the existing `Mediator::mediate` for each action. Feed it canonical target wire bytes, not a
pre-decoded `AssetRef`. Never provide a route that directly appends to `EffectSink`.

Only the fixed `aisig-tooltable/v0` operations and `.test`/synthetic DB assets are available.
There is no HTTP fetch of a proposed target, real scan, DB write or other external tool effect.
Reject malformed model tool calls and unsupported operations without side effects. Put limits
on tool-call count, prompt length and output size. Keep n8n, the model API and demo controller
local; a public interactive endpoint needs its own abuse, authentication and rate-limit design.
The n8n workflow is an experiment orchestrator, never the security decision point.

Use a lean n8n + Ollama + controller setup. A vector database is unnecessary for these
fixed scenarios. The owner's Radeon R7 350X reports 4 GiB VRAM, but does not appear on
Ollama's Linux ROCm support list (<https://docs.ollama.com/gpu>). Do not assume it will
accelerate the demo; use the CPU-only configuration in [`demo/compose.cpu.yml`](../demo/compose.cpu.yml).
This host also reports 182 GiB available disk and Docker/Compose installed. These facts
support a small local trial, but are not a measured model-performance result. Vulkan on
older GPUs is an optional separate compatibility experiment, not the baseline.

### Local infrastructure smoke test

From the repository root:

```sh
docker compose -f demo/compose.cpu.yml up -d
docker compose -f demo/compose.cpu.yml ps
docker compose -f demo/compose.cpu.yml exec ollama ollama pull qwen3:0.6b
docker compose -f demo/compose.cpu.yml exec ollama ollama pull qwen3:1.7b
docker compose -f demo/compose.cpu.yml exec ollama ollama list
```

Open <http://localhost:5678> and create the local n8n owner account. For a connectivity
check, make a temporary **Manual Trigger → HTTP Request** workflow. Configure a POST to
`http://ollama:11434/api/chat`, send JSON, and inspect the full JSON response:

```json
{"model":"qwen3:0.6b","messages":[{"role":"user","content":"Reply with one short sentence about this synthetic demo."}],"stream":false}
```

`ollama` is the Docker service name inside the Compose network. The model endpoint has
no published host port; only n8n's UI is exposed on host loopback. The CPU-only image
has no GPU device mapping, and `OLLAMA_VULKAN=0` disables Vulkan. This check only proves
that n8n can reach a local model API; it does **not** test the authorization verifier.
If Docker cannot pull the images or model on a restricted network, transfer/pull them via
the owner's approved download path and record their image/model digests.

For the recorded experiment, build the controller binary (`cargo build --release --bin
demo_controller`), bring the stack up, import the exported workflow
([`demo/n8n-workflow.json`](../demo/n8n-workflow.json)) with `n8n import:workflow`, and run it
with `n8n execute --id=<id>` (use a one-off `docker compose run --rm --no-deps n8n execute …`
container to avoid the port-5679 task-broker clash with the live n8n server), or run it from the
editor UI. The deterministic excluded-target control is
[`demo/n8n-control-excluded.json`](../demo/n8n-control-excluded.json). Recorded results and the
exact commands are in [`results/model_demo/model_runs.md`](../results/model_demo/model_runs.md).
Stop the local containers with `docker compose -f demo/compose.cpu.yml down` (without `-v` if you
want to keep the local n8n/Ollama data volumes).

Hardware facts were captured with:

```sh
lscpu | grep -E 'Model name|CPU\(s\)|Thread\(s\)|Core\(s\)'
free -h
lspci -nnk | grep -EA4 'VGA|3D|Display'
for f in /sys/class/drm/card*/device/mem_info_vram_total; do
  if [ -r "$f" ]; then printf '%s: ' "$f"; cat "$f"; fi
done
df -h .
docker --version
docker compose version
```

For AMD acceleration, check the exact GPU against the model runtime's current support matrix;
`amdgpu` in `lsmod` alone is insufficient (<https://docs.ollama.com/gpu>).

## Experiments and measurements

Start with the reviewed EE01–EE28 enforcement fixtures as policy controls. Include normal
allowed calls, excluded/out-of-scope targets, wrong class and false `claimed_class`, unknown
operation, unbounded footprint, expired session, revoked grant, unavailable evidence and a
noncanonical target. Add prompt variants that ask the model to choose a tool naturally and that
try to override the provider's stated limits. The controller must use the **same** policy path
for every variant. Where the model chooses a different action, report its actual action and
decision rather than relabeling it as the control's expected action.

For each run, record: scenario ID and fixture revision, n8n workflow revision, model tag/digest,
runtime version, prompt-variant ID and prompt hash, supported sampling settings/seed, raw
proposed tool name and arguments, parse status, chain/session/mediation decisions with
stage/reason, sink length before and after, and separate n8n orchestration, model and
verification elapsed times. Do not log private key material or claim that a sampled model
output is deterministic unless the runtime demonstrates it.

| Metric | Definition |
| --- | --- |
| Model tool-call rate | Calls proposed / model trials, with refusal and malformed-output counts separately |
| Mediator decision distribution | Allow / Deny / Indeterminate over actual proposed calls, grouped by scenario |
| Forbidden modeled effects | Sink increments after Deny or Indeterminate; expected zero |
| Allowed modeled effects | Sink increments after Allow; expected one per accepted call |
| Policy-control agreement | Exact decision/stage/reason for fixed control calls against existing reviewed labels |
| Timing | Model API duration and verifier/mediator duration separately; no real end-to-end deployment claim |

Write per-run JSON plus a generated Markdown summary under `results/model_demo/` after a real
model run. Include failures, exported workflow JSON and exact run commands. Test the controller
with deterministic fake model proposals and bad outputs; separately run at least two prompt
variants through **n8n and an actual local small model** and report the observed outputs, even
if it declines or produces no tool call. Do not write expected labels to match the model's
behavior. Do not change any of the
existing 94/15/34/28/34/16/6/17 reviewed outcomes.
