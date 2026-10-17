# RQ-demo Phase 1 — local infrastructure connectivity smoke test (actual run)

**This is a connectivity test only: it proves n8n can reach a local model API. It is NOT an
authorization result and exercises none of the chain/session/freshness/mediation verifier.**
No real scan, fetch, DB write, or shell command was run; no target was contacted.

Run on 2026-10-18 (UTC). Host: Intel Core i7-6700 (4 cores / 8 threads), CPU-only
(`demo/compose.cpu.yml`, no GPU device mapping, `OLLAMA_VULKAN=0`).

## Environment

| Component | Value |
| --- | --- |
| Docker | 29.8.2 (build 7fc2dff) |
| Docker Compose | v5.6.0 |
| n8n image | `n8nio/n8n:2.43.7` @ `sha256:3db21366be1d3c77c1708963129c051948573019659e8873e0294be035ffc1b2` |
| n8n version | 2.43.7 |
| Ollama image | `ollama/ollama:latest` @ `sha256:265409e1d931028a8f7d5a32bcbafddd7bffbc6cc629d77efe9560adf692a5e7` |
| Ollama version | 0.40.6 |
| Model (connectivity) | `qwen3:0.6b` id `7df6b6e09427`, 522 MB, manifest sha256 `6f76d4346c34ba89df6e137fb661b4bb4daf322c1151b6ef0dfda981070a851f` |
| Model (experiments) | `qwen3:1.7b` id `8f68893c685c`, 1.4 GB, manifest sha256 `0f45bae8cd2fec097cf09b400b078cf42388a1f5702f4058d2d6d641a09db46d` |

Port exposure (verified with `docker compose ps`): n8n UI published on host loopback only
(`127.0.0.1:5678->5678/tcp`); Ollama port `11434` is on the private Compose network with **no
host port**.

## Call and response

The exact `/api/chat` POST (`stream:false`) was issued **from inside the n8n container** to
`http://ollama:11434/api/chat` — the same network path an n8n HTTP Request node uses (the n8n
UI builds the equivalent Manual Trigger → HTTP Request workflow):

Request body:
```json
{"model":"qwen3:0.6b","messages":[{"role":"user","content":"Reply with one short sentence about this synthetic demo."}],"stream":false}
```

Actual response:
- `model`: `qwen3:0.6b`
- `done`: `true`, `done_reason`: `stop`
- `message.content`: `"Synthetic demos simulate real-world scenarios to test new technologies effectively."`
- `eval_count`: 94 tokens
- Ollama `total_duration`: 3,547,322,747 ns (≈ 3.55 s)
- Wall-clock round-trip measured in the n8n container: **3626 ms**

This is a single CPU inference on a warm model; it is not a performance benchmark and says
nothing about throughput or real end-to-end deployment latency.

## Reproduce

```sh
docker compose -f demo/compose.cpu.yml up -d
docker compose -f demo/compose.cpu.yml ps
docker compose -f demo/compose.cpu.yml exec ollama ollama pull qwen3:0.6b
docker compose -f demo/compose.cpu.yml exec ollama ollama pull qwen3:1.7b
docker compose -f demo/compose.cpu.yml exec ollama ollama list
# connectivity (equivalent to an n8n Manual Trigger -> HTTP Request node):
docker compose -f demo/compose.cpu.yml exec -T n8n node -e \
  'fetch("http://ollama:11434/api/chat",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({model:"qwen3:0.6b",messages:[{role:"user",content:"Reply with one short sentence about this synthetic demo."}],stream:false})}).then(r=>r.json()).then(j=>console.log(j.message.content))'
docker compose -f demo/compose.cpu.yml down    # add -v to also drop the n8n/ollama data volumes
```

The provider controller and the authorization experiment workflow are implemented in later
phases; until then there are no model-derived authorization results.
