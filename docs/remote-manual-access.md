# Access the synthetic experiment from a laptop

> `100.x.y.z` is a placeholder for your Docker host's own private IP (e.g. a
> Tailscale/VPN or LAN address); substitute it throughout, or set it once in
> `AISIG_DEMO_ACCESS_IP`. Do not commit your real address.

The normal [`compose.cpu.yml`](../demo/compose.cpu.yml) keeps n8n on host
loopback and does not publish the controller. The optional
[`compose.access.yml`](../demo/compose.access.yml) also publishes n8n's editor
and the synthetic controller API on **one selected Docker-host IP**. It does
not publish Ollama. The base `127.0.0.1:5678` mapping remains available on
the host. This is for a trusted private link, not a public internet service.

## Start on the Docker host

Run from the repository root on the computer that runs Docker:

```sh
# This must be assigned to this Docker host, not to the laptop.
ip -4 addr show | grep -F 'inet 100.x.y.z/'
cargo build --release --bin demo_controller
export AISIG_DEMO_ACCESS_IP=100.x.y.z
docker compose -f demo/compose.cpu.yml -f demo/compose.access.yml config
docker compose -f demo/compose.cpu.yml -f demo/compose.access.yml up -d
docker compose -f demo/compose.cpu.yml -f demo/compose.access.yml ps
docker compose -f demo/compose.cpu.yml -f demo/compose.access.yml exec ollama ollama pull qwen3:1.7b
docker compose -f demo/compose.cpu.yml -f demo/compose.access.yml port n8n 5678
docker compose -f demo/compose.cpu.yml -f demo/compose.access.yml port controller 8787
```

Check `config` before starting: n8n should have host IPs `127.0.0.1` and
`100.x.y.z` for port 5678; controller should have **only**
`100.x.y.z` for port 8787; Ollama should have no published ports. Docker
will fail to bind if the given IP is not assigned to the host or if a port is
already in use. If `grep` finds nothing, inspect `ip -4 addr show` and use
the actual host address. Both the laptop and host must have a route through
the same trusted private network; the host firewall and network policy must
allow TCP 5678 and 8787 there.

## Open from the laptop

| Address | Purpose |
| --- | --- |
| <http://100.x.y.z:5678> | n8n editor; sign in with its existing owner account |
| <http://100.x.y.z:8787/v1/scenarios> | Read the controller's synthetic scenario list |

From the laptop terminal, `curl -fsS
http://100.x.y.z:8787/v1/scenarios` is a simple reachability check.
Open the imported workflow in n8n and use **Execute workflow** to run manual
variants. The `http://controller:8787` and `http://ollama:11434` URLs inside
workflow nodes remain service-to-service URLs; do not replace them with the
host IP. Follow the [manual experiment guide](manual-experiments.md) and
fill a copy of the [workbook](experiment-workbook.md). The
controller performs only modeled in-memory effects.

After the complete 13-control + 30-run replication, the visual report can be
viewed in the laptop browser too. On the host, point a separate terminal at
**this session's** report directory (change `manual-01` for your session):

```sh
python3 -m http.server 8788 --bind 100.x.y.z \
  --directory local-experiments/manual-01/full-matrix
```

Then open <http://100.x.y.z:8788/visual_report.html>. This optional
server exposes **all files** in that session directory to devices permitted on
that private interface; only use it for sanitized results, and stop it with
Ctrl+C after viewing. It is separate from Docker Compose; allow TCP 8788 on
the private link only if you use this option.

The controller API has **no authentication**: another device permitted to
reach `100.x.y.z:8787` can read synthetic traces and create runs. n8n's
login remains enabled, but this override sets `N8N_SECURE_COOKIE=false` for
HTTP access by IP. n8n otherwise requires HTTPS for its secure cookie. Use
this only over a trusted encrypted private link; do not forward either port
to the public internet. For access over a wider network, use HTTPS and a
proper authentication boundary instead. If `100.x.y.z` is a Tailscale
address, make sure both devices are on the authorized tailnet.

## Return to local-only access

From the host, keeping the existing n8n/Ollama data volumes:

```sh
docker compose -f demo/compose.cpu.yml up -d
docker compose -f demo/compose.cpu.yml ps
```

Compose will recreate the affected services without the private-IP port
mappings; it also restores n8n's default secure-cookie setting. To stop the
stack entirely, run `docker compose -f demo/compose.cpu.yml down` (do not add
`-v` unless you intend to delete the volumes).
