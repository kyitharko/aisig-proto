#!/usr/bin/env python3
"""Local-only setup and experiment wrapper for the synthetic AISIG demo.

This script does not install system packages, create a remote, contact a target,
or modify committed results. See docs/automated-experiments.md.
"""

import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
LOCAL = ROOT / "local-experiments"
BASE = "demo/compose.cpu.yml"
ACCESS = "demo/compose.access.yml"
MODEL = "qwen3:1.7b"
TRUSTED_NETS = tuple(
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")
)


class LabError(Exception):
    """A setup problem that can be reported without a traceback."""


def session_dir(name):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,49}", name):
        raise LabError("Session must be 1–50 letters/digits/-/_ and start with a letter or digit")
    return LOCAL / name


def trusted_address(value):
    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        raise LabError("--access-ip must be a single IPv4 address") from exc
    if addr.version != 4 or not any(addr in n for n in TRUSTED_NETS):
        raise LabError("--access-ip must be a host address in RFC1918 or 100.64.0.0/10")
    if str(addr) != value:
        raise LabError("--access-ip must use canonical IPv4 form")
    return value


def run(command, *, env=None, capture=False, check=True):
    try:
        return subprocess.run(command, cwd=ROOT, env=env, text=True, check=check,
                              capture_output=capture)
    except FileNotFoundError as exc:
        raise LabError(f"Missing executable: {command[0]}; see host prerequisites") from exc


def assigned_ipv4():
    result = run(["ip", "-j", "-4", "addr", "show"], capture=True)
    try:
        return {entry["local"] for interface in json.loads(result.stdout)
                for entry in interface.get("addr_info", []) if entry.get("family") == "inet"}
    except (KeyError, ValueError, TypeError) as exc:
        raise LabError("Could not read local IPv4 interfaces from 'ip -j -4 addr show'") from exc


def configure(args):
    directory = session_dir(args.session)
    if directory.exists():
        raise LabError(f"Session already exists: {directory}; choose a new session name")
    access_ip = trusted_address(args.access_ip) if args.access_ip else None
    if access_ip and access_ip not in assigned_ipv4():
        raise LabError("--access-ip is not assigned to this Docker host")
    directory.mkdir(parents=True, mode=0o700)
    path = directory / "config.json"
    config = {"version": 1, "session": args.session, "access_ip": access_ip,
              "model": MODEL, "mode": "private-ip" if access_ip else "local-only"}
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as file:
        json.dump(config, file, indent=2)
        file.write("\n")
    print(f"Configured {directory.relative_to(ROOT)} ({config['mode']}); no service started")
    if access_ip:
        print("The controller has no authentication: use this only on one trusted private host/link")


def load_config(name):
    directory = session_dir(name)
    try:
        config = json.loads((directory / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LabError(f"No valid configuration for '{name}'. Run 'configure' first") from exc
    if config.get("version") != 1 or config.get("session") != name or config.get("model") != MODEL:
        raise LabError("Session config does not match the supported demo version")
    ip = config.get("access_ip")
    if ip is not None:
        trusted_address(ip)
        if config.get("mode") != "private-ip":
            raise LabError("Inconsistent private-IP session config")
    elif config.get("mode") != "local-only":
        raise LabError("Inconsistent local-only session config")
    return config, directory


def compose(config):
    args = ["docker", "compose", "-f", BASE]
    if config["access_ip"]:
        args += ["-f", ACCESS]
    env = os.environ.copy()
    if config["access_ip"]:
        env["AISIG_DEMO_ACCESS_IP"] = config["access_ip"]
    else:
        env.pop("AISIG_DEMO_ACCESS_IP", None)
    return args, env


def doctor(_args):
    commands = (["python3", "--version"], ["cargo", "--version"],
                ["docker", "--version"], ["docker", "compose", "version"],
                ["docker", "info", "--format", "{{.ServerVersion}}"])
    ok = True
    for command in commands:
        try:
            result = run(command, capture=True, check=False)
            value = (result.stdout or result.stderr).strip().splitlines()
            print(f"{'OK' if result.returncode == 0 else 'MISSING'} {' '.join(command[:3])}: "
                  f"{value[0] if value else 'no output'}")
            ok &= result.returncode == 0
        except LabError as exc:
            ok = False
            print(f"MISSING {' '.join(command[:3])}: {exc}")
    if not ok:
        print("Install/enable prerequisites using the official links in docs/automated-experiments.md")
    return 0 if ok else 1


def controller_url(config):
    if config["access_ip"]:
        return f"http://{config['access_ip']}:8787"
    if platform.system() != "Linux":
        raise LabError("Local-only host access to the container IP is Linux-specific")
    command, env = compose(config)
    cid = run(command + ["ps", "-q", "controller"], env=env, capture=True).stdout.strip()
    if not cid:
        raise LabError("Controller is not running; run 'setup' first")
    info = json.loads(run(["docker", "inspect", cid], capture=True).stdout)[0]
    addresses = [net.get("IPAddress") for net in info["NetworkSettings"]["Networks"].values()]
    addresses = [a for a in addresses if a]
    if len(addresses) != 1:
        raise LabError("Expected one controller container IPv4; inspect Docker networking manually")
    return f"http://{addresses[0]}:8787"


def health(url, attempts=1):
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(url + "/v1/scenarios", timeout=3) as response:
                data = json.load(response)
            if isinstance(data.get("scenarios"), list) and data["scenarios"]:
                return
        except (OSError, ValueError, TypeError):
            pass
        if attempt + 1 < attempts:
            time.sleep(1)
    raise LabError("Provider health check failed; verify the Compose stack and selected interface")


def setup(args):
    config, _ = load_config(args.session)
    if doctor(args):
        raise LabError("Host prerequisites are not available")
    if config["access_ip"] and config["access_ip"] not in assigned_ipv4():
        raise LabError("Configured private IP is no longer assigned to this host")
    cmd, env = compose(config)
    run(["cargo", "build", "--release", "--bin", "demo_controller"])
    run(cmd + ["config", "--quiet"], env=env)
    run(cmd + ["up", "-d", "--force-recreate"], env=env)
    if args.pull_model:
        run(cmd + ["exec", "-T", "ollama", "ollama", "pull", MODEL], env=env)
    url = controller_url(config)
    health(url, attempts=12)
    print(f"Provider ready at {url}/v1/scenarios; n8n: "
          f"http://{config['access_ip'] or '127.0.0.1'}:5678")
    if not args.pull_model:
        print("For full-model runs, pull qwen3:1.7b with 'setup --pull-model'")


def model_available(config):
    cmd, env = compose(config)
    result = run(cmd + ["exec", "-T", "ollama", "ollama", "list"], env=env, capture=True)
    return any(line.split() and line.split()[0] == MODEL for line in result.stdout.splitlines())


def utc_now():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def write_json(path, data):
    with path.open("x", encoding="utf-8") as file:
        json.dump(data, file, indent=2)
        file.write("\n")


def render(directory):
    for name in ("controls_results.json", "model_matrix.json"):
        if not (directory / name).is_file():
            raise LabError(f"Cannot build the visual report: {name} is missing")
    run([sys.executable, "scripts/build_model_visual_report.py", "--matrix",
         str(directory / "model_matrix.json"), "--controls",
         str(directory / "controls_results.json"), "--output",
         str(directory / "visual_report.html")])
    print(f"Report: {directory / 'visual_report.html'}")


def experiment(args):
    config, directory = load_config(args.session)
    url = controller_url(config)
    health(url)
    if args.mode == "full" and not model_available(config):
        raise LabError(f"{MODEL} is not installed; run 'setup --pull-model' first")
    output = directory / f"{args.mode}-{utc_now()}-{uuid.uuid4().hex[:8]}"
    output.mkdir(mode=0o700)
    env = os.environ.copy()
    env.update(AISIG_CONTROLLER_URL=url, AISIG_COMPOSE=BASE, AISIG_OUTPUT_DIR=str(output))
    if args.mode == "controls":
        env["AISIG_SKIP_MODEL"] = "1"
    else:
        env.pop("AISIG_SKIP_MODEL", None)
    started = dt.datetime.now(dt.timezone.utc).isoformat()
    process = run([sys.executable, "scripts/run_prepublication_experiment.py"],
                  env=env, check=False)
    code = process.returncode
    manifest = {"session": args.session, "mode": args.mode, "started_utc": started,
                "ended_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "collector_returncode": code, "output_directory": str(output.relative_to(ROOT))}
    revision = run(["git", "rev-parse", "HEAD"], capture=True, check=False)
    manifest["git_commit"] = revision.stdout.strip() if revision.returncode == 0 else None
    write_json(output / "run_manifest.json", manifest)
    if code:
        print(f"Collector failed (exit {code}); incomplete evidence kept at {output}", file=sys.stderr)
        return code
    if args.mode == "full":
        render(output)  # The report generator separately rejects incomplete or bad result pairs.
    print(f"Completed {args.mode}; evidence: {output}")
    return 0


def report(args):
    _, directory = load_config(args.session)
    result = Path(args.result_dir).resolve()
    if not result.is_relative_to(directory.resolve()) or result == directory.resolve():
        raise LabError("--result-dir must be an experiment folder inside this ignored session")
    manifest = result / "run_manifest.json"
    if not manifest.is_file() or json.loads(manifest.read_text()).get("collector_returncode") != 0:
        raise LabError("Only a completed, gated experiment can be rendered")
    render(result)


def stop(args):
    config, _ = load_config(args.session)
    cmd, env = compose(config)
    run(cmd + ["down"], env=env)  # Deliberately no -v: preserve n8n and Ollama data.
    print("Stack stopped; volumes and experiment outputs retained")


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("doctor", help="check host prerequisites; never install system packages")
    c = sub.add_parser("configure", help="create an ignored, immutable session config")
    c.add_argument("--session", required=True)
    c.add_argument("--access-ip", help="optional private IPv4 assigned to this Docker host")
    s = sub.add_parser("setup", help="build the controller and start the local Compose stack")
    s.add_argument("--session", required=True)
    s.add_argument("--pull-model", action="store_true", help=f"also download {MODEL}")
    e = sub.add_parser("experiment", help="run fixed controls or the full 30-cell model matrix")
    e.add_argument("--session", required=True)
    e.add_argument("--mode", choices=("controls", "full"), required=True)
    r = sub.add_parser("report", help="regenerate a gated full-run visual report")
    r.add_argument("--session", required=True)
    r.add_argument("--result-dir", required=True)
    t = sub.add_parser("stop", help="stop Compose without deleting its volumes")
    t.add_argument("--session", required=True)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "doctor":
            return doctor(args)
        if args.command == "configure":
            configure(args)
        elif args.command == "setup":
            setup(args)
        elif args.command == "experiment":
            return experiment(args)
        elif args.command == "report":
            report(args)
        elif args.command == "stop":
            stop(args)
        return 0
    except (LabError, subprocess.CalledProcessError) as exc:
        print(f"AISIG lab: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
