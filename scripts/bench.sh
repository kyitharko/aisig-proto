#!/usr/bin/env bash
# Run the CPU benchmark and record the environment alongside the results.
# Usage: scripts/bench.sh            (N=10000 iterations, R=10 runs)
#        N=2000 R=5 scripts/bench.sh
set -euo pipefail
cd "$(dirname "$0")/.."

ts="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p results

export AISIG_ENV_TIMESTAMP="$ts"
export AISIG_ENV_RUSTC="$(rustc -V)"
export AISIG_ENV_CARGO="$(cargo -V)"
export AISIG_ENV_CPU="$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- | sed 's/^ *//' || echo unknown)"
export AISIG_ENV_CORES="$(nproc 2>/dev/null || echo unknown)"
export AISIG_ENV_KERNEL="$(uname -sr)"
export AISIG_ENV_GOVERNOR="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unavailable)"
dirty=""
git diff --quiet 2>/dev/null || dirty="-dirty"
export AISIG_ENV_GIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)${dirty}"

cargo build --release --quiet --bin bench
./target/release/bench --n "${N:-10000}" --r "${R:-10}" --out "results/bench_${ts}"
