#!/usr/bin/env bash
# Runs the Linux runtime checks locally in Docker: the CLI test suite
# (including live bubblewrap and seccomp sandbox tests) and, unless
# RIVET_LINUX_SKIP_E2E=1, the npm end-to-end script in both placements.
# The container is privileged only so the unprivileged user inside it can
# create user namespaces for bubblewrap; the tests themselves run as non-root.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
IMAGE=rivet-linux-check

docker build --quiet -t "$IMAGE" -f "$ROOT/tools/e2e/Dockerfile.linux" "$ROOT/tools/e2e" >/dev/null
docker run --rm --privileged \
  -v "$ROOT":/src:ro \
  -v rivet-linux-cargo:/home/rivet/.cargo/registry \
  -v rivet-linux-target:/home/rivet/target \
  -e CARGO_TARGET_DIR=/home/rivet/target \
  -e RIVET_LINUX_SKIP_E2E="${RIVET_LINUX_SKIP_E2E:-}" \
  -e RIVET_E2E_BENCH_OUT="${RIVET_E2E_BENCH_OUT:+/home/rivet/bench.jsonl}" \
  "$IMAGE" bash -euo pipefail -c '
    echo "running as $(id -un) (uid $(id -u))"
    mkdir -p work && tar -C /src --exclude=./target --exclude=./tmp --exclude=node_modules --exclude=.git -cf - . | tar -C work -xf -
    cd work
    bwrap --ro-bind / / --unshare-user --unshare-net true && echo "bubblewrap user namespaces: ok"
    (cd cli && cargo test --locked)
    if [[ -z "$RIVET_LINUX_SKIP_E2E" ]]; then tools/e2e/npm-port.sh; fi
    if [[ -n "${RIVET_E2E_BENCH_OUT:-}" && -f "$RIVET_E2E_BENCH_OUT" ]]; then cat "$RIVET_E2E_BENCH_OUT"; fi
  '
