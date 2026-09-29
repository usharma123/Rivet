# Verification benchmarks

Build release binaries before comparing verifier changes. `verify.py` alternates
old/new/new/old on one installed project and checks that both verify the same
number of packages. It reports verifier phase times from `rivet run --json
--dry-run`. The end-to-end script runs it at the benchmark step when
`RIVET_E2E_BENCH_BEFORE` points to the old binary:

```sh
cargo build --release --locked -p rivet
cp target/release/rivet /tmp/rivet-before
# Make the candidate change and rebuild.
RIVET_E2E_PLACEMENTS=tmp RIVET_E2E_BENCH_BEFORE=/tmp/rivet-before \
  tools/e2e/npm-port.sh
```

The release tree-hash helper isolates file hashing from CLI startup, registry
work, and Node. To compare a candidate against commit `f2c3c0d`, build the
same helper source in a detached baseline checkout:

```sh
git worktree add --detach /tmp/rivet-hash-baseline f2c3c0d
mkdir -p /tmp/rivet-hash-baseline/cli/examples
cp cli/examples/tree_hash.rs /tmp/rivet-hash-baseline/cli/examples/
(cd /tmp/rivet-hash-baseline/cli && cargo build --release --locked --example tree_hash)
cp /tmp/rivet-hash-baseline/target/release/examples/tree_hash /tmp/tree-hash-before
(cd cli && cargo build --release --locked --example tree_hash)
python3 tools/bench/tree-memory.py /tmp/tree-hash-before \
  target/release/examples/tree_hash 192
```

`tree-memory.py` creates one 192 MiB file by default, confirms digest parity,
and uses `wait4` to record each hash helper's peak RSS. That RSS belongs to the
helper process, not Rivet plus a command it launches. Both scripts print raw
samples and medians as JSON. The end-to-end benchmark also records an actual
`rivet run` versus the same entry point under plain Node.

The archived hashing-only worker sweep used release variants differing only in
the historical `HASH_WORKERS` cap in `cli/src/core/installed.rs`. To reproduce
it, apply `results/2026-09-29-hashing.patch` atop commit `f2c3c0d`, build
those variants, then set
`RIVET_E2E_BENCH_TWO`, `RIVET_E2E_BENCH_FOUR`, and
`RIVET_E2E_BENCH_EIGHT` to those binaries. The E2E script runs `workers.py`
on the same installed tree. Current code uses `VERIFY_WORKERS` for both
attestation-cache work and file hashing, so changing its cap measures both
phases together. The 2026-09-29 raw samples, binary
hashes, package identities, and source patch are in `results/`.

The follow-up cache experiment is archived in
`results/2026-09-29-cache-macos-arm64.json`. Its baseline is the accepted
eight-worker hashing build, and `results/2026-09-29-cache-safe.patch` is the
additional verifier change. The JSON retains the exact source and binary
SHA-256 hashes, raw alternating samples, the fresh E2E workload, and a
separately labeled rejected exploratory result. On that same installed tree,
the final cache candidate reduced median verifier wall time from 187.5 ms to
110.5 ms. These are warm local-registry measurements on one macOS arm64 host.

`results/2026-09-29-integrated-e2e.json` and its paired macOS/Linux E2E logs
record the final shared-tree release binaries, source hashes, full runtime
checks, and actual `rivet run` samples in both temporary and HOME placements.
Those placement runs use separate newly installed trees, so they are runtime
validation and not a controlled before/after speed comparison.
