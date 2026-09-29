# Verification, portable locks, peers, and audit observations

## Results

- Streaming hashes bound file-content memory; bounded parallel hashing and
  attestation cache writes reduce verification time while retaining full-tree
  checks. The matched cache comparison reduced median command time from
  193.5 ms to 116.9 ms. The separate large-file helper reduced peak RSS from
  193.4 MiB to 1.4 MiB.
- Lock v3 preserves identical frozen lock bytes across actual macOS and Linux
  arm64 installs, including native esbuild, without resolver calls.
- Signed peer fixtures verify distinct runtime contexts, compatible range
  intersections, conflict refusal, aliases, optional peers, and cycles.
- The live gVisor pipeline certifies isolated kernel observations and refuses
  incomplete or unsupported evidence. Native network, protected evidence,
  forged hook logs, and detached-child cases passed their expected outcomes.

All final integration checks passed. Coverage and deployment limits remain
explicit below and in [the security review](security-review.md#open-limits).

## Acceptance criteria

This work uses GPT-6 Sol for implementation and Astra for independent review.
Each round records its measurements, validation, and unresolved findings before
the next round is accepted.

### Verification performance

- Compare release builds on identical installed trees, with repeated samples.
- Report hashing, remaining verification work, total command time, and memory
  separately. Label warm filesystem caches and measurement limits.
- Preserve the canonical tree digest and verification of every exposed package.
- Exercise content changes, executable bits, added and removed files, symlinks,
  special files, dependency links, receipts, and attestation rollback.
- Keep useful measured improvements; reject changes that weaken verification or
  merely move work outside the reported timing.

### Portable frozen installs

- Retain pinned optional platform variants and their dependency closures.
- Materialize only the applicable graph, using signed platform metadata.
- Preserve the portable lockfile when installing with `--frozen`.
- Install the same lockfile on actual macOS and Linux runtimes, including a
  native optional dependency, without resolving replacement versions.
- Reject altered identities, missing required edges, and unpinned replacements.
- Specify migration behavior for existing version 2 lockfiles.

### Peer dependencies

- Resolve peers from the consuming context and report incompatible providers.
- Preserve separate instances when the same release consumes different peers.
- Handle absent optional peers, compatible peers, transitive consumers, cycles,
  and aliases deterministically.
- Keep contextual installation IDs separate from signed release identities.
- Revalidate peer bindings during frozen installation and installed verification.
- Verify Node loads the expected provider from each installed context.

### Trusted gVisor observations

- Collect events outside package-controlled files, processes, and credentials.
- Establish tracing before package execution, including native code and children.
- Bind observations to the audited artifact, manifest, and unique execution.
- Fail closed on unavailable collectors, incomplete probes, event loss,
  malformed evidence, exceeded resource limits, and timeouts.
- Test package attempts to forge, delete, suppress, and replay evidence.
- Demonstrate the boundary under a live gVisor runtime. Unit-test simulations
  alone do not establish runtime protection.
- Describe what the probes exercised; trusted observation does not prove that
  every possible package behavior was explored.

## Starting point

- Base commit: `f2c3c0d1c0075b92b08eb45beae806a3ac7a5f96`.
- Existing platform and benchmark evidence: `docs/security-review.md`.
- A fresh Docker `runsc` smoke test succeeded on Linux aarch64 on 2026-09-29.
  At that stage, trusted collection and full audit execution had not been validated.

## Review rounds

### Round 1: streaming tree hashing

The implementation reads each file through a 64 KiB buffer and retains only
paths, executable flags, and SHA-256 digests. It still reads every file on every
verification. Review also required nonblocking, no-follow opens and rejection of
special files, plus interrupted-read handling.

An alternating A/B/B/A comparison ran ten samples per release binary on the
same 137-package macOS installation, after warmup. The command was
`semver 1.2.3 -r ^1.0.0`, using `rivet run --json --dry-run` for the comparison.

| Median | Baseline | Streaming |
| --- | --- | --- |
| CLI wall time | 422.1 ms | 418.0 ms |
| Verification | 414.5 ms | 411.0 ms |
| Hashing | 256.5 ms | 252.0 ms |
| Other verification | 123.0 ms | 125.0 ms |

This is not evidence of a meaningful speed improvement. The subsequent round
tests bounded parallel hashing. The
comparison script is `tools/bench/verify.py`; these samples used warm filesystem
caches and a local registry. Full-command E2E checks passed for both binaries,
including tamper and revocation checks, but their separate fresh installations
are not a controlled performance comparison.

The final isolated hashing test used the same 192 MiB file and three A/B/B/A cycles.
The baseline and candidate produced identical canonical digests. Median peak
RSS of each direct hashing process fell from 193.4 MiB to 1.4 MiB, while median
elapsed time fell from 398.4 ms to 367.3 ms. This measures the hashing helper,
not a whole Rivet command or its process tree. Reproduce it with
`cli/examples/tree_hash.rs` and `tools/bench/tree-memory.py`.

### Round 2: bounded parallel hashing

The verifier hashes every installed package using a shared work queue, with at
most eight workers and no more than the reported CPU parallelism. It verifies
signatures and policy before this phase and waits for every worker before any
package can run. Results are checked in package order. Thread creation and
worker failures return errors after all launched workers are joined.

Ten warm samples per variant on the same 137-package installation produced:

| Variant | Median CLI verification wall time | Median hashing wall time |
| --- | --- | --- |
| Serial baseline | 402.1 ms | 224.5 ms |
| Two workers | 271.7 ms | 110.0 ms |
| Four workers | 217.4 ms | 61.5 ms |
| Eight workers | 206.3 ms | 50.5 ms |

Eight workers is the selected cap. These measurements cover a local registry
and warm filesystem caches on one macOS arm64 host. They do not establish a
universal optimum. `hash_ms` now records elapsed time for the parallel phase,
not a sum of each worker's elapsed time.

The final isolated hashing candidate passed 61 Rust tests, Clippy with warnings
denied, and formatting checks. Independent Astra review found no blocking
verification regression. Its thread-error findings were fixed. Existing races
with external filesystem mutation remain; verification is not an atomic
filesystem snapshot.

Raw samples, package identities, build details, and the exact candidate patch
are in `tools/bench/results/2026-09-29-macos-arm64.json` and the adjacent patch.
The final integrated CLI also passed the runtime checks listed below after the
resolver and cache changes.

### Round 3: attestation cache writes

Profiling after parallel hashing found that cache writes dominated the remaining
verification time. Signature checks took about 4 ms in the sampled run. The
candidate uses the same bounded worker queue for independent cache writes and
retains the existing per-release lock, signature, rollback, and atomic replacement
checks.

Review rejected an initial ordering change that checked policy before updating
the cache. A fresh revocation must be saved even when policy rejects execution.
Review also required saving valid fresh statements when another statement in the
same response is missing or invalid. Regression tests now cover a fresh
revocation followed by offline verification, a mixed response containing a
revocation and an error, and a rollback attempt beyond the worker count.

The corrected production candidate passed 64 isolated Rust tests, Clippy,
formatting, and the full temporary-directory E2E. A fresh alternating comparison
used ten samples per binary on one 137-package installation:

| Median | Parallel hashing only | Parallel hashing and cache writes |
| --- | --- | --- |
| CLI verification wall time | 193.5 ms | 116.9 ms |
| Verification | 187.5 ms | 110.5 ms |
| Hashing | 49.0 ms | 49.0 ms |
| Other verification | 107.5 ms | 33.0 ms |

This is a 39.6% reduction in wall time for this comparison. Do not combine it
arithmetically with the earlier round's measurements from a different fixture.
The raw samples and exact source are archived in `tools/bench/results/`.
The integrated verifier fetches, verifies, and caches each signed release once,
then checks every contextual instance and hashes every installed directory.
The final signed fixtures and full runtime checks passed with this integration.

### Compatibility review

Version 3 stores four pinned target graphs and selects one for installation.
Frozen installs retain the original lock bytes. Context IDs distinguish packages
whose peer providers differ, while attestations and artifacts retain their signed
release identities.

Review produced regressions for provider declaration scope, cyclic peer
reachability, shared dependency graphs, peer aliases with different target
packages, coherent range intersections, cold artifact fetches, long package names,
optional-package removal, and policy rejection across context-ID changes.
Context expansion also has an explicit depth limit to return an error instead of
overflowing the stack.

An optional install-script failure removes every context of that signed release.
If any context is required, installation fails. This conservative rule avoids
combining inconsistent script results when the graph is rebuilt.

Signed local-registry fixtures passed actual Node loading, cold frozen
reinstalls, cycles, optional peer behavior, conflicts, and forged-binding
rejection. Explicit contextual IDs, signed release IDs, and root aliases all
route `rivet verify` through full installed-tree verification.

`python3 -u tools/e2e/compatibility.py --keep` passed on the integrated release
CLI. The same esbuild 0.25.0 lock worked from macOS to Linux and back, and a
Linux-origin lock worked on macOS. Both operating systems executed a native
TypeScript transform. Every frozen phase made zero resolve requests. Every
lock digest was
`4a25eb54d81a2dc0125528ead2952a064631b14643fe4cd349e8ae8c98f87ee9`.
The macOS binary SHA-256 was
`77d3a2eadafa6e0b893aad01338dd267cd1d322d7f44d5388a08fdb2321adc9b`.

These live checks cover arm64 on both operating systems. Linux installs ran as
UID 1000 on a native container filesystem. An earlier test that installed into
a Docker Desktop macOS bind mount failed at `fchmodat`; the test now transfers
the manifest and lock bytes between platform-local installations.

### Audit review

The Go pipeline has completed a live gVisor audit using a separate collector and
a private trace volume, with a root supervisor and UID 2000 package probes.
The host checked cumulative event loss before releasing the supervisor. The
pipeline bound the result to the artifact, canonical tree, and normalized
manifest and signed it only after both containers exited successfully.

The same lifecycle passed with a non-root registry process and an
administrator-provisioned helper restricted to the host trace query. The
unprivileged command without that helper failed closed. Tests used an isolated,
disposable Docker daemon and did not reconfigure the shared daemon.

Review found gaps in classifying native file access through aliases. The current
collector conservatively refuses unsupported alias and namespace changes, proc
magic-link paths, and unsupported I/O mechanisms. Ordinary failed io_uring setup
probes can proceed because no ring was created; successful setup prevents
certification. Native positive and negative fixtures for the final collector are
recorded in the audit gate. Trusted observations cover the configured probes and trace
points; they do not prove that every possible package behavior was explored.

The final fresh Linux arm64 gate used the official checksum-verified runsc
`release-20260601.0`. A native unconnected UDP send produced a kernel network
observation. A package that modified its advisory hook log still produced three
kernel honey-path observations and no forged egress. Symlink/proc aliases and
namespace changes were refused. This runtime returns `ENOSYS` for `openat2`, so
that fixture verified a regular-read fallback rather than claiming an observed
`openat2` call.

The detached-child fixture was refused because the final process list contained
an adopted zombie as well as PID 1. The Node supervisor cannot reap those children;
the current policy conservatively refuses certification. A registry running as
the reserved package UID 2000 was also refused before creating Docker resources.
Reproduction instructions are in
[the audit gate guide](../tools/e2e/README-audit-trace.md). The
[live result receipt](../tools/e2e/audit-trace-results-2026-09-29.md) records
source hashes, image identities, runtime checksums, and each fixture's outcome.

## Integrated validation

- 83 Rust tests on macOS and Linux, including live Seatbelt and bubblewrap checks.
- Rust formatting and Clippy with warnings denied.
- Full npm E2E in temporary directories and under `$HOME` on both operating systems.
- Signed peer fixtures and real native esbuild with the same frozen lock in both directions.
- Go tests with the race detector; real Postgres store and legacy-release tests.
- Live gVisor certification, native observations, forged-log resistance, and fail-closed cases.
- Workspace, documentation, schema, Node syntax, and Python observer checks.

The integrated actual-command medians were 201 ms and 176 ms on macOS, and
84 ms and 80 ms on Linux, for temp and `$HOME` respectively. These used separate
fresh installations with warm local registries. They are not controlled speed
comparisons. Full timing and build evidence is in
`tools/bench/results/2026-09-29-integrated-e2e.json`.
