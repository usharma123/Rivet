# Security review record

This records the 2026-09-25 review of the Rivet trust chain and the 2026-09-29 follow-up work on verification, portable locks, peers, and trusted audit observations. It replaces the four review notes that were kept in `docs/reviews/`: the original Astra review, the supplemental review, the Sol implementation notes and the Astra recheck. Their findings, evidence and open limits are preserved below. Update this file whenever a finding changes state or a limit is closed.

Passing tests show that the listed fixes work for the cases tested. They do not prove there are no remaining defects.

## How to reproduce the evidence

| Check | Command | Covers |
| --- | --- | --- |
| Unit and live sandbox tests | `make cli-test`, `make registry-test` | Everything marked "test" below. On macOS the sandbox tests run under Seatbelt; on Linux they run under bubblewrap and need it installed. |
| Postgres store contract | `make registry-test-postgres` with `RIVET_TEST_DATABASE_URL` | Store behaviour and the legacy-release startup check. |
| Live npm end-to-end | `make e2e` | Import, install, run, tamper, publish, revoke, offline and key-pinning flows against registry.npmjs.org, once in a temp directory and once under `$HOME`. |
| Linux locally | `tools/e2e/linux.sh` | The CLI suite and the end-to-end script as an unprivileged user under real bubblewrap, in Docker. |
| CI | `.github/workflows/ci.yml` | On Ubuntu 24.04, `product` runs the live Linux sandbox tests, `e2e` runs both placements and saves console, registry and benchmark logs for seven days, and `postgres` runs the real database tests without Go's test cache. |

Review-time probe output in the ignored `tmp/` directory is not part of the repository. Findings that relied only on a probe now point to a repository regression test or end-to-end step.

## Findings

Severity: P1 breaks a claimed trust boundary; P2 is a correctness or robustness defect.

| ID | Sev | Finding | Status | Repository regression or source evidence |
| --- | --- | --- | --- | --- |
| R1 | P1 | Package bin names were written raw into `.bin` shim comments; a newline in a name ran shell code before verification and outside the sandbox. | Fixed: names validated at registry ingestion and before shim writing; constant shim comment. | `command_names_cannot_inject_shell_or_escape_bin_directory`, `TestBinNamesRejectShellSyntax` |
| R2 | P1 | Dependency aliases such as `../../victim` escaped `node_modules` and let the linker replace files outside the install tree. | Fixed: aliases and names validated at resolver, signed-manifest, link and publish boundaries; injective package ids. | `package_alias_rejects_traversal_and_absolute_components`, `TestValidName` |
| R3 | P1 | An older, unexpired "active" statement could be replayed after a revocation was cached, including via a concurrent-write race and same-second timestamps. | Fixed: acceptance compares against the cache under a cross-process lock, rejects rollback and equal-time conflicts, and replaces atomically. | `rejects_replayed_active_attestation_after_revocation`, `concurrent_attestation_writes_keep_revocation`, `equal_time_revocation_conflict_is_rejected` |
| R4 | P1 | Runtime trusted unsigned `state.json`: dependency symlinks, bin entries and "script modified" digests could be changed without touching hashed package files. | Fixed: a protected install receipt outside the project; links, bins and edges checked against signed manifests; every installed package re-hashed, including sibling roots. | `rejects_state_and_link_tampering_before_execution`, `rehashes_sibling_root_outside_the_commands_closure`, e2e tamper step |
| R5 | P1 | Lifecycle scripts and executables declared only in a native `rivet.toml` were signed but never audited. | Fixed: audits use the signed normalized manifest. | `TestNativeManifestWithoutPackageJSONIsAuditedAndProbed` |
| R6 | P1 | The dynamic audit's observations are written by the same user the package runs as, so a package can erase or forge them. | Fixed: a separate observer receives gVisor events through a private volume. Certification requires a bound, complete stream, no remaining package processes, zero dropped events, and successful workload and observer exits. Package hook logs remain advisory. | `TestPackageWritableDynamicEvidenceCannotCertifyGVisorPass`, `TestDockerRunnerLive`, observer parser tests; live non-root Go pipeline under gVisor |
| R7 | P1 | The dynamic agent extracted the raw tarball, which can differ from the canonical tree that is signed and installed. | Fixed and exercised under gVisor: the registry prepares the canonical tree and normalized manifest and binds their hashes to the trace result. Incomplete required probes fail. | Go input-binding tests and `TestDockerRunnerLive` |
| R8 | P2 | Redirects bypassed the npm host allowlist. | Fixed: redirects are pinned to the configured scheme and host. | `TestRestrictedFetchesDoNotFollowCrossHostRedirects` |
| R9 | P2 | A failed install deleted the previous working install. | Fixed: builds in a staging tree and swaps only on success. | `failed_artifact_fetch_preserves_previous_installation`, `failed_required_script_preserves_previous_installation` |
| R10 | P2 | Failed required install scripts were reported as successful installs. | Fixed: required failures and timeouts abort; optional failures remove the package and its links. | `timed_out_required_script_preserves_previous_installation`, `failed_optional_script_is_removed_from_installed_state` |
| R11 | P2 | Attestation caches and tool indexes collided across registries and blocked key rotation. | Fixed: caches, receipts and indexes are scoped by registry and key. | `attestation_cache_is_scoped_to_registry_and_key` |
| R12 | P2 | `verify` could accept a stale cached statement and silently skip installed-file checks on malformed state. | Fixed. | e2e "verify" step (malformed state fails); `rejects_other_keys_and_expired_statements` covers expiry at the envelope level |
| R13 | P1 | A custom `RIVET_HOME` inside a granted path let package code rewrite trust pins and caches. | Fixed: the resolved store is protected; symlinked aliases inside write grants are refused. | `sandbox_blocks_custom_store_and_project_controls`, `sandbox_reads_global_tool_under_custom_store_in_real_home` |
| R14 | P1 | Write access to the working directory covered `rivet.toml`, the lockfile and `.bin` shims, so a package could grant itself network access. | Fixed: those paths are read-only during runs, including under broader write grants. | `sandbox_blocks_custom_store_and_project_controls`, `sandbox_protects_project_controls_under_broader_write_grant` |
| R15 | P1 | Network-disabled Seatbelt runs could reach host Unix-socket brokers such as SSH agents. | Fixed: Seatbelt denies remote Unix sockets in both network modes; Linux uses a seccomp filter. | `sandbox_denies_host_unix_socket_in_both_network_modes` (macOS and Linux) |
| R16 | P2 | Provenance accepted a package name and tarball digest taken from different subjects. | Fixed: both must be on the same signed subject, and the signed predicate type is checked. | `TestProvenanceRequiresNameAndDigestOnSameSubject` |
| R17 | P2 | Upgrading an existing database left old releases unattestable. | Mitigated: startup refuses legacy rows with an actionable error. No automatic migration. | `TestLegacyReleaseWithoutDigestBlocksStartup` |
| R18 | P2 | Frozen installs of yanked-but-locked releases failed because each edge was re-resolved. | Fixed: local npm-compatible range checks. | `frozen_range_checks_follow_npm_semver_rules` |
| R19 | P2 | `verify package@version` failed inside any installed project. | Fixed. | e2e "verify" step (explicit version inside a project) |
| R20 | P2 | Unchanged native lifecycle scripts were flagged as newly added on every release. | Fixed. | `TestUnchangedNativeManifestScriptIsNotNewEachRelease` |
| R21 | P1 | A package could declare `GITHUB_TOKEN` or similar in its permissions and receive the caller's value without a grant. | Fixed: declarations are requests; only `--allow-env` passes values. | `caller_secret_requires_explicit_environment_grant` |

### Found outside the numbered findings

| ID | Sev | Finding | Status | Repository regression or source evidence |
| --- | --- | --- | --- | --- |
| F1 | P2 | A failed optional install script removed the package directory but left its `.rivet/<id>` slot, which the verifier then rejected, breaking every later run in that project. | Fixed. | `failed_optional_script_is_removed_from_installed_state` |
| F2 | P1 | Seatbelt profiles for projects under `$HOME` could not read the project, because `file-read-data` rules outrank `file-read*`. | Fixed; the paired rules carry a comment explaining why both are needed. | Live sandbox tests under `$HOME`; e2e `home` placement |
| F3 | P2 | On Linux, secret directories inside exposed paths were masked with a writable tmpfs, so writes appeared to succeed (into a throwaway mount) instead of failing. | Fixed: the masks are remounted read-only. | `sandbox_reads_global_tool_under_custom_store_in_real_home` on Linux |

## Platform validation

| Platform | Sandbox tests | End-to-end (temp and `$HOME`) | Notes |
| --- | --- | --- | --- |
| macOS 15 (arm64), Seatbelt | Pass | Pass | Fresh 2026-09-29 run on the integrated CLI, 83 Rust tests. |
| Linux aarch64, bubblewrap, non-root | Pass | Pass | Fresh `tools/e2e/linux.sh` run on 2026-09-29, 83 Rust tests and both placements. The outer Docker container is privileged so UID 1000 can create user namespaces; the repository mount is read-only. |
| Linux x86_64, bubblewrap, non-root | Pass | Pass | GitHub Actions `ubuntu-latest`, bubblewrap 0.9.0, CI run [36175660533](https://github.com/usharma123/Rivet/actions/runs/36175660533) on PR #1 (commit `098fc31`). All six live sandbox tests ran under bubblewrap, including the seccomp filter refusing Unix sockets on an x86_64 kernel. The same run passed the Postgres store contract and legacy-release startup test. |
| gVisor dynamic audit, Linux aarch64 | Live pipeline passed | Dedicated audit fixtures | Separate collector, native egress and honeyfile observations, zero drops, supervisor-only completion, and both exits checked. See R6, R7, and the [live receipt](../tools/e2e/audit-trace-results-2026-09-29.md). |

On the 2026-09-25 macOS worktree, the full end-to-end run passed in both placements. All 56 Rust tests, Clippy, formatting, workspace and docs checks, and Node checks passed. The corrected PostgreSQL target ran both the store contract and legacy-release startup tests against a real database, then shut down the disposable database. That Linux run passed all 56 Rust tests, including live bubblewrap tests, and both end-to-end placements. A separate `go test ./...` run passed there; it did not enable the real-database tests. The Linux run used source snapshot SHA-256 `b4d662a1adaa8ed3a2b1209f710773f348cc93fae704b669d66fd489e0a86eba`.

## Run-time cost

`rivet run` re-verifies before every execution. The benchmark in `make e2e` times it on the end-to-end project against running the same entry point with plain `node`:

Historical samples measured on 2026-09-25 with `semver 1.2.3 -r ^1.0.0` in the end-to-end project (137 packages on macOS, 138 on Linux aarch64). "First measured run" follows earlier scenario runs and a frozen reinstall, so it is not a cold-cache measurement. "Warm" is the median of five subsequent runs; "plain node" runs the same entry point without Rivet. "Max child RSS" is the `RUSAGE_CHILDREN` high-water mark reported by the Python benchmark harness after the Rivet samples. It is not the concurrent peak of the parent and all children, so it under-represents process-tree memory when their peaks overlap.

| Platform | Placement | First measured run | Warm | Plain node | Hashing | Layout checks | Fetch statements | Max child RSS |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| macOS arm64 | temp | 0.48 s | 0.49 s | 0.06 s | Invalidated | 31 ms | 5 ms | 50 MiB |
| macOS arm64 | `$HOME` | 0.45 s | 0.46 s | 0.06 s | Invalidated | 27 ms | 6 ms | 49 MiB |
| Linux aarch64 (Docker) | temp | 0.23 s | 0.22 s | 0.02 s | Invalidated | 2 ms | 5 ms | 23 MiB |
| Linux aarch64 (Docker) | `$HOME` | 0.23 s | 0.22 s | 0.02 s | Invalidated | 2 ms | 6 ms | 23 MiB |

The historical hashing figures summed each package's elapsed whole milliseconds, discarding submillisecond time from every package. They remain invalid; corrected macOS and Linux samples are below. The corrected verifier sums durations before rounding and reports total, layout, fetch, hashing, and other verification time. Other verification includes signature checks, cache writes, policy and dependency-graph checks, plus millisecond rounding. Time outside verification also includes CLI startup, sandbox setup, and interpreter and package execution. The registry here was local, so real-network statement fetches will add latency. `rivet run --verbose` prints the breakdown, and `--json` includes it as `verify_timings_ms`.

Corrected historical samples (2026-09-25, `semver 1.2.3 -r ^1.0.0`; Linux aarch64 used `tools/e2e/linux.sh`, Linux x86_64 is the shared CI runner and therefore noisier):

| Platform | Placement | Packages | First run | Warm median | Plain node median | Max child RSS | Verify total | Layout | Fetch | Hash | Other |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| macOS arm64 | temp | 137 | 0.548 s | 0.572 s | 0.068 s | 51.6 MiB | 479 ms | 30 ms | 6 ms | 285 ms | 158 ms |
| macOS arm64 | `$HOME` | 137 | 0.514 s | 0.584 s | 0.064 s | 52.0 MiB | 456 ms | 31 ms | 5 ms | 252 ms | 168 ms |
| Linux aarch64 | temp | 138 | 0.221 s | 0.218 s | 0.017 s | 23.4 MiB | 191 ms | 2 ms | 5 ms | 168 ms | 16 ms |
| Linux aarch64 | `$HOME` | 138 | 0.217 s | 0.216 s | 0.018 s | 23.3 MiB | 190 ms | 2 ms | 5 ms | 167 ms | 16 ms |
| Linux x86_64 (CI) | temp | 138 | 0.244 s | 0.243 s | 0.042 s | 26.3 MiB | 183 ms | 8 ms | 11 ms | 111 ms | 53 ms |
| Linux x86_64 (CI) | `$HOME` | 138 | 0.246 s | 0.250 s | 0.046 s | 26.2 MiB | 188 ms | 8 ms | 12 ms | 114 ms | 54 ms |

The verification phases come from a separate `rivet run --json --dry-run` sample. They do not partition the first-run or median wall time.

The integrated 2026-09-29 CLI passed all end-to-end scenarios in both placements
on macOS and Linux arm64. Five warm actual-command samples per placement gave:

| Platform | Placement | Packages | Rivet median | Plain Node median |
| --- | --- | --- | --- | --- |
| macOS arm64 | temp | 137 | 201 ms | 65 ms |
| macOS arm64 | `$HOME` | 137 | 176 ms | 64 ms |
| Linux arm64 | temp | 138 | 84 ms | 20 ms |
| Linux arm64 | `$HOME` | 138 | 80 ms | 19 ms |

These runs used separate fresh installations and warm local registries. They
are runtime checks, not controlled comparisons against the historical table
or between operating systems. Source and binary hashes, phase measurements,
and logs are in `tools/bench/results/2026-09-29-integrated-e2e.json` and the
adjacent logs.

The 2026-09-29 implementation streams each file through a 64 KiB buffer and hashes packages with at most eight workers. It still reads every installed file before execution. No persistent file-digest cache was introduced.

An alternating comparison on the same warm 137-package macOS arm64 installation measured median verification command wall time of 402.1 ms for the serial baseline and 206.3 ms with eight workers. Median hashing time fell from 224.5 ms to 50.5 ms. A separate 192 MiB file test produced identical digests and reduced the hashing helper's median peak RSS from 193.4 MiB to 1.4 MiB. These are local measurements, not cross-platform performance guarantees. The isolated hashing candidate passed the full macOS end-to-end scenarios in both placements. Integrated resolver and audit validation is tracked in [the work report](verification-compatibility-work.md).

Raw samples and the measured source patch are in `tools/bench/results/`. The updated `hash_ms` measures elapsed time for the parallel phase. It is not the sum of individual workers' durations.

Full-tree hashing is justified by the current module exposure: Node can resolve any top-level root, so verifying only a command's closure would leave reachable code unchecked. Do not narrow it without also constraining Node's resolution, and re-measure before and after any change.

## Open limits

- **Audit coverage.** The trusted collector observes configured kernel events during selected probes. It does not prove that every package behavior was exercised. This runtime lacks a resolved-target mmap trace, so unsupported alias, namespace, and I/O mechanisms conservatively prevent certification. This can refuse legitimate packages. Details and deployment requirements are in [ADR 0005](adr/0005-audit-trust-policy.md).
- **gVisor deployment.** Certification requires runsc `release-20260601.0`, permission for its trace configuration, and a restricted host helper using the Docker runtime's binary and state root. Missing access fails closed. UID 2000 is reserved for package probes and cannot run the registry. Current live audit evidence is Linux arm64; the older Linux x86_64 CI evidence above covers the CLI sandbox, not this new audit collector.
- **Background audit children.** The Node supervisor cannot reap adopted zombies. Certification refuses any process list beyond supervisor PID 1, including killed but unreaped children. The live detached-child fixture verifies this refusal.
- **Legacy Postgres releases (R17)** need an external migration or a development reset; there is no automatic backfill.
- **Ancestor `node_modules`.** Rivet refuses to run when any ancestor directory contains `node_modules`, because Node would resolve unverified modules there. This is safe but blocks some monorepo layouts; broader support needs a defined resolution boundary.
- **Revocation scope.** Because every installed package is verified, one revoked package blocks every command in that project until it is removed or replaced.
- **Linux relocation.** Bubblewrap cannot deny renaming a protected directory's parent when a write grant covers it. Protected bytes still cannot change, and a substituted tree fails verification, but the rename itself succeeds.
- **Peer graph limits.** Context expansion allows at most 4,096 instances and 64 recursive levels. Larger graphs return an error. Optional script failure removes all contexts of that release, and fails the install if any context is required.
- **Portable lock coverage.** Version 3 pins macOS/Linux arm64/x64 variants. The live same-lock test covers macOS arm64 and Linux arm64 with native esbuild in both directions, identical lock bytes, and no frozen re-resolution. Cross-architecture variants have signed-fixture coverage; this change has no new live x64 run. Frozen version 2 installs require a normal install to migrate the project lock; existing version 2 installed receipts still verify.
- **Registry resource limits.** The packument cache never evicts, and public mirroring has no global concurrency or memory budget.
- **Filesystem races.** Streaming hashing bounds file-content memory, but verification is not an atomic filesystem snapshot. External mutation during or after verification remains outside that guarantee.
