# gVisor audit trace live result, 2026-09-29

Command: `tools/e2e/audit-trace.sh`. It created a disposable Docker-in-Docker daemon, downloaded both pinned gVisor binaries from the official bucket, and verified their SHA-512 files (`runsc: OK`, `containerd-shim-runsc-v1: OK`). The test ran on Linux `aarch64` with `runsc version release-20260601.0` (`spec: 1.2.1`). Runsc SHA-256 was `bc686dd7e9f3432a898ccf6c406be37eb87ebe13c667b4f6cbebb8f69fc00e81`.

The fresh daemon built agent image `sha256:16b7949a2ae2ca3847c43a73956903ac6893d7f0b0a0523781a91802d432cfc4` and observer image `sha256:1789ef74c0c4eb3dc66b91104350363791462728d8e172152562a31a07790fa3`. The setuid test helper SHA-256 was `3ecc513c166a75a55e58c5660725391ea456c0e62dfd6bb8cc0facbd2e713e9b`.

| Live test | Result |
| --- | --- |
| UID 1000 without host helper | Refused: `host gVisor process query failed`; unprivileged runsc could not load the sandbox. |
| UID 1000 with restricted helper | Signed gVisor audit passed. Runner required supervisor-only `runsc ps`, remote sink dropped zero, and both containers to exit successfully. |
| Native symlink then mmap | Refused: `unsupported symlinkat (arm64) syscall during package probe`. |
| Native proc-root alias then mmap | Refused: `unsupported proc or fd path alias during package probe`. |
| Native unshare | Refused: `unsupported unshare (arm64) syscall during package probe`. |
| Native openat2 then mmap | `openat2 errno=38` (`ENOSYS`) on this pinned release; fallback open certified one kernel honey path. |
| Native `//tmp` path then mmap | Certified one kernel honey path after Linux path normalization. |
| Native unconnected UDP `sendto` | Certified one kernel network attempt without a JavaScript hook. |
| Package evidence/hook forgery | Certified three kernel honey observations and zero kernel egress observations; forged hook entries did not enter signed findings. |
| Detached child | Refused: `gVisor workload has tasks after completion marker: [1,15]`. The adopted zombie prevents certification. |
| Registry UID 2000 collision | Refused before Docker resources: registry UID collides with reserved package probe UID. |

A second live smoke using the final source files captured the raw completion receipt before workload exit: `runsc ps -format=json` returned `[1]`; `runsc trace list` showed one `Default` remote sink with `dropped: 0`; workload and observer both exited `0`. The observer reported 805 packets, 137,802 bytes, 427 UID 2000 events, 20 execs, four network attempts, two `.npmrc` observations, zero pending io_uring exits, and `complete: true`. That manual smoke rebuilt the same source in a persistent test daemon; its agent and observer image IDs were `sha256:3400b1c75390596a182667751f614f9be3c11cc52d251dd7be890b7d743479e6` and `sha256:636edef54842b7eb03ff5d5fe02bb956474ba93b759b4b39bf67323c140624e0`. After workload exit, `runsc trace list` returned `loading sandbox: file does not exist`, so the production check is made at the quiescent marker before release.

Source SHA-256 for this run:

| File | SHA-256 |
| --- | --- |
| `audit-agent/agent.js` | `c95ad414580003504ff662ab1feda10c92fa84bce90f73a1181426ece30fdf2d` |
| `audit-agent/observer.py` | `8c0a2f0efc65641f5edef3d59902ff566bfcb82807ea15464a2c0aa5737cee6f` |
| `audit-agent/Dockerfile` | `1a514ad0b951a098676f2e3403507cd6f52f1cc30e791e8154e5c387c17cd359` |
| `audit-agent/Dockerfile.observer` | `d5ff0b28130bdb07893950be513418ac0388ff477192daf7f42663c1cd947f05` |
| `registry/internal/audit/docker.go` | `6590af961262c0898c6a49b410c150ca08e307aea01e1e5ba396e1a3c097306a` |
| `registry/internal/audit/trace.go` | `df18bc1b6e03881087b5048b33d253699893d32403c219a497e6070717298be3` |
| `registry/internal/audit/trusted_test.go` | `a3a7eaa7b0c19ed56ae93ca9e61256014e84f95e7d842738c774d42016041da7` |
| `tools/e2e/audit-trace.sh` | `68db062add8558c2a857b93f5ff01c83e266825d67b28ddd7898d566c829206d` |
| `tools/e2e/runsc-gate.go` | `3b1ea25d26f37e68eab7769708b7f0b8cc8af94787c0d404e07c01043ac46677` |
| `tools/e2e/audit-native.go` | `8cc90dbe623e200324a5df67a2b059c55e60f6987d8fe772436b25c9b4db27b3` |

Local parser tests (10), Node syntax, harness shell syntax, and native ARM64 build passed. This is a trusted record of bounded probe observations; it does not prove the package benign or every behavior exercised. The gVisor runtime version gate limits these results to the tested release.
