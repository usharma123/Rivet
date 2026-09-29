# Rivet validation

The `ci` workflow runs on pull requests, main pushes, merge queues, manual dispatch,
and weekly. All jobs use disposable standard GitHub-hosted runners. No deployment
credentials are needed. The labeler alone uses `pull_request_target`; it neither
checks out nor executes PR code.

| Gate | What it verifies |
| --- | --- |
| workspace | Generated metadata, schema/fixture/docs checks, actionlint, workflow and helper boundary tests |
| product, four platforms | Rust tests including live sandbox checks, Clippy, formatting, observer tests, Go tests, vet, race detector, coverage |
| portable-seed | Creates a v3 esbuild lock under a public test signing identity |
| compatibility, four platforms | Downloads those exact lock bytes, populates a local registry, then cold-installs without resolve calls; native esbuild, signed peers, aliases, cycles, conflicts, forged bindings; pinned real projects |
| e2e, four platforms | Live npm imports, runtime sandbox, tampering, revocation, shims, and both temporary-directory and HOME placements |
| audit-trace, Linux x64 and arm64 | Checksum-verified pinned runsc, separate observer, native network/file probes, forged logs, incomplete evidence, detached children and UID collision refusal |
| postgres | Uncached real database contract and legacy-release checks; production startup, import authorization, stable key and data after restart |
| dependency-security | Cargo vulnerabilities/unsoundness and Go reachable-vulnerability checks |
| Rivet required checks | Fails if any prerequisite failed, was cancelled, or was skipped |

The platform matrix is Linux x64 `ubuntu-24.04`, Linux arm64
`ubuntu-24.04-arm`, macOS arm64 `macos-15`, and macOS x64 `macos-15-intel`.
See [GitHub's runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

Configure branch protection to require **Rivet required checks** after its first
successful run. That setting is separate from the workflow and is not applied by
committing this file. Do not require only the workspace or product job. The
aggregate deliberately fails when another required job is skipped.

## Evidence and interpretation

Each integration job uploads a source receipt with the checked-out commit,
worktree status, individual source hashes, tool versions, run ID and attempt.
On PRs the tested commit can be GitHub's synthetic merge commit rather than the
branch tip. Use the receipt, not the PR title, to identify tested source.
Integration logs and JSON results survive failures for 14 days. Portable locks
are retained for 7 days. No signing secrets or client stores are uploaded.
The portable suite's fixed signing seed is public test data and must never be
used by a deployment. Each runner creates its own ephemeral registry at the
same loopback URL and imports the pinned releases before the measured frozen
phase. The frozen phase uses a cold client store and records zero resolve calls.

The real-project corpus pins Prettier, TypeScript, React/Vite, and ESLint roots.
Transitive versions can still change; each report includes resolved identities
and the lock hash. It checks actual formatting, compilation/build output, and
lint execution before alternating three warm Rivet/Node timing samples. These
are small representative workloads, not a claim that arbitrary existing npm
repositories work. The corpus uses static registry auditing. Its policy refusal
count does not measure acceptance under the gVisor probe policy.

The dedicated audit gate validates trusted observations against controlled benign
and adversarial packages. Audit coverage remains bounded to the executed probes.
A healthy registry HTTP endpoint does not establish gVisor certification.

Timing is reported without an absolute millisecond pass threshold: shared runner
load varies. Compare matched samples on the same host before claiming a speed
regression or improvement. The controlled benchmark scripts remain in
[tools/bench](../tools/bench/README.md).

Dependency vulnerability findings fail the security job. Triage or update the
actual dependency; do not add blanket ignores or `continue-on-error`. Dependabot
covers actions, Cargo, Go modules, and Docker images weekly. Third-party actions
are pinned to commits. Tool versions for scanners and workflow lint are explicit.

## Local commands

```sh
make workspace-check docs-check
make cli-test cli-clippy fmt-check registry-test audit-agent-check
python3 -m unittest discover -s tools/ci
actionlint
python3 -u tools/e2e/compatibility.py --native --corpus --evidence-dir /tmp/rivet-compat-results
tools/e2e/npm-port.sh
tools/e2e/audit-trace.sh
```

The native compatibility command works on all four supported targets and does
not require Docker. Its loopback port 18185 must be free. To test a transferred
lock, use `--lock-output /tmp/portable/rivet.lock` on the first machine and
`--lock-input /path/to/copied/rivet.lock` on the next. The older macOS arm64 to
Linux Docker round trip remains available by omitting `--native`.

Postgres checks require a disposable database:

```sh
export RIVET_TEST_DATABASE_URL='postgres://rivet:rivet@127.0.0.1:5432/rivet_test?sslmode=disable'
make registry-test-postgres
python3 tools/e2e/production.py
```

## Cost

This repository is public. Standard hosted Actions compute is currently free for
public repositories; larger runners have different billing. Keep artifact and
cache usage bounded and review billing if the repository becomes private.
There are no self-hosted runners or always-on CI servers in this configuration.
[GitHub Actions billing](https://docs.github.com/en/billing/concepts/product-billing/github-actions)
