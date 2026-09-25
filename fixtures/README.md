# Rivet Test Fixtures

Fixtures are small package shapes used to keep resolver, install, and audit behaviour deterministic.

- `fixtures/packages/benign-cli`: a low-risk package with one executable.
- `fixtures/packages/risky-postinstall`: a lifecycle script plus a native binary. Both are common in legitimate packages, so the expected verdict is medium (warned).
- `fixtures/packages/credential-stealer`: a postinstall that reads `~/.npmrc` and posts it with the environment to a webhook. It is modelled on real npm worms and targets a `.invalid` host so it can never reach the network. The static audit must mark it critical, and the dynamic agent must catch the honeytoken read and the egress attempt.
- `fixtures/tarballs/tree-vector.tgz` with `tree-vector.digest`: the canonical tree-digest test vector shared by the Go registry and the Rust CLI. It covers the `package/` prefix, directory entries, a symlink (skipped), an executable bit, a duplicate path (the later entry wins) and a `./` segment.

Each package declares `rivetFixture.expectedVerdict` and `expectedState`; `registry/internal/audit` tests assert them. The fixture catalog is snapshotted by `make workspace-sync` and checked by `make fixtures-check`.
