# Rivet Test Fixtures

Fixtures are small package shapes used to keep workspace, resolver, install, and audit examples deterministic.

- `fixtures/packages/benign-cli` models a low-risk package with one executable.
- `fixtures/packages/risky-postinstall` models a high-risk package with lifecycle script and native binary indicators.

The fixture catalog is snapshotted by `make workspace-sync` and checked by `make fixtures-check`.
