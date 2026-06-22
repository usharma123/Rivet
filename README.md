# Rivet

Rivet is a package manager, registry, and executable trust layer for visible, auditable, reversible package installation and execution.

The first MVP slice proves this flow:

```sh
rivet import npm:prettier
rivet inspect prettier
rivet run prettier --version
```

It also includes a Postgres-backed registry, release state controls, native `rivet.toml` and `rivet.lock` files, local content-addressed artifacts, namesquat warnings, and a deterministic BYOK eval stub.

## Layout

```text
cli/        Rust CLI and package-manager logic
registry/   Go registry service and Postgres persistence
schemas/    Public JSON schemas for manifests, locks, and events
examples/   Demo packages and npm import notes
```

## Development

Start the local registry dependencies:

```sh
docker compose up -d postgres
```

Run the registry:

```sh
cd registry
DATABASE_URL=postgres://rivet:rivet@localhost:5432/rivet?sslmode=disable \
RIVET_REGISTRY_TOKEN=dev-token \
RIVET_ARTIFACT_DIR=./artifacts \
go run ./cmd/server
```

Build the local static gVisor audit-agent image:

```sh
make audit-agent-image
```

Run the CLI:

```sh
cd cli
RIVET_REGISTRY_URL=http://localhost:8080 \
RIVET_REGISTRY_TOKEN=dev-token \
cargo run -- import npm:prettier
```

Useful checks:

```sh
make test
make fmt-check
```
