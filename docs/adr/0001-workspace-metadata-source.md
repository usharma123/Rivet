# ADR 0001: `rivet.workspace.toml` Is The Workspace Source Of Truth

Status: accepted

Rivet uses `rivet.workspace.toml` to define first-class components, release groups, owners, public interfaces, validation commands, docs, and schema references. README, CI, labeler config, and generated snapshots are checked against this manifest.

This mirrors the useful operating-model discipline from JSR monorepos without adopting Deno/JSR as Rivet's runtime architecture.
