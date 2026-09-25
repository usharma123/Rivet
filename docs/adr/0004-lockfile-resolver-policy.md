# ADR 0004: Lockfile And Resolver Policy

Status: accepted (revised for lockfile v2)

The registry resolves versions; the CLI walks the graph. For each `(name, range)` the CLI asks `POST /v1/npm/resolve`, and the registry applies npm semver rules (ranges, dist-tags, `npm:` aliases expanded by the client), skips releases inside the cooldown window, skips releases whose audit left them `quarantined`, `blocked`, `revoked` or `yanked`, imports and audits the chosen version, and returns a signed statement. The CLI only follows dependencies listed in signed statements, never files it downloaded.

Resolver rules:

- Dependencies are deduplicated by sending already-chosen versions as `prefer`; peers resolve the same way so a graph shares one copy where ranges allow.
- Optional dependencies (including platform packages filtered by `os`/`cpu`) may fail or be skipped; required ones fail the install.
- git, URL, `file:` and other non-registry specs are refused: they cannot be audited.
- Several versions of one package can coexist (pnpm-style `node_modules/.rivet/<id>` virtual store).

`rivet.lock` v2 records the roots, every package id, its artifact hash, tree digest, state, verdict and provenance, the dependency edges, and the registry key the graph was signed with. A lockfile install fetches fresh statements for every package and fails if the registry now describes different content for a pinned version. Lockfiles from another registry key are refused. v1 lockfiles carry no signed identity and are re-resolved.

The policy goal is npm compatibility with stronger trust guarantees, not a line-for-line clone of npm internals.
