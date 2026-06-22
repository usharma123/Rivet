# ADR 0004: Lockfile And Resolver Policy

Status: accepted

Rivet's current lockfile is an MVP primitive. Resolver v2 should preserve deterministic installs, support multiple versions of the same dependency, record registry and artifact identity, and keep audit/release-state metadata close to each resolved package.

The policy goal is npm compatibility with stronger trust guarantees, not a line-for-line clone of npm internals.
