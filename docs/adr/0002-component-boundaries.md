# ADR 0002: Component Boundaries Come Before Publishable Workspaces

Status: accepted

The first workspace phase treats `cli`, `registry`, `audit-agent`, `schemas`, `examples`, and `fixtures` as governance components. They receive owners, release labels, docs checks, and validation commands, but they are not all Rivet-publishable packages yet.

This keeps the repository understandable while Rivet's resolver, cache, install compatibility, and registry trust model mature.
