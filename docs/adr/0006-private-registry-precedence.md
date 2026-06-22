# ADR 0006: Private Registry Precedence

Status: accepted

Rivet should prefer configured private registries before public npm import fallback. Private packages must still pass the same ownership, audit, release-state, and executable preflight rules as public packages.

This supports internal tools without recreating npm's habit of showing too little trust context before running package code.
