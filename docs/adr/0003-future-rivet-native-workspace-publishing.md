# ADR 0003: Design Rivet-Native Workspace Publishing Before Building It

Status: accepted

Future Rivet workspace publishing should support `packages/@rivet/*` or component publishing only after the secure npm-compatible install surface is stronger.

When implemented, workspace publishing must use registry ownership, signed gVisor audits, release states, path-based release notes, and explicit provenance. No component should bypass the audit and release-state machinery just because it lives in the Rivet repo.
