# ADR 0005: Registry-Signed Audits Are The Public Trust Signal

Status: accepted

Registry-signed gVisor audits are the public trust signal for package install and execution policy. Local BYOK evals remain advisory. High-risk, critical, quarantined, blocked, and revoked states must be visible before execution and must require explicit unsafe overrides when allowed.

Audit-agent images, evidence shape, release-state transitions, and privacy boundaries are part of the workspace governance surface.
