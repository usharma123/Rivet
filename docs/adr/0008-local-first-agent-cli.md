# ADR 0008: local package reuse and an agent-readable CLI

Status: accepted for the first compatibility increment; background synchronization
and remote worker separation remain proposed.

Use package.json as the source for npm-project dependencies and scripts. Keep
Rivet policy separate and keep the existing portable signed lock. Preserve legacy
rivet.toml-only projects. Refuse unsupported graph semantics explicitly.

Make local verified package reuse effective across processes before introducing
a daemon. Project locks serialize mutations and execution. Per-artifact locks
deduplicate concurrent downloads across projects. The CLI remains independently
usable in CI. Structured errors and streamed phase events provide agent feedback
without scraping human prose.

The shared registry remains the authority for approved releases, signing keys,
audits and revocations. Local content can be deduplicated by hash. Local claims
and telemetry cannot approve a release. Registry publishes remain authenticated,
explicit operations rather than implicit uploads during normal installs.

Entire.io's local capture and Git checkpoint synchronization inform the workflow,
not the artifact transport. Git is not the proposed store for package tarballs.
Project source, prompts, credentials and transcripts are not uploaded implicitly.

Later work requires measurements of cold/warm installs, verification, registry
round trips, network transfer, and multi-agent contention. Add an optional local
prefetch service only if those measurements justify its lifecycle and IPC costs.
Synchronize immutable artifacts separately from expiring trust statements. Offline
operation must retain an explicit freshness limit and rollback protection.

The current registry can import during resolution. A durable bounded audit queue
with resumable job IDs, artifact/environment/policy-version audit identities, and
resource budgets is a separate change. An ordinary cache miss must not be reported
as approved before the required audit completes. A CDN/object store or remote
worker protocol can be introduced when measured load warrants it.
