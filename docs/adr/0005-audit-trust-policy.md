# ADR 0005: Registry-Signed Audits Are The Public Trust Signal

Status: accepted (revised)

Only the registry produces audits. Clients may request a re-audit but can never submit verdicts, evidence or signatures; the old path that accepted client-supplied audits is removed. Every audit record is signed with the registry's Ed25519 key and verified before it is stored.

Every release is audited before it becomes installable (new releases start `pending`):

- Static analysis always runs in-process: install scripts (including implicit `node-gyp`), native binaries, obfuscation, embedded blobs, and per-file capabilities (`network`, `child_process`, `dynamic_code`, `env_harvest`, `sensitive_paths`, `exfil_endpoint`, and the `exfil_pattern` combination).
- Provenance: npm Sigstore bundles are verified against the public-good trust root and bound to the exact tarball digest; the proven source repository is compared to the declared one.
- Diff against the previous release: new capabilities, new install scripts, added dependencies, a publisher change and dropped provenance weigh far more than static capabilities, because compromised releases usually show up as sudden changes.
- Registry metadata is compared with the tarball's own package.json (manifest confusion).
- With `RIVET_AUDIT_MODE=gvisor`, the agent runs the canonical installed tree and normalized manifest under gVisor with `--network=none`. Extraction or probe-setup failure marks the run incomplete. Honeytoken and egress-hook observations are produced in package-writable context and are explicitly untrusted: they are advisory signals only and cannot lower risk or satisfy `require_sandbox_audit`.

Verdicts map to states: low `active`, medium `warned`, high `quarantined`, critical `blocked`. Re-audits never undo `revoked`, `yanked` or `archived`. `quarantined`, `blocked` and `revoked` require explicit unsafe overrides at install and at run time. Local BYOK evals remain advisory.

Known limits: static heuristics can be evaded by determined attackers. The package can erase or forge its own hook logs, and the Node hook cannot observe native code. Until an auditor-owned observation boundary exists, no dynamic run is certified as a trusted pass; `require_sandbox_audit` fails closed. gVisor was not available for local runtime validation of this change.
