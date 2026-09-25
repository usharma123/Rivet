# ADR 0007: Signed Attestations, Mirroring And A Run-Time Sandbox

Status: accepted

## Trust chain

1. The registry, not the client, imports npm packages. It fetches only from the configured npm host, checks the published sha512 integrity (falling back to sha1 `shasum` only when that is all npm has, and recording that), verifies Sigstore provenance, and computes its own sha512 artifact hash and canonical tree digest.
2. Artifact uploads are content-addressed: the registry hashes the bytes and rejects uploads whose hash does not match the path.
3. Releases are immutable: republishing a version with different bytes is a conflict.
4. For every release the registry serves a statement binding name, version, artifact hash, tree digest, normalized manifest, provenance, audit summary and current state. Statements are signed with Ed25519 over `"rivet-attestation-v1\n" || payload`, re-signed on every request, and expire after 7 days (`RIVET_ATTESTATION_TTL_HOURS`).
5. The CLI pins the registry key on first use (or from `RIVET_REGISTRY_PUBKEY`) and rejects statements signed by any other key. It never replaces a cached statement with an older one (no rollback to a pre-revocation "active").
6. Installs download the artifact from the registry and require its sha512 and recomputed tree digest to match the statement. Installs stage a new tree and swap it only after required builds succeed. Before every run the CLI compares local state with a protected install receipt, validates links and layout, refreshes statements for every installed package exposed to Node resolution (falling back to unexpired cached ones offline), re-applies policy, and re-hashes each package directory.

This is TUF-inspired rather than full TUF: there is one online key, no role separation or thresholds, and freshness comes from short-lived statements rather than timestamp metadata.

## Tree digest v1

The registry (Go) and CLI (Rust) must agree on package contents. A gzip tar is read by stripping the first path component, keeping only regular files, rejecting absolute, `..`, NUL or backslash paths, letting later duplicates win, and hashing sorted `path \0 x|- \0 sha256hex \n` lines with SHA-256. `fixtures/tarballs/tree-vector.tgz` pins the result for both implementations.

## Supply-chain policy

- Cooldown: releases younger than `min_release_age_hours` (default 72) are skipped, including dist-tags; exact pins inside the window fail unless `--allow-fresh`.
- Registry-native names take precedence over npm (ADR 0006). A native name is never resolved or imported from npm, which closes dependency confusion; claiming a name npm already serves needs the admin token.
- Install scripts never run by default. Allowed scripts (`[policy].allow_scripts` or `--allow-scripts`) run inside the sandbox with write access only to their own package directory and a 120-second timeout. A failed required script aborts installation and retains the prior tree; a failed optional package is omitted. Successful script outputs have their digest recorded locally.
- Publisher tokens cannot self-assert `security_evidence` or `registry_approved`; those need the admin token.

## Run-time sandbox

Package code runs under macOS Seatbelt (`sandbox-exec`) or Linux bubblewrap. Internet access is off unless granted per command. Host Unix-socket brokers are denied even when internet access is granted: Seatbelt blocks remote Unix sockets, while bubblewrap uses a seccomp filter for x86_64 and aarch64 that rejects AF_UNIX socket creation and unsafe socketpairs. Other Linux architectures fail closed. The home directory's contents are hidden except for the project and tool directories; credential locations and the resolved Rivet store's trust data stay unreadable and unwritable even inside granted paths. Project policy, lockfiles and the entire `node_modules` tree are read-only during runtime. When a write grant covers their parent, Seatbelt denies renaming the protected ancestors; bubblewrap cannot, but its read-only bind mounts move with a renamed directory, so the protected bytes still cannot change, and a tree swapped in at the old path fails verification on the next run. Secret directories inside exposed paths are hidden behind empty read-only mounts on Linux. A protected path crossing a symlink inside a writable grant is refused; use the canonical store path or narrow the write grant. Writes are limited to the working directory (when the executable declares `write:cwd`) and a private temp directory. The environment is cleared except for a short allowlist and names the user explicitly grants with `--allow-env`; executable declarations are requests, not grants. `HOME` points at an empty temp directory. Without a sandbox backend Rivet refuses to run package code unless `--unsafe-no-sandbox` is passed. The Linux path is runtime-tested by the CLI's live sandbox tests and `tools/e2e/linux.sh` (bubblewrap as an unprivileged user, validated on aarch64 in Docker) and by the CI jobs on x86_64 Ubuntu; see `docs/security-review.md`.

`node_modules/.bin` entries are shims that call `rivet run`, so npm-style invocations get the same verification and sandbox. Code the user runs directly with `node` is the user's own program and is not sandboxed.
