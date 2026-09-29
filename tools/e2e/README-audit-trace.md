# Isolated gVisor audit test

Run `tools/e2e/audit-trace.sh` from the repository checkout. It needs Docker, Go, curl, and permission to start a privileged Docker-in-Docker container. The script downloads the pinned gVisor `release-20260601.0` ARM64 or x86_64 binaries from the official release bucket and checks their SHA-512 files. It creates a private daemon and removes only the containers, volume, and temporary files it created.

For a repeat using an already verified local runsc volume, set `RIVET_AUDIT_RUNSC_VOLUME` to that volume name. The script still checks the runsc version at audit startup.

The test builds the audit agent, observer, a native ELF probe, and a Go integration test from this checkout. It first runs the registry test as UID 1000 without host runsc access and requires refusal. It then installs `runsc-gate.go` as a root-owned setuid helper **inside the disposable daemon only**. That helper accepts exactly `--version`, `ps -format=json <container ID>`, or `trace list <container ID>`. The positive test requires a signed gVisor result bound to the artifact and manifest, a zero-drop sink, only supervisor PID 1 at the completion barrier, and kernel-observed network and honey-path events.

The native cases test symlink and procfs aliases followed by `mmap`, an `unshare` attempt, a direct unconnected UDP `sendto`, a Linux `//tmp` honey path, and `openat2`. On the pinned runsc release, `openat2` returns `ENOSYS`, so the probe falls back to a regular honey read and must still certify that observation. A separate package fixture attempts evidence and nonce access and tampers with the writable advisory hook log. Its detached-child variant must fail closed because Node PID 1 cannot reap the adopted zombie. The final run as UID 2000 checks refusal when the registry identity collides with the reserved package probe UID.

This helper is a test tool. A deployment must provision and review its own host-side runsc query mechanism, with the same narrow command scope and the Docker runtime's exact binary and state root.

The gate also provisions the deployment sudo/Python query helper inside the
disposable daemon and repeats the live signed audit as UID 1000. The production
template is described in [the deployment guide](../../docs/registry-deployment.md).
No host sudoers, runtime registration, or Docker permissions are changed.
