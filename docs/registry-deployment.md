# Deploy a small Rivet registry

Start with one dedicated Linux VM, local Postgres, and persistent local storage.
Keep access restricted to your own clients. This avoids paying for a separate
API host, database service, worker fleet, and object store before there is demand.
A 2-vCPU, 4-GB machine is an initial sizing hypothesis for a small pilot, not a
capacity result. Audits need bounded concurrency before public access: the runner
limits each workload, but the registry currently lacks a global audit/import
budget and the packument cache never evicts.

A planning budget of roughly $10–15/month leaves room for a small VM and backups;
check region, tax, IPv4, disk, and traffic charges before ordering. As checked on
2026-09-29, Hetzner lists CX23 at €5.49/month in its updated EU table. This is a
price reference, not a measured Rivet capacity recommendation.
[Hetzner pricing](https://docs.hetzner.com/general/infrastructure-and-availability/price-adjustment/)

## Hosting choices and Railway

| Option | Fit for the current code |
| --- | --- |
| Dedicated Linux VM with local Postgres | Fewest services and direct control of Docker/runsc; you manage updates and backups |
| Linux VM with Railway Postgres | Off-host database operation, with extra usage and network cost; use the externally reachable TLS endpoint |
| Standard Railway service, static audits | The Go registry can run with Postgres and a persistent artifact volume; this does not provide trusted gVisor auditing |
| Railway API plus remote audit VM | Requires a new worker protocol and artifact transfer; the current runner is local |
| Railway Sandboxes | Separate product with Docker; custom runsc, trace support, persistence and lifecycle suitability still need validation |
| Kubernetes | Dedicated configured audit nodes and operational work; unnecessary for the pilot |

Railway's $5 Hobby fee includes $5 of usage; it is not a spending cap. Its
Sandboxes announcement confirms a Docker daemon and internet-only networking,
but does not establish support for this runner's custom runtime and host queries.
[Railway billing](https://docs.railway.com/pricing/understanding-your-bill),
[Railway Sandboxes](https://railway.com/changelog/2026-06-12-docker-in-sandboxes),
[Railway Postgres](https://docs.railway.com/databases/postgresql).

A remote `DOCKER_HOST` alone is insufficient. The current runner bind-mounts local
artifact/evidence paths and queries host runsc state, so those resources must be
on the same host. The simplest supported topology runs the registry binary as a
systemd service beside Docker. Reserve UID 2000 for package probes.

## 1. Choose a tested commit and prepare the host

Use a commit whose `Rivet required checks` succeeded, and retain its source
receipt. On a fresh Linux x64 or arm64 host, install Git, Go at the version in
`registry/go.mod`, Docker Engine, Python 3, sudo, Postgres 16, and a TLS reverse
proxy. Use Docker's official installation instructions for the host distribution.
Do not deploy untrusted PR branches on this host.

Create a system account `rivet-registry` with a UID other than 2000, and directories
`/etc/rivet`, `/var/lib/rivet`, and `/usr/local/libexec`. Keep `/etc/rivet` root-owned
and accessible only to root and the registry group. Give the registry account
ownership of `/var/lib/rivet`. Docker group membership is effectively host-root
access; this is why the audit host should be dedicated.
See [Docker group privileges](https://docs.docker.com/engine/install/linux-postinstall/). The narrow query helper
limits its sudo interface but does not remove the broader Docker privilege.

Create a Postgres database and role named `rivet`. Bind local Postgres to loopback,
and use a generated password. For remote Postgres, use its certificate-verified
TLS connection configuration instead of the local `sslmode=disable` example.
The registry runs schema migrations on startup. Legacy rows without signed tree
digests cause startup refusal; do not delete a production database to bypass it.

## 2. Install the exact gVisor runtime

Rivet currently requires `runsc version release-20260601.0`. Newer releases are
not automatically accepted because trace schemas are part of the trust boundary.
Download `runsc`, `containerd-shim-runsc-v1`, and both `.sha512` files from:

```text
https://storage.googleapis.com/gvisor/releases/release/20260601.0/x86_64/
https://storage.googleapis.com/gvisor/releases/release/20260601.0/aarch64/
```

Select the host architecture, verify both checksums, and install the executables
root-owned mode 0755 in `/usr/local/bin`. Register Docker runtime `runsc` using
that binary and `--allow-flag-override` so Rivet's per-workload
`dev.gvisor.flag.pod-init-config` annotation is accepted. Merge the following into
the daemon configuration; do not replace unrelated settings:

```json
{
  "runtimes": {
    "runsc": {
      "path": "/usr/local/bin/runsc",
      "runtimeArgs": ["--allow-flag-override"]
    }
  }
}
```

Restart Docker during host setup and verify `docker info` lists `runsc`. Verify
`runsc --version` reports the pinned release. Docker's runsc state root must match
`/var/run/docker/runtime-runc/moby`; custom roots require an explicit reviewed
change to both the helper and configuration.
[gVisor Docker setup](https://gvisor.dev/docs/user_guide/quick_start/docker/),
[gVisor host state](https://gvisor.dev/docs/user_guide/observability/).

## 3. Provision the restricted trace query

The templates in `tools/deploy/` use sudo and an isolated Python entrypoint, not
the setuid Go helper used inside the disposable integration test. Install from
your tested checkout:

```sh
sudo install -o root -g root -m 0755 tools/deploy/runsc-query.py /usr/local/libexec/rivet-runsc-query.py
sudo install -o root -g root -m 0755 tools/deploy/rivet-runsc-query /usr/local/bin/rivet-runsc-query
```

Use `sudo visudo -f /etc/sudoers.d/rivet-runsc-query` to add exactly:

```text
rivet-registry ALL=(root) NOPASSWD: /usr/local/libexec/rivet-runsc-query.py
```

The helper accepts only `--version`, `ps -format=json <64-hex-container-id>`, and
`trace list <64-hex-container-id>`, with the fixed state root. It rejects other
flags and commands, and replaces the inherited environment before exec. Keep the
script, wrapper, runtime binary, and their parent directories root-owned and
unwritable by the registry account. Validate sudoers with `visudo -c`.

Test as the service account:

```sh
sudo -u rivet-registry /usr/local/bin/rivet-runsc-query --version
sudo -u rivet-registry /usr/local/bin/rivet-runsc-query --root=/tmp trace list bad
```

The first must report the pinned runtime; the second must fail. This alone does
not prove that a real audit can query Docker's running sandbox. Verify that in
step 6. Do not add `NoNewPrivileges=true` to the service while using this sudo
helper. Do not use `PrivateTmp=true`; Docker needs the same host-visible temporary
paths as the registry process.

## 4. Build and configure

On the selected checkout:

```sh
(cd registry && go build -trimpath -o ../rivet-registry ./cmd/server)
sudo install -o root -g root -m 0755 rivet-registry /usr/local/bin/rivet-registry
revision=$(git rev-parse HEAD)
docker build -f audit-agent/Dockerfile -t "rivet-audit-agent:$revision" audit-agent
docker build -f audit-agent/Dockerfile.observer -t "rivet-audit-observer:$revision" audit-agent
```

Record the commit, binary SHA-256, and both image IDs. Copy
`tools/deploy/registry.env.example` to `/etc/rivet/registry.env`, make it root-owned
mode 0600, and replace every placeholder. Set both image references to the commit
tags just built, or their immutable local image IDs.

Generate one Ed25519 seed as 32 random bytes encoded in base64. Store it in
`/etc/rivet/signing.key`, readable by the registry account only through its group,
mode 0640. Generate two distinct random tokens of at least 32 characters for
`RIVET_REGISTRY_TOKEN` and `RIVET_ADMIN_TOKEN`. A local helper command for each token
is `openssl rand -hex 32`; for the key seed use `openssl rand -base64 32`. Avoid
printing these into CI logs or committing them. Back up the signing key securely.
Replacing it silently breaks clients' pinned trust identity.

Required settings are production mode, Postgres connection, persistent artifact
path, signing-key path, publisher token, audit images, and the runsc helper.
Keep `RIVET_PUBLIC_MIRROR=false`, provenance verification enabled, and
`RIVET_AUDIT_MODE=gvisor`. A static-only Railway pilot must explicitly use
`RIVET_AUDIT_MODE=static` and describe that limit to clients.

## 5. Start privately and add TLS

Install `tools/deploy/rivet-registry.service` in `/etc/systemd/system/`, then run:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now rivet-registry
sudo systemctl status rivet-registry
curl --fail http://127.0.0.1:8080/healthz
curl --fail http://127.0.0.1:8080/v1/keys
```

Put the reverse proxy in front of `127.0.0.1:8080`, terminate TLS, and restrict
inbound client access by VPN or an IP allowlist during the pilot. Keep Postgres
and Docker ports off the public internet. The registry token protects mutations;
metadata and artifact reads are not private by default. An external access
boundary is required if package contents are private.

Limit concurrent requests at the reverse proxy and keep one operator issuing
new imports initially. Request limits alone are not a global audit budget:
one dependency resolution can import many releases. Public mirroring should
remain disabled until the application has global concurrency, memory and cache
limits. Monitor disk use before enabling large dependency imports.

For a Railway static pilot, mount a volume at `/var/lib/rivet`, supply the
production variables and signing seed as a secret, set `RIVET_ADDR` to the port
configured in Railway, and connect Postgres. The server does not automatically
read Railway's `PORT` variable. `/healthz` is a liveness endpoint, not a continuous
database, artifact-store or audit readiness test.

## 6. Verify the deployment end to end

- Check `/v1/keys` against the expected key out of band before pinning trust.
- Confirm an unauthenticated `POST /v1/import/npm` is refused.
- Import a known benign package with the publisher token. Inspect its signed
  attestation and require a completed audit with `sandbox_runtime=gvisor`.
- Run the controlled native/tamper fixtures on the new host. The disposable
  `tools/e2e/audit-trace.sh` proves host runtime capability, but also exercise the
  deployed service account and helper against its configured Docker daemon.
- From a client, install and run a known CLI with the runtime sandbox enabled.
  Confirm tampered bytes are refused; do not use unsafe bypass flags as a smoke test.
- Restart the service and verify the same key, release, artifact and client lock
  still work. CI's `tools/e2e/production.py` covers the static/Postgres persistence
  path against a disposable database; never point that test at production.

Some legitimate packages will fail strict gVisor probes, particularly packages
that need dependencies during probes or leave detached children. Record those
refusals. They are not permission to silently switch to static auditing.

## 7. Backups, upgrades and operating cost

Back up all three together: Postgres, `/var/lib/rivet/artifacts`, and the signing
key. Also retain the deployment configuration and image/binary identities.
For a small pilot, briefly stop imports while taking a consistent database and
artifact backup. Encrypt backups, copy them off-host, and test a restore into a
separate environment. A database backup without the artifacts or signing key is
not a complete registry recovery plan.

Monitor free disk, memory, HTTP failures, audit duration/refusals, Postgres health,
and backup age. Configure provider budget alerts. Keep the audit worker on the
fixed-size VM with no autoscaling. Do not prune artifacts still referenced by
release records or clients' locks. Keep a modest log retention period.

Upgrade only after CI passes, take a backup, deploy immutable images and binary,
and repeat the smoke checks. Check migration compatibility before rolling back
an older binary. Do not automatically deploy PRs or publish releases from this
validation workflow. Move Postgres off-host or split audit workers only when
measured load or availability requirements justify the extra components.
