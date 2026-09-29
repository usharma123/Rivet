#!/usr/bin/env bash
# Exercise the audit collector against a disposable Docker daemon with runsc.
# The setup never changes the host Docker daemon's runtime configuration.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
DAEMON="rivet-audit-live-$$"
OWN_VOLUME=""
RUNSC_VOLUME="${RIVET_AUDIT_RUNSC_VOLUME:-}"

cleanup() {
  docker rm -f "$DAEMON" >/dev/null 2>&1 || true
  if [[ -n "$OWN_VOLUME" ]]; then docker volume rm "$OWN_VOLUME" >/dev/null 2>&1 || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT

case "$(uname -m)" in
  arm64|aarch64) RELEASE_ARCH=aarch64; GO_ARCH=arm64 ;;
  x86_64) RELEASE_ARCH=x86_64; GO_ARCH=amd64 ;;
  *) echo "gVisor audit test needs arm64 or x86_64" >&2; exit 1 ;;
esac

if [[ -z "$RUNSC_VOLUME" ]]; then
  RUNSC_VOLUME="rivet-audit-runsc-$$"
  OWN_VOLUME="$RUNSC_VOLUME"
  docker volume create "$RUNSC_VOLUME" >/dev/null
  RELEASE="https://storage.googleapis.com/gvisor/releases/release/20260601.0/$RELEASE_ARCH"
  for binary in runsc containerd-shim-runsc-v1; do
    curl -fsSL "$RELEASE/$binary" -o "$WORK/$binary"
    curl -fsSL "$RELEASE/$binary.sha512" -o "$WORK/$binary.sha512"
    (cd "$WORK" && shasum -a 512 -c "$binary.sha512")
  done
  docker run --rm -v "$RUNSC_VOLUME:/out" -v "$WORK:/in:ro" busybox:1.37.0 \
    sh -c 'cp /in/runsc /in/containerd-shim-runsc-v1 /out/ && chmod 755 /out/runsc /out/containerd-shim-runsc-v1'
fi

cat > "$WORK/runsc-wrapper" <<'EOF'
#!/bin/sh
exec /runsc/runsc --allow-flag-override "$@"
EOF
chmod 755 "$WORK/runsc-wrapper"
docker run -d --privileged --name "$DAEMON" \
  -v "$RUNSC_VOLUME:/runsc:ro" \
  -v "$WORK/runsc-wrapper:/usr/local/bin/runsc-rivet:ro" \
  docker:29-dind --host=unix:///var/run/docker.sock --tls=false \
  --add-runtime runsc=/usr/local/bin/runsc-rivet >/dev/null

for attempt in $(seq 1 60); do
  if docker exec "$DAEMON" docker info >/dev/null 2>&1; then break; fi
  if [[ "$attempt" == 60 ]]; then echo "isolated Docker daemon did not start" >&2; exit 1; fi
  sleep 1
done

tar -C "$ROOT/audit-agent" -cf - Dockerfile agent.js egress-hook.js |
  docker exec -i "$DAEMON" docker build -q -t rivet-audit-agent:local -f Dockerfile - >/dev/null
tar -C "$ROOT/audit-agent" -cf - Dockerfile.observer observer.py |
  docker exec -i "$DAEMON" docker build -q -t rivet-audit-observer:local -f Dockerfile.observer - >/dev/null

(cd "$ROOT/registry" && GOOS=linux GOARCH="$GO_ARCH" CGO_ENABLED=0 \
  go test -c -o "$WORK/audit.test" ./internal/audit)
GOOS=linux GOARCH="$GO_ARCH" CGO_ENABLED=0 \
  go build -o "$WORK/runsc-gate" "$ROOT/tools/e2e/runsc-gate.go"
GOOS=linux GOARCH="$GO_ARCH" CGO_ENABLED=0 \
  go build -o "$WORK/audit-native" "$ROOT/tools/e2e/audit-native.go"

docker cp "$WORK/audit.test" "$DAEMON:/usr/local/bin/audit.test"
docker cp "$WORK/audit-native" "$DAEMON:/usr/local/bin/audit-native"
docker cp "$WORK/runsc-gate" "$DAEMON:/usr/local/bin/rivet-runsc-gate"
docker exec "$DAEMON" sh -c 'chown root:root /usr/local/bin/rivet-runsc-gate && chmod 4755 /usr/local/bin/rivet-runsc-gate && chmod 755 /usr/local/bin/audit.test /usr/local/bin/audit-native && chmod 666 /var/run/docker.sock'
docker exec "$DAEMON" sh -c 'uname -m; /runsc/runsc --version; sha256sum /runsc/runsc /usr/local/bin/rivet-runsc-gate; docker image inspect --format "{{.Id}}" rivet-audit-agent:local rivet-audit-observer:local'

# A non-root registry process cannot inspect host runsc state without the
# narrowly scoped helper. Require the test to fail before running the gate.
if docker exec --user 1000:1000 -e RIVET_AUDIT_LIVE=1 "$DAEMON" \
  /usr/local/bin/audit.test -test.run '^TestDockerRunnerLive$' -test.v > "$WORK/no-helper.log" 2>&1; then
  echo "audit unexpectedly certified without the host runsc helper" >&2
  cat "$WORK/no-helper.log" >&2
  exit 1
fi
if ! grep -Eq 'host gVisor|runsc|permission denied' "$WORK/no-helper.log"; then
  echo "no-helper failure was unrelated to runsc access" >&2
  cat "$WORK/no-helper.log" >&2
  exit 1
fi
echo "no-helper run: refused"
grep -m1 -E 'host gVisor|runsc|permission denied' "$WORK/no-helper.log"

docker exec --user 1000:1000 \
  -e RIVET_AUDIT_LIVE=1 \
  -e RIVET_AUDIT_TEST_RUNSC_BIN=/usr/local/bin/rivet-runsc-gate \
  -e RIVET_AUDIT_NATIVE_BINARY=/usr/local/bin/audit-native \
  "$DAEMON" /usr/local/bin/audit.test -test.run '^TestDockerRunner(Live|NativeGuardsLive|PackageTamperLive)$' -test.v

docker exec --user 2000:2000 \
  -e RIVET_AUDIT_LIVE=1 \
  -e RIVET_AUDIT_TEST_RUNSC_BIN=/usr/local/bin/rivet-runsc-gate \
  "$DAEMON" /usr/local/bin/audit.test -test.run '^TestDockerRunnerUIDCollisionLive$' -test.v

# Exercise the deployment sudo/Python helper separately from the test-only
# setuid helper. All provisioning is inside this disposable daemon.
docker exec "$DAEMON" apk add --no-cache python3 sudo >/dev/null
docker exec "$DAEMON" sh -c 'adduser -D -u 1000 rivet-registry && mkdir -p /usr/local/libexec && ln -s /runsc/runsc /usr/local/bin/runsc'
docker cp "$ROOT/tools/deploy/runsc-query.py" "$DAEMON:/usr/local/libexec/rivet-runsc-query.py"
docker cp "$ROOT/tools/deploy/rivet-runsc-query" "$DAEMON:/usr/local/bin/rivet-runsc-query"
docker exec "$DAEMON" sh -c 'chown root:root /usr/local/libexec/rivet-runsc-query.py /usr/local/bin/rivet-runsc-query && chmod 755 /usr/local/libexec/rivet-runsc-query.py /usr/local/bin/rivet-runsc-query && printf "%s\n" "rivet-registry ALL=(root) NOPASSWD: /usr/local/libexec/rivet-runsc-query.py" > /etc/sudoers.d/rivet-runsc-query && chmod 440 /etc/sudoers.d/rivet-runsc-query && visudo -c'
docker exec --user 1000:1000 \
  -e RIVET_AUDIT_LIVE=1 \
  -e RIVET_AUDIT_TEST_RUNSC_BIN=/usr/local/bin/rivet-runsc-query \
  "$DAEMON" /usr/local/bin/audit.test -test.run '^TestDockerRunnerLive$' -test.v
