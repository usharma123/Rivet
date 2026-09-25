#!/usr/bin/env bash
# End-to-end check: a local Rivet registry mirroring the live npm registry,
# and the CLI porting real npm packages through it. Needs network access,
# Go, Rust and Node.
#
# The whole scenario runs once per placement, each with a fresh registry,
# RIVET_HOME and project: "tmp" (the system temp directory) and "home" (a
# directory under $HOME, where the sandbox hides home contents and must still
# allow the project). Choose with RIVET_E2E_PLACEMENTS="tmp home".
#
# Usage: tools/e2e/npm-port.sh
#   RIVET_E2E_KEEP=1          keep work directories
#   RIVET_E2E_BENCH_OUT=file  append run-time benchmark results (JSON lines)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PORT=${RIVET_E2E_PORT:-18181}
PLACEMENTS=${RIVET_E2E_PLACEMENTS:-tmp home}
BUILD=$(mktemp -d "${TMPDIR:-/tmp}/rivet-e2e-build.XXXXXX")
WORKS=("$BUILD")
REGISTRY_PID=""

cleanup() {
  stop_registry
  for dir in "${WORKS[@]}"; do
    chmod -R u+w "$dir" 2>/dev/null || true
    if [[ -z "${RIVET_E2E_KEEP:-}" ]]; then rm -rf "$dir"; else echo "kept $dir"; fi
  done
}
trap cleanup EXIT

step() { printf '\n==> [%s] %s\n' "${PLACEMENT:-build}" "$*"; }
fail() { printf 'FAIL [%s]: %s\n' "${PLACEMENT:-build}" "$*" >&2; exit 1; }
expect() { # expect <output> <pattern> <description>
  grep -qE -- "$2" <<<"$1" || { printf '%s\n' "$1" >&2; fail "$3 (missing /$2/)"; }
}

start_registry() {
  RIVET_STORE=memory RIVET_DATA_DIR="$WORK/registry" RIVET_REGISTRY_TOKEN=e2e-token \
    RIVET_ADMIN_TOKEN=e2e-admin RIVET_ADDR="127.0.0.1:$PORT" \
    "$BUILD/rivet-registry" >>"$WORK/registry.log" 2>&1 &
  REGISTRY_PID=$!
  for _ in $(seq 50); do
    curl -fs "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  cat "$WORK/registry.log" >&2
  fail "registry did not start"
}

stop_registry() {
  if [[ -n "$REGISTRY_PID" ]]; then
    kill "$REGISTRY_PID" 2>/dev/null || true
    wait "$REGISTRY_PID" 2>/dev/null || true
    REGISTRY_PID=""
  fi
}

# Times `rivet run` (which verifies and re-hashes the whole installed tree)
# against running the same entry point with plain node. The first measured run
# follows the scenario's earlier runs and reinstall, so it is not a cold cache.
# ru_maxrss is a child-process high-water mark, not a concurrent tree peak.
bench() {
  local entry=$1; shift
  python3 - "$RIVET" "$entry" "$PLACEMENT" "$@" <<'PY'
import json, os, resource, statistics, subprocess, sys, time
rivet, entry, placement, *args = sys.argv[1:]
def measure(cmd):
    start = time.perf_counter()
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return time.perf_counter() - start
def rss_mib():
    raw = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return raw / (1024 * 1024) if sys.platform == "darwin" else raw / 1024
packages = len(os.listdir("node_modules/.rivet")) - 1
first = measure([rivet, "run", *args])
warm = [measure([rivet, "run", *args]) for _ in range(5)]
rivet_rss = rss_mib()
dry = subprocess.run([rivet, "run", "--json", "--dry-run", *args], check=True, capture_output=True, text=True)
phases = json.loads(dry.stdout)["verify_timings_ms"]
node = [measure(["node", entry, *args[1:]]) for _ in range(5)]
result = {
    "placement": placement, "platform": sys.platform, "packages": packages,
    "command": " ".join(args), "first_run_s": round(first, 3),
    "warm_median_s": round(statistics.median(warm), 3),
    "plain_node_median_s": round(statistics.median(node), 3),
    "max_child_rss_mib": round(rivet_rss, 1),
    "verify_phases_ms": phases,
}
print(json.dumps(result))
out = os.environ.get("RIVET_E2E_BENCH_OUT")
if out:
    with open(out, "a") as handle:
        handle.write(json.dumps(result) + "\n")
PY
}

step "build registry and CLI"
(cd "$ROOT/registry" && go build -o "$BUILD/rivet-registry" ./cmd/server)
(cd "$ROOT/cli" && cargo build --release --quiet)
RIVET="${CARGO_TARGET_DIR:-$ROOT/target}/release/rivet"

run_scenario() {
  step "import a global tool (prettier) and run it sandboxed"
  out=$("$RIVET" import npm:prettier 2>&1)
  expect "$out" "State: active" "prettier imported"
  expect "$out" "Commands: prettier" "prettier command registered"
  mkdir -p "$WORK/scratch" && cd "$WORK/scratch"
  printf 'const   x = {a:1}\n' > t.js
  out=$("$RIVET" run prettier t.js)
  expect "$out" "const x = \{ a: 1 \};" "prettier formats code"

  step "install a real project (137-package tree, native optional deps, peers)"
  mkdir -p "$WORK/app" && cd "$WORK/app"
  "$RIVET" init >/dev/null
  for dep in "eslint@^9" react react-dom vite esbuild semver cowsay; do "$RIVET" add "$dep" >/dev/null; done
  out=$("$RIVET" install 2>&1)
  expect "$out" "Packages: [0-9]{2,}" "dependency tree resolved"
  expect "$out" "Verified provenance: [1-9]" "some packages carry verified provenance"
  expect "$out" "optional packages built for other platforms" "platform-specific optional deps filtered"
  expect "$out" "Install script not run: esbuild" "install scripts are off by default"
  [[ -f rivet.lock ]] || fail "rivet.lock written"

  step "installed packages work with plain Node resolution"
  out=$(node -e "const React=require('react');const {renderToString}=require('react-dom/server');console.log(renderToString(React.createElement('b',null,'ok')))")
  expect "$out" "<b>ok</b>" "react-dom renders"

  step "run executables from the project through the sandbox"
  out=$("$RIVET" run semver 1.2.3 -r '^1.0.0')
  expect "$out" "1.2.3" "semver cli"
  out=$("$RIVET" run cowsay moo)
  expect "$out" "< moo >" "cowsay cli"
  printf 'export default [{ rules: { "no-unused-vars": "error" } }];\n' > eslint.config.js
  printf 'const unused = 1;\n' > bad.js
  set +e; out=$("$RIVET" run eslint bad.js 2>&1); status=$?; set -e
  [[ $status -eq 1 ]] || { echo "$out"; fail "eslint should report a lint error (exit $status)"; }
  expect "$out" "no-unused-vars" "eslint runs with its full dependency tree"
  printf 'import { valid } from "semver"; console.log(valid("1.2.3"));\n' > entry.js
  "$RIVET" run esbuild entry.js --bundle --platform=node --outfile=out.js >/dev/null 2>&1
  expect "$(node out.js)" "1.2.3" "esbuild native binary bundles"
  mkdir -p site && printf '<!doctype html><script type="module">document.body.textContent="hi"</script>\n' > site/index.html
  out=$(cd site && "$RIVET" run --project "$WORK/app" vite build 2>&1)
  expect "$out" "built in" "vite build with native rolldown binding"
  [[ -f site/dist/index.html ]] || fail "vite wrote dist/"

  step "node_modules/.bin shims go through rivet"
  out=$(./node_modules/.bin/semver 2.0.0 -r '>=1')
  expect "$out" "2.0.0" ".bin shim"

  step "verify checks installed files, explicit versions and malformed state"
  out=$("$RIVET" verify semver 2>&1)
  expect "$out" "Installed files and links: [0-9]+ packages verified" "verify re-hashes a project command"
  semver_id=$(python3 -c 'import json; print(json.load(open("rivet.lock"))["roots"]["semver"]["package"])')
  out=$("$RIVET" verify "$semver_id" 2>&1) || { echo "$out"; fail "verify $semver_id inside an installed project"; }
  expect "$out" "Package: $semver_id" "explicit package@version verifies inside a project"
  cp node_modules/.rivet/state.json "$WORK/state.json.bak"
  printf '{not json' > node_modules/.rivet/state.json
  set +e; out=$("$RIVET" verify semver 2>&1); status=$?; set -e
  [[ $status -ne 0 ]] || { echo "$out"; fail "verify must fail on malformed installed state"; }
  cp "$WORK/state.json.bak" node_modules/.rivet/state.json

  step "frozen reinstall from rivet.lock re-verifies every package"
  rm -rf node_modules
  out=$("$RIVET" install --frozen 2>&1)
  expect "$out" "rivet.lock \(re-verified\)" "frozen install used the lockfile"


  step "benchmark rivet run against plain node on the installed tree"
  semver_entry=$(find node_modules/.rivet -path '*node_modules/semver/bin/semver.js' | head -1)
  out=$(bench "$semver_entry" semver 1.2.3 -r '^1.0.0')
  printf '%s\n' "$out"
  expect "$out" '"warm_median_s"' "benchmark recorded"

  step "tampering with an installed file is detected before running"
  target=$(find node_modules/.rivet -path '*node_modules/semver/bin/semver.js' | head -1)
  chmod u+w "$target" && printf '\n// tampered\n' >> "$target"
  set +e; out=$("$RIVET" run semver 1.0.0 2>&1); status=$?; set -e
  [[ $status -ne 0 ]] || fail "tampered package must not run"
  expect "$out" "modified after install" "tamper detected"
  out=$("$RIVET" install 2>&1) || { echo "$out"; fail "reinstall"; }
  expect "$("$RIVET" run semver 1.0.0)" "1.0.0" "install repairs tampering"

  step "native publish, audit and install (@rivet-examples/hello-cli)"
  cd "$ROOT/examples/hello-cli"
  out=$("$RIVET" publish --non-interactive 2>&1)
  expect "$out" "State: active" "hello-cli published and audited"
  cd "$WORK/app" && "$RIVET" add @rivet-examples/hello-cli >/dev/null
  out=$("$RIVET" install 2>&1 || true)
  expect "$out" "cooldown" "a release published seconds ago is held back by the cooldown"
  out=$("$RIVET" install --allow-fresh 2>&1) || { echo "$out"; fail "install --allow-fresh"; }
  expect "$("$RIVET" run hello)" "hello from rivet" "native package runs"

  step "publishing a name that npm already serves needs the admin token"
  mkdir -p "$WORK/shadow/bin" && printf 'console.log(1)\n' > "$WORK/shadow/bin/x.js"
  printf '[package]\nname = "left-pad"\nversion = "9.0.0"\n' > "$WORK/shadow/rivet.toml"
  set +e; out=$(cd "$WORK/shadow" && "$RIVET" publish --non-interactive 2>&1); status=$?; set -e
  [[ $status -ne 0 ]] || fail "shadowing left-pad must be refused"
  expect "$out" "shadow npm" "npm names are protected"

  step "a credential-stealing package is blocked by the registry audit"
  mkdir -p "$WORK/stealer" && cp -R "$ROOT/fixtures/packages/credential-stealer/." "$WORK/stealer/"
  cat > "$WORK/stealer/rivet.toml" <<'TOML'
[package]
name = "e2e-credential-stealer"
version = "0.1.0"

[scripts.postinstall]
command = "node collect.js"
TOML
  out=$(cd "$WORK/stealer" && "$RIVET" publish --non-interactive 2>&1)
  expect "$out" "State: blocked" "stealer blocked"
  "$RIVET" add e2e-credential-stealer >/dev/null
  set +e; out=$("$RIVET" install --allow-fresh 2>&1); status=$?; set -e
  [[ $status -ne 0 ]] || fail "install of a blocked package must fail"
  expect "$out" "blocked" "install refuses blocked package"
  python3 - <<'PY'
import re
p="rivet.toml"; s=open(p).read()
open(p,"w").write(re.sub(r'(?m)^e2e-credential-stealer = .*\n', "", s))
PY

  step "revocation takes effect at run time"
  out=$("$RIVET" revoke @rivet-examples/hello-cli@0.1.0 --reason "e2e revoke" 2>&1) || { echo "$out"; fail "revoke"; }
  set +e; out=$("$RIVET" run hello 2>&1); status=$?; set -e
  [[ $status -ne 0 ]] || fail "revoked package must not run"
  expect "$out" "revoked" "revocation enforced"

  step "offline runs use unexpired cached attestations"
  stop_registry
  cd "$WORK/scratch"
  out=$("$RIVET" run prettier t.js 2>&1)
  expect "$out" "using cached attestations" "offline warning"
  expect "$out" "const x" "offline run works"

  step "a different registry key is rejected"
  out=$(RIVET_REGISTRY_PUBKEY=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= "$RIVET" run prettier t.js 2>&1 || true)
  expect "$out" "pinned registry key" "key pinning enforced"
}

for PLACEMENT in $PLACEMENTS; do
  case "$PLACEMENT" in
    tmp) WORK=$(mktemp -d "${TMPDIR:-/tmp}/rivet-e2e.XXXXXX") ;;
    home) WORK=$(mktemp -d "$HOME/.rivet-e2e.XXXXXX") ;;
    *) fail "unknown placement $PLACEMENT (want tmp or home)" ;;
  esac
  WORKS+=("$WORK")
  start_registry
  export RIVET_HOME="$WORK/home" RIVET_REGISTRY_URL="http://127.0.0.1:$PORT" RIVET_REGISTRY_TOKEN=e2e-token
  unset RIVET_REGISTRY_PUBKEY
  run_scenario
  stop_registry
  printf '\n[%s] all checks passed in %s\n' "$PLACEMENT" "$WORK"
done

printf '\nAll end-to-end checks passed (%s).\n' "$PLACEMENTS"
