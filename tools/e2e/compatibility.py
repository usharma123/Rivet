#!/usr/bin/env python3
"""Signed peer fixtures and one-lock macOS/Linux frozen install checks.

The fixture upstream speaks npm's packument/tarball protocol. Rivet's normal
registry imports, audits and signs each release. Unknown packages are fetched
from the public npm registry so the portable case uses real esbuild artifacts.
"""

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import platform
from pathlib import Path
import shutil
import socket
import subprocess
import tarfile
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import unquote
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
TARGETS = {"darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64"}
HOST_TARGET = ("darwin" if platform.system() == "Darwin" else "linux") + "-" + ("arm64" if platform.machine() in ("arm64", "aarch64") else "x64")
EVIDENCE = None
CONTAINERS = []
PACKAGES = {
    "compat-core": {
        "1.0.0": ({}, "module.exports = {version: '1.0.0'};\n"),
        "2.0.0": ({}, "module.exports = {version: '2.0.0'};\n"),
    },
    "compat-plugin": {
        "1.0.0": ({"peerDependencies": {"compat-core": ">=1 <3"}},
                  "module.exports = require('compat-core').version;\n"),
    },
    "compat-parent-one": {
        "1.0.0": ({"dependencies": {"compat-core": "^1", "compat-plugin": "^1"}},
                  "module.exports = require('compat-plugin');\n"),
    },
    "compat-parent-two": {
        "1.0.0": ({"dependencies": {"compat-core": "^2", "compat-plugin": "^1"}},
                  "module.exports = require('compat-plugin');\n"),
    },
    "compat-wide": {
        "1.0.0": ({"peerDependencies": {"compat-core": ">=1 <3"}},
                  "module.exports = require('compat-core').version;\n"),
    },
    "compat-narrow": {
        "1.0.0": ({"peerDependencies": {"compat-core": ">=2 <3"}},
                  "module.exports = require('compat-core').version;\n"),
    },
    "compat-optional": {
        "1.0.0": ({"peerDependencies": {"compat-core": "^1"},
                   "peerDependenciesMeta": {"compat-core": {"optional": True}}},
                  "module.exports = (() => { try { return require('compat-core').version }"
                  " catch (e) { if (e.code === 'MODULE_NOT_FOUND') return 'absent'; throw e } })();\n"),
    },
    "compat-bad": {
        "1.0.0": ({"peerDependencies": {"compat-core": "^2"}},
                  "module.exports = require('compat-core').version;\n"),
    },
    "compat-parent-bad": {
        "1.0.0": ({"dependencies": {"compat-core": "^1", "compat-bad": "^1"}},
                  "module.exports = require('compat-bad');\n"),
    },
    "compat-cycle-a": {
        "1.0.0": ({"dependencies": {"compat-cycle-b": "^1"},
                   "peerDependencies": {"compat-core": "^1"}},
                  "module.exports = {peer: require('compat-core').version,"
                  "other: () => require('compat-cycle-b').tag, tag: 'a'};\n"),
    },
    "compat-cycle-b": {
        "1.0.0": ({"dependencies": {"compat-cycle-a": "^1"}},
                  "module.exports = {tag: 'b', other: () => require('compat-cycle-a').tag};\n"),
    },
    "compat-overlap": {
        "1.0.0": ({"dependencies": {"compat-core": "^2"},
                   "optionalDependencies": {"compat-core": "npm:rivet-compat-missing-7c815b@1.0.0"},
                   "peerDependencies": {"compat-core": "^2"}},
                  "module.exports = 'optional edge skipped';\n"),
    },
}


def command(args, *, cwd=None, env=None, ok=True, timeout=180):
    try:
        result = subprocess.run([str(x) for x in args], cwd=cwd, env=env,
                                text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        captured = error.stdout or b""
        if isinstance(captured, bytes):
            captured = captured.decode(errors="replace")
        if EVIDENCE is not None:
            with EVIDENCE.open("a") as log:
                log.write(f"$ {' '.join(map(str, args))}\ncwd={cwd or Path.cwd()}\n"
                          f"TIMEOUT after {timeout}s\n{captured}\n")
        raise AssertionError(f"command timed out after {timeout}s: {' '.join(map(str, args))}\n"
                             f"{captured}") from error
    if EVIDENCE is not None:
        with EVIDENCE.open("a") as log:
            log.write(f"$ {' '.join(map(str, args))}\ncwd={cwd or Path.cwd()}\n"
                      f"exit={result.returncode}\n{result.stdout}\n")
    if (result.returncode == 0) != ok:
        raise AssertionError(f"command exit {result.returncode}, expected {'success' if ok else 'failure'}:\n"
                             f"{' '.join(map(str, args))}\n{result.stdout}")
    return result.stdout


def check(value, reason):
    if not value:
        raise AssertionError(reason)


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def tarball(manifest, code):
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w") as archive:
            for name, body in (("package.json", json.dumps(manifest, sort_keys=True).encode()),
                               ("index.js", code.encode())):
                item = tarfile.TarInfo(f"package/{name}")
                item.size = len(body)
                item.mode = 0o644
                item.mtime = 0
                archive.addfile(item, io.BytesIO(body))
    return output.getvalue()


class Upstream(BaseHTTPRequestHandler):
    server: ThreadingHTTPServer

    def log_message(self, *_args):
        return

    def do_GET(self):
        path = unquote(self.path.split("?", 1)[0]).lstrip("/")
        name = path.split("/-/", 1)[0]
        if name in PACKAGES:
            versions = {}
            times = {}
            for version, (extra, code) in PACKAGES[name].items():
                manifest = {"name": name, "version": version, "main": "index.js", **extra}
                artifact = tarball(manifest, code)
                file = f"{name}-{version}.tgz"
                self.server.tarballs[f"{name}/-/{file}"] = artifact
                versions[version] = {
                    **manifest,
                    "dist": {"tarball": f"http://127.0.0.1:{self.server.server_port}/{name}/-/{file}",
                             "integrity": "sha512-" + base64.b64encode(hashlib.sha512(artifact).digest()).decode()},
                }
                times[version] = "2020-01-01T00:00:00Z"
            if path in self.server.tarballs:
                self.send_bytes(self.server.tarballs[path], "application/octet-stream")
            else:
                self.send_json({"name": name, "dist-tags": {"latest": sorted(versions)[-1]},
                                "versions": versions, "time": times})
            return
        upstream = f"https://registry.npmjs.org/{self.path.lstrip('/')}"
        try:
            with urlopen(Request(upstream, headers={"Accept": "application/json"}), timeout=90) as response:
                body, kind = response.read(), response.headers.get("Content-Type", "application/octet-stream")
            if "/-/" not in path:
                data = json.loads(body)
                for meta in data.get("versions", {}).values():
                    url = meta.get("dist", {}).get("tarball", "")
                    meta["dist"]["tarball"] = url.replace("https://registry.npmjs.org",
                                                           f"http://127.0.0.1:{self.server.server_port}")
                body, kind = json.dumps(data).encode(), "application/json"
            self.send_bytes(body, kind)
        except HTTPError as error:
            self.send_error(error.code, error.reason)

    def send_json(self, value):
        self.send_bytes(json.dumps(value).encode(), "application/json")

    def send_bytes(self, body, kind):
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RegistryProxy(BaseHTTPRequestHandler):
    server: ThreadingHTTPServer

    def log_message(self, *_args):
        return

    def request(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.requests.append({"phase": self.server.phase, "method": self.command,
                                     "path": self.path})
        headers = {key: value for key, value in self.headers.items()
                   if key.lower() not in {"host", "content-length", "connection"}}
        request = Request(f"http://127.0.0.1:{self.server.backend}{self.path}",
                          data=body if self.command == "POST" else None,
                          headers=headers, method=self.command)
        try:
            response = urlopen(request, timeout=180)
        except HTTPError as error:
            response = error
        with response:
            data = response.read()
            self.send_response(response.status)
            self.send_header("Content-Type", response.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    do_GET = request
    do_POST = request


def serve(handler, address):
    server = ThreadingHTTPServer(address, handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def manifest(project, dependencies):
    lines = ['[package]', f'name = "{project.name}"', 'version = "1.0.0"', '',
             '[policy]', 'min_release_age_hours = 0', '', '[dependencies]']
    lines.extend(f'{name} = {json.dumps(spec)}' for name, spec in dependencies.items())
    project.mkdir()
    (project / "rivet.toml").write_text("\n".join(lines) + "\n")


def locked(project):
    data = (project / "rivet.lock").read_bytes()
    value = json.loads(data)
    check(value["version"] == 3 and set(value["variants"]) == TARGETS,
          "expected all four v3 target variants")
    return data, value


def lock_sha(project, label):
    digest = hashlib.sha256((project / "rivet.lock").read_bytes()).hexdigest()
    print(f"{label} lock sha256 {digest}")
    return digest


def node(project, expression):
    return command(["node", "-e", expression], cwd=project).strip()


def peer_cases(base, rivet, env):
    print("==> signed fixture: two peer contexts, aliases and cold store")
    project = base / "contexts"
    manifest(project, {"one": "npm:compat-parent-one@1.0.0",
                       "two": "npm:compat-parent-two@1.0.0"})
    output = command([rivet, "install"], cwd=project, env=env)
    check("resolved via registry" in output, output)
    first_bytes, lock = locked(project)
    first_sha = lock_sha(project, "fixture original")
    variant = lock["variants"][HOST_TARGET]
    plugins = [(key, pkg) for key, pkg in variant["packages"].items()
               if pkg["name"] == "compat-plugin"]
    check(len(plugins) == 2 and all("__peers_" in key for key, _ in plugins),
          f"expected two contextual plugin instances, got {[key for key, _ in plugins]}")
    bindings = {pkg["peer_bindings"]["compat-core"] for _, pkg in plugins}
    check(len(bindings) == 2, f"expected distinct signed providers, got {bindings}")
    check(node(project, "console.log(require('one') + ',' + require('two'))") == "1.0.0,2.0.0",
          "Node did not load both expected peer contexts")
    def verify_contexts(active_env):
        for target, release in (
            *((instance, "compat-plugin@1.0.0") for instance, _ in plugins),
            ("compat-plugin@1.0.0", "compat-plugin@1.0.0"),
            ("one", "compat-parent-one@1.0.0"),
        ):
            output = command([rivet, "verify", target], cwd=project, env=active_env)
            check(f"Installed files and links: {len(variant['packages'])} packages verified" in output,
                  f"contextual verify did not check full installed graph: {output}")
            check(f"Package: {release}" in output,
                  f"verify {target} selected the wrong signed release: {output}")

    verify_contexts(env)
    shutil.rmtree(project / "node_modules")
    cold = dict(env, RIVET_HOME=str(base / "cold-home"))
    output = command([rivet, "install", "--frozen"], cwd=project, env=cold)
    check("rivet.lock (re-verified)" in output, output)
    check((project / "rivet.lock").read_bytes() == first_bytes, "cold frozen install changed lock bytes")
    check(lock_sha(project, "fixture cold frozen") == first_sha, "cold lock digest changed")
    check(node(project, "console.log(require('one') + ',' + require('two'))") == "1.0.0,2.0.0",
          "cold store changed Node peer resolution")
    verify_contexts(cold)

    print("==> signed fixture: forged peer binding rejected")
    shutil.rmtree(project / "node_modules")
    forged = json.loads(first_bytes)
    plugins = [(key, pkg) for key, pkg in forged["variants"][HOST_TARGET]["packages"].items()
               if pkg["name"] == "compat-plugin"]
    plugins[0][1]["peer_bindings"]["compat-core"] = plugins[1][1]["peer_bindings"]["compat-core"]
    (project / "rivet.lock").write_text(json.dumps(forged, indent=2) + "\n")
    output = command([rivet, "install", "--frozen"], cwd=project, env=cold, ok=False)
    check("forged" in output or "peer binding" in output, f"wrong frozen failure: {output}")
    (project / "rivet.lock").write_bytes(first_bytes)

    print("==> signed fixture: compatible peer range intersection")
    project = base / "intersection"
    manifest(project, {"compat-wide": "1.0.0", "compat-narrow": "1.0.0"})
    command([rivet, "install"], cwd=project, env=env)
    check(node(project, "console.log(require('compat-wide') + ',' + require('compat-narrow'))")
          == "2.0.0,2.0.0", "intersection did not select core 2")

    print("==> signed fixture: optional peer absent and present")
    for label, dependencies, expected in (
        ("optional-absent", {"compat-optional": "1.0.0"}, "absent"),
        ("optional-present", {"compat-optional": "1.0.0", "compat-core": "1.0.0"}, "1.0.0"),
    ):
        project = base / label
        manifest(project, dependencies)
        command([rivet, "install"], cwd=project, env=env)
        check(node(project, "console.log(require('compat-optional'))") == expected,
              f"{label} Node result differs from {expected}")
        _, lock = locked(project)
        optional = [pkg for pkg in lock["variants"][HOST_TARGET]["packages"].values()
                    if pkg["name"] == "compat-optional"]
        check(len(optional) == 1, f"{label}: optional consumer missing")
        check(bool(optional[0].get("peer_bindings")) == (expected != "absent"),
              f"{label}: wrong peer binding")

    print("==> signed fixture: incompatible provider rejected")
    project = base / "conflict"
    manifest(project, {"compat-parent-bad": "1.0.0"})
    output = command([rivet, "install"], cwd=project, env=env, ok=False)
    check("incompatible provider" in output or "no coherent provider" in output,
          f"wrong conflict failure: {output}")

    print("==> signed fixture: peer binding through a dependency cycle")
    project = base / "cycle"
    manifest(project, {"compat-cycle-a": "1.0.0", "compat-core": "1.0.0"})
    command([rivet, "install"], cwd=project, env=env)
    check(node(project, "const a=require('compat-cycle-a');"
                        "console.log(a.peer + ',' + a.other())") == "1.0.0,b",
          "Node could not load the signed cyclic peer graph")

    print("==> signed fixture: optional alias takes precedence over dependency and peer")
    project = base / "overlap"
    manifest(project, {"compat-overlap": "1.0.0"})
    command([rivet, "install"], cwd=project, env=env)
    check(node(project, "console.log(require('compat-overlap'))") == "optional edge skipped",
          "optional failure prevented Node from loading consumer")
    _, lock = locked(project)
    for variant in lock["variants"].values():
        check(all(pkg["name"] != "rivet-compat-missing-7c815b"
                  for pkg in variant["packages"].values()),
              "missing optional package was retained in lock")


def linux(base, project, env, expression, docker_image, root, *, resolve_count, expected_sha):
    # The Linux CLI and install tree use native container storage. Docker
    # Desktop's macOS bind mount rejects chmod on staged package files.
    # Transfer the exact manifest/lock bytes and leave node_modules per host.
    case = project.resolve()
    script = f'''
set -euo pipefail
mkdir -p /home/rivet/work /home/rivet/case
tar -C /src --exclude=./target --exclude=./tmp --exclude=node_modules --exclude=.git -cf - . | tar -C /home/rivet/work -xf -
cd /home/rivet/work
cargo build -p rivet --release --locked --quiet
cp /exchange/rivet.toml /exchange/rivet.lock /home/rivet/case/
cd /home/rivet/case
sha256sum rivet.lock
/home/rivet/target/release/rivet install --frozen
sha256sum rivet.lock
node -e {json.dumps(expression)}
'''
    container = f"rivet-compat-{base.name}-linux"
    CONTAINERS.append(container)
    args = ["docker", "run", "--rm", "--name", container,
            "--privileged", "--user", "rivet",
            "-v", f"{root}:/src:ro", "-v", f"{case}:/exchange:ro",
            "-v", "rivet-linux-cargo:/home/rivet/.cargo/registry",
            "-v", "rivet-linux-target:/home/rivet/target",
            "-e", "CARGO_TARGET_DIR=/home/rivet/target",
            "-e", "CARGO_HOME=/home/rivet/.cargo",
            "-e", "RIVET_HOME=/home/rivet/compat-home",
            "-e", f"RIVET_REGISTRY_URL={env['RIVET_REGISTRY_URL']}",
            "-e", f"RIVET_REGISTRY_TOKEN={env['RIVET_REGISTRY_TOKEN']}",
            docker_image, "bash", "-c", script]
    output = command(args, timeout=1200)
    check("rivet.lock (re-verified)" in output, output)
    check("NATIVE_OK linux-arm64" in output, output)
    check(output.count(expected_sha) == 2, f"Linux native lock bytes changed: {output}")
    check(resolve_count() == 0, "Linux frozen install called /v1/npm/resolve")


def portable_case(base, rivet, env, proxy, args):
    results = {"targets_checked_live": ["darwin-arm64", "linux-arm64"]}
    print("==> real npm: macOS arm64 lock and native esbuild")
    proxy.phase = "mac_initial_resolve"
    project = base / "portable"
    manifest(project, {"esbuild": "0.25.0"})
    command([rivet, "install"], cwd=project, env=env)
    original, lock = locked(project)
    original_sha = lock_sha(project, "Mac original")
    results["mac_origin_lock_sha256"] = original_sha
    for target in ("darwin-arm64", "linux-arm64"):
        variant = lock["variants"][target]
        check(not variant.get("unsupported"), f"{target} unexpectedly unsupported")
        native = {pkg["name"] for pkg in variant["packages"].values()
                  if pkg["name"].startswith("@esbuild/")}
        expected = "@esbuild/darwin-arm64" if target.startswith("darwin") else "@esbuild/linux-arm64"
        check(expected in native, f"{target} lacks native {expected}: {native}")
    expression = "const e=require('esbuild');const x=e.transformSync('let answer: number = 42', {loader:'ts'}).code;if(!x.includes('42'))throw Error(x);console.log('NATIVE_OK '+process.platform+'-'+process.arch)"
    native = node(project, expression)
    check("NATIVE_OK darwin-arm64" in native, "Mac esbuild native binary failed")
    results["mac_initial_native"] = native

    def no_resolves(phase):
        return sum(request["phase"] == phase and request["path"].startswith("/v1/npm/resolve")
                   for request in proxy.requests)

    print("==> real npm: same lock on Linux arm64, then macOS arm64")
    proxy.phase = "linux_frozen_from_mac"
    linux(base, project, env, expression, args.docker_image, ROOT,
          resolve_count=lambda: no_resolves("linux_frozen_from_mac"),
          expected_sha=original_sha)
    results["linux_frozen_from_mac_resolves"] = no_resolves("linux_frozen_from_mac")
    check((project / "rivet.lock").read_bytes() == original, "Linux frozen install changed lock bytes")
    check(lock_sha(project, "Linux frozen") == original_sha, "Linux lock digest changed")
    shutil.rmtree(project / "node_modules")
    proxy.phase = "mac_frozen_return"
    output = command([rivet, "install", "--frozen"], cwd=project, env=env)
    check("rivet.lock (re-verified)" in output and no_resolves("mac_frozen_return") == 0,
          "Mac frozen install resolved or did not use lock")
    results["mac_frozen_return_resolves"] = no_resolves("mac_frozen_return")
    check((project / "rivet.lock").read_bytes() == original, "Mac frozen install changed lock bytes")
    check(lock_sha(project, "Mac return frozen") == original_sha, "Mac lock digest changed")
    native = node(project, expression)
    check("NATIVE_OK darwin-arm64" in native, "Mac return install native binary failed")
    results["mac_frozen_return_native"] = native

    print("==> real npm: Linux-origin lock on macOS, with exact bytes retained")
    # A Linux first install is made with the same signed registry and fresh project.
    reverse = base / "linux-origin"
    manifest(reverse, {"esbuild": "0.25.0"})
    # Only this manifest/lock exchange needs container write access.
    reverse.chmod(0o777)
    proxy.phase = "linux_initial_resolve"
    reverse_script = '''set -euo pipefail
mkdir -p /home/rivet/case
cp /exchange/rivet.toml /home/rivet/case/rivet.toml
cd /home/rivet/case
/home/rivet/target/release/rivet install
node -e "const e=require('esbuild');if(!e.transformSync('let x: number=42',{loader:'ts'}).code.includes('42'))throw Error('native');console.log('NATIVE_OK '+process.platform+'-'+process.arch)"
sha256sum rivet.lock
cp rivet.lock /exchange/rivet.lock
'''
    container = f"rivet-compat-{base.name}-reverse"
    CONTAINERS.append(container)
    output = command(["docker", "run", "--rm", "--name", container, "--user", "rivet",
                      "-v", f"{reverse.resolve()}:/exchange",
                      "-v", "rivet-linux-target:/home/rivet/target",
                      "-e", "RIVET_HOME=/home/rivet/compat-home",
                      "-e", f"RIVET_REGISTRY_URL={env['RIVET_REGISTRY_URL']}",
                      "-e", f"RIVET_REGISTRY_TOKEN={env['RIVET_REGISTRY_TOKEN']}",
                      args.docker_image, "bash", "-c", reverse_script], timeout=600)
    check("NATIVE_OK linux-arm64" in output, output)
    reverse_bytes, _ = locked(reverse)
    reverse_sha = lock_sha(reverse, "Linux original")
    results["linux_origin_lock_sha256"] = reverse_sha
    results["linux_initial_native"] = next(
        line.strip() for line in output.splitlines() if line.startswith("NATIVE_OK ")
    )
    proxy.phase = "mac_frozen_from_linux"
    output = command([rivet, "install", "--frozen"], cwd=reverse, env=env)
    check("rivet.lock (re-verified)" in output and no_resolves("mac_frozen_from_linux") == 0,
          "Mac frozen from Linux lock resolved")
    results["mac_frozen_from_linux_resolves"] = no_resolves("mac_frozen_from_linux")
    check((reverse / "rivet.lock").read_bytes() == reverse_bytes,
          "Mac frozen from Linux lock changed bytes")
    check(lock_sha(reverse, "Mac frozen from Linux") == reverse_sha,
          "Linux-origin lock digest changed")
    native = node(reverse, expression)
    check("NATIVE_OK darwin-arm64" in native, "Linux-origin lock failed on Mac")
    results["mac_frozen_from_linux_native"] = native
    (base / "results.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")


def native_portable_case(base, rivet, env, proxy, args):
    """Consume the exact seed-job lock on each OS/architecture, with a cold store.

    The local registry is independently populated before the measured frozen
    phase. A public test-only signing seed and fixed loopback URL preserve the
    lock's trust identity across ephemeral CI machines.
    """
    project = base / "portable"
    manifest(project, {"esbuild": "0.25.0"})
    proxy.phase = "native_registry_population"
    command([rivet, "install"], cwd=project, env=env)
    if args.lock_input:
        (project / "rivet.lock").write_bytes(Path(args.lock_input).read_bytes())
    original, lock = locked(project)
    for target in TARGETS:
        native = {pkg["name"] for pkg in lock["variants"][target]["packages"].values()
                  if pkg["name"].startswith("@esbuild/")}
        check(native == {"@esbuild/" + target}, f"wrong native pins for {target}: {native}")
    if args.lock_output:
        destination = Path(args.lock_output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(original)
    shutil.rmtree(project / "node_modules")
    cold = dict(env, RIVET_HOME=str(base / "portable-cold-home"))
    proxy.phase = "native_frozen"
    output = command([rivet, "install", "--frozen"], cwd=project, env=cold)
    check("rivet.lock (re-verified)" in output, output)
    check((project / "rivet.lock").read_bytes() == original, "frozen lock bytes changed")
    resolves = sum(request["phase"] == "native_frozen" and
                   request["path"].startswith("/v1/npm/resolve") for request in proxy.requests)
    check(resolves == 0, "frozen install resolved replacement versions")
    expression = "const e=require('esbuild');const x=e.transformSync('let answer: number = 42', {loader:'ts'}).code;if(!x.includes('42'))throw Error(x);console.log('NATIVE_OK '+process.platform+'-'+process.arch)"
    native = node(project, expression)
    check(native == "NATIVE_OK " + HOST_TARGET, f"native transform failed: {native}")
    result = {"target": HOST_TARGET, "lock_sha256": hashlib.sha256(original).hexdigest(),
              "frozen_resolve_requests": resolves, "native": native,
              "lock_origin": "downloaded" if args.lock_input else "local",
              "rivet_sha256": hashlib.sha256(Path(rivet).read_bytes()).hexdigest()}
    (base / "results.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result), flush=True)


def main():
    global EVIDENCE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rivet", help="use this prebuilt CLI instead of rebuilding")
    parser.add_argument("--registry", help="prebuilt registry binary")
    parser.add_argument("--docker-image", default="rivet-linux-check:latest")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--native", action="store_true", help="native CI mode, no Docker")
    parser.add_argument("--lock-input", help="exact portable lock from another CI host")
    parser.add_argument("--lock-output", help="export portable lock for other CI hosts")
    parser.add_argument("--evidence-dir", help="preserve logs/results here, excluding credentials")
    parser.add_argument("--corpus", action="store_true", help="also run pinned real-project workloads")
    parser.add_argument("--skip-linux", action="store_true")
    parser.add_argument("--pause-on-failure", type=int, default=0,
                        help="keep local servers alive briefly for debugging")
    args = parser.parse_args()
    check(args.native or (os.uname().sysname == "Darwin" and os.uname().machine == "arm64"),
          "this cross-platform E2E starts on macOS arm64")
    base = Path(tempfile.mkdtemp(prefix="rivet-compat-"))
    EVIDENCE = base / "commands.log"
    upstream = serve(Upstream, ("127.0.0.1", port()))
    upstream.tarballs = {}
    backend_port = port()
    registry = Path(args.registry) if args.registry else base / "rivet-registry"
    if not args.registry:
        command(["go", "build", "-o", registry, "./cmd/server"], cwd=ROOT / "registry", timeout=600)
    if args.rivet is None:
        command(["cargo", "build", "-p", "rivet", "--release", "--locked"], cwd=ROOT, timeout=1200)
        args.rivet = str(ROOT / "target/release/rivet")
    else:
        args.rivet = str(Path(args.rivet).resolve())
        check(Path(args.rivet).is_file(), f"prebuilt CLI not found: {args.rivet}")
    registry_log = (base / "registry.log").open("w")
    registry_process = subprocess.Popen([str(registry)], stdout=registry_log,
                                        stderr=subprocess.STDOUT, env=dict(os.environ,
                                        RIVET_ENV="development", RIVET_AUDIT_MODE="static",
                                        RIVET_SIGNING_KEY=base64.b64encode(bytes(range(32))).decode() if args.native else "",
                                        RIVET_STORE="memory", RIVET_DATA_DIR=str(base / "registry"),
                                        RIVET_REGISTRY_TOKEN="compat-token",
                                        RIVET_ADDR=f"127.0.0.1:{backend_port}",
                                        RIVET_NPM_UPSTREAM=f"http://127.0.0.1:{upstream.server_port}"))
    proxy = serve(RegistryProxy, ("127.0.0.1", 18185) if args.native else ("0.0.0.0", port()))
    proxy.backend = backend_port
    proxy.requests = []
    proxy.phase = "startup"
    try:
        print(f"CLI sha256 {hashlib.sha256(Path(args.rivet).read_bytes()).hexdigest()}")
        print(f"registry sha256 {hashlib.sha256(registry.read_bytes()).hexdigest()}")
        for _ in range(100):
            try:
                urlopen(f"http://127.0.0.1:{backend_port}/healthz", timeout=1).close()
                break
            except Exception:
                time.sleep(0.1)
        else:
            raise AssertionError("registry did not start")
        host_ip = "127.0.0.1" if args.native else command(["ipconfig", "getifaddr", "en0"]).strip()
        env = dict(os.environ, RIVET_HOME=str(base / "home"),
                   RIVET_REGISTRY_URL=f"http://{host_ip}:{proxy.server_port}",
                   RIVET_REGISTRY_TOKEN="compat-token")
        peer_cases(base, args.rivet, env)
        if args.native:
            native_portable_case(base, args.rivet, env, proxy, args)
        elif not args.skip_linux:
            portable_case(base, args.rivet, env, proxy, args)
        if args.corpus:
            from projects import run_corpus
            run_corpus(base, args.rivet, env)
        print(f"PASS compatibility E2E; evidence: {base}")
    except Exception:
        if args.pause_on_failure:
            print(f"failure evidence: {base}; servers stay up for {args.pause_on_failure}s",
                  flush=True)
            time.sleep(args.pause_on_failure)
        raise
    finally:
        for container in CONTAINERS:
            subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=20, check=False)
        with (base / "proxy-requests.jsonl").open("w") as log:
            for request in proxy.requests:
                log.write(json.dumps(request) + "\n")
        proxy.shutdown()
        proxy.server_close()
        upstream.shutdown()
        upstream.server_close()
        registry_process.terminate()
        try:
            registry_process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            registry_process.kill()
            registry_process.wait(timeout=5)
        registry_log.close()
        if args.evidence_dir:
            destination = Path(args.evidence_dir)
            destination.mkdir(parents=True, exist_ok=True)
            for file in base.iterdir():
                if file.suffix in (".log", ".json", ".jsonl"):
                    shutil.copy2(file, destination / file.name)
        if not args.keep:
            shutil.rmtree(base)


if __name__ == "__main__":
    main()
