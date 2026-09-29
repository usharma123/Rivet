"""Exercise the npm project and agent CLI contracts against a real registry."""
import json
import selectors
import subprocess
import time


def run_agent_cases(base, rivet, env, proxy):
    project = base / "agent-project"
    project.mkdir()
    document = {"name": "agent-project", "private": True, "type": "module",
                "dependencies": {"compat-core": "^1"},
                "devDependencies": {"prettier": "3.5.3"},
                "scripts": {"format": "prettier input.js",
                            "explicit": "./node_modules/.bin/prettier input.js",
                            "explicit-args": "./node_modules/.bin/prettier",
                            "hold": "node hold.cjs", "fail": "node -e 'process.exit(7)'",
                            "prettier": "node -e 'console.log(\"project-script\")'",
                            "args": "node args.cjs", "protect": "node protect.cjs"},
                "custom": {"preserve": True}}
    manifest = project / "package.json"
    manifest.write_text(json.dumps(document, indent=2) + "\n")
    (project / "input.js").write_text("const   x={n:1}\n")
    (project / "hold.cjs").write_text("console.log('ready');setTimeout(()=>{},3000)")
    (project / "args.cjs").write_text("console.log(JSON.stringify(process.argv.slice(2)))")
    (project / "protect.cjs").write_text("""
const fs = require('fs');
for (const p of [process.env.RIVET_SCRIPT_BINS + '/prettier', 'package.json', 'rivet.toml', 'rivet.lock', 'node_modules/.bin/prettier']) {
  try { fs.writeFileSync(p, 'corrupt'); throw new Error('write unexpectedly allowed: ' + p); }
  catch (e) { if (!['EPERM','EACCES','EROFS'].includes(e.code)) throw e; }
}
console.log('protected');
""")
    (project / "rivet.toml").write_text("[policy]\nmin_release_age_hours = 0\n")
    log = (base / "agent-dx.log").open("w")
    checks = []

    def run(args, expected=0, cwd=project, custom_env=env):
        result = subprocess.run([str(rivet), *args], cwd=cwd, env=custom_env,
                                capture_output=True, text=True, timeout=300)
        log.write(f"{args}\nexit={result.returncode}\nstdout={result.stdout}\nstderr={result.stderr}\n")
        log.flush()
        assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
        return result

    def machine(args, expected=0, **kwargs):
        result = run([*args, "--json"], expected, **kwargs)
        value = json.loads(result.stdout)
        assert value["schema_version"] == 1 and value["ok"] == (expected == 0), value
        return value, result

    def unchanged(before):
        assert {name: (project / name).read_bytes() for name in before} == before

    try:
        started = time.monotonic()
        original = manifest.read_bytes()
        # Observe the first event while the process is still doing work.
        process = subprocess.Popen([str(rivet), "install", "--events"], cwd=project, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                assert selector.select(timeout=10), "no streaming event before registry work"
            first = json.loads(process.stdout.readline())
            assert first["event"] == "install.started", first
            assert process.poll() is None, "event was buffered until process completion"
            stdout, stderr = process.communicate(timeout=300)
            assert process.returncode == 0, stderr
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()
        events = [first, *[json.loads(line) for line in stdout.splitlines()]]
        assert events[-1]["event"] == "install.completed", events
        assert all(event["schema_version"] == 1 for event in events)
        assert manifest.read_bytes() == original
        checks.append("live events and unchanged npm manifest")

        saved = {name: (project / name).read_bytes() for name in ["package.json", "rivet.lock", "node_modules/.rivet/state.json"]}
        value, _ = machine(["install", "compat-core@^2", "--plan"])
        assert not value["changed"] and value["changes"]["after"]["compat-core"] == "^2"
        unchanged(saved)
        value, _ = machine(["install", "compat-core@99.0.0"], expected=1)
        assert value["error"]["code"] == "POLICY_REFUSED", value
        unchanged(saved)
        checks.append("plan and failed install preserve manifest lock and installation")

        output = run(["run", "--json", "format"])
        assert json.loads(output.stdout)["exit_code"] == 0 and "const x = { n: 1 };" in output.stderr
        output = run(["run", "--json", "explicit"])
        assert json.loads(output.stdout)["exit_code"] == 0 and "const x = { n: 1 };" in output.stderr
        assert run(["run", "explicit-args", "--", "--version"]).stdout.strip() == "3.5.3"
        output = run(["run", "explicit-args", "--", "missing-input.js"], expected=2)
        assert "No files matching" in output.stderr
        output = run(["run", "--json", "fail"], expected=7)
        assert json.loads(output.stdout)["error"]["code"] == "PROCESS_FAILED"
        assert "project-script" in run(["run", "prettier"]).stdout
        assert run(["exec", "prettier", "--", "--version"]).stdout.strip() == "3.5.3"
        shim = subprocess.run([project / "node_modules/.bin/prettier", "--version"], cwd=project, env=env, capture_output=True, text=True, timeout=30)
        assert shim.returncode == 0 and shim.stdout.strip() == "3.5.3", shim
        injected = "$(touch injected); argument with spaces ' and quotes"
        assert json.loads(run(["run", "args", "--", injected]).stdout) == [injected]
        assert not (project / "injected").exists()
        assert "protected" in run(["run", "--allow-write", str(project), "protect"]).stdout
        unchanged(saved)
        checks.append("sandboxed scripts binary collision argument quoting and machine output")
        # A script keeps the mutation lock for its entire lifetime.
        child = subprocess.Popen([str(rivet), "run", "hold"], cwd=project, env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                assert selector.select(timeout=30), "script did not start"
            assert child.stdout.readline().strip() == "ready"
            value, _ = machine(["add", "compat-core", "--plan"], expected=1)
            assert value["error"]["code"] == "PROJECT_BUSY"
            stdout, stderr = child.communicate(timeout=30)
            assert child.returncode == 0, (stdout, stderr)
        finally:
            if child.poll() is None:
                child.kill()
                child.communicate()
        # Explicit shims must still be preceded by full tree verification.
        entry = project / "node_modules/prettier/bin/prettier.cjs"
        original_entry = entry.read_bytes()
        mode = entry.stat().st_mode
        entry.chmod(0o644)
        try:
            entry.write_bytes(original_entry + b"\n// changed\n")
            output = run(["run", "explicit-args", "--", "--version"], expected=1)
            assert "3.5.3" not in output.stdout
        finally:
            entry.write_bytes(original_entry)
            entry.chmod(mode)
        checks.append("explicit shims preserve arguments exit status verification sandbox and locking")

        lock = (project / "rivet.lock").read_bytes()
        proxy.phase = "agent-frozen"
        value, _ = machine(["ci"])
        assert value["from_lock"] and (project / "rivet.lock").read_bytes() == lock
        requests = [r for r in proxy.requests if r["phase"] == "agent-frozen"]
        assert not any(r["path"] == "/v1/npm/resolve" or r["path"].startswith("/v1/artifacts/") for r in requests), requests
        document["dependencies"]["compat-core"] = "^2"
        manifest.write_text(json.dumps(document))
        value, _ = machine(["ci"], expected=1)
        assert value["error"]["code"] == "LOCKFILE_STALE"
        manifest.write_bytes(original)
        checks.append("frozen installs reuse cache and refuse stale manifests")

        machine(["install", "-D", "compat-plugin@^1"])
        edited = json.loads(manifest.read_text())
        assert edited["custom"] == {"preserve": True} and edited["devDependencies"]["compat-plugin"] == "^1"
        machine(["remove", "compat-plugin"])
        assert "compat-plugin" not in json.loads(manifest.read_text())["devDependencies"]
        machine(["update"])
        checks.append("install save-dev remove and update")

        proxy.phase = "agent-concurrent-cache"
        shared_env = dict(env, RIVET_HOME=str(base / "agent-shared-home"))
        workers = []
        for index in range(2):
            root = base / f"agent-parallel-{index}"
            root.mkdir()
            (root / "package.json").write_text(json.dumps({"dependencies": {"compat-core": "1.0.0"}}))
            workers.append(subprocess.Popen([str(rivet), "install", "--json"], cwd=root, env=shared_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        for worker in workers:
            out, err = worker.communicate(timeout=120)
            assert worker.returncode == 0, (out, err)
        downloads = [r for r in proxy.requests if r["phase"] == "agent-concurrent-cache" and r["path"].startswith("/v1/artifacts/")]
        assert len(downloads) == 1, downloads
        pins = [r for r in proxy.requests if r["phase"] == "agent-concurrent-cache" and r["path"] == "/v1/keys"]
        assert len(pins) == 1, pins
        checks.append("two simultaneous projects download shared artifact once")
        (base / "agent-dx.json").write_text(json.dumps({"status": "passed", "checks": checks, "seconds": time.monotonic() - started, "shared_artifact_downloads": len(downloads)}, indent=2) + "\n")
        print(f"PASS agent DX: {len(checks)} scenarios", flush=True)
    finally:
        log.close()
