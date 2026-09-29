"""Pinned representative projects; called by compatibility.py --native --corpus.

Each case records install failure, execution failure, audit/policy refusal, and
warm run overhead independently. Static registry policy applies here; live
kernel audit certification has its own gate and is not inferred from this run.
"""
import hashlib
import json
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import time


def run_corpus(base, rivet, env):
    # Import lazily; compatibility.py may be the __main__ module.
    from compatibility import HOST_TARGET
    cases = [
        {"name": "formatter", "deps": {"prettier": "3.5.3"},
         "files": {"input.js": "const   answer={value:42}\n"},
         "args": ["prettier", "input.js"], "entry": "prettier/bin/prettier.cjs",
         "expect": "const answer = { value: 42 };"},
        {"name": "typescript", "deps": {"typescript": "5.8.3"},
         "files": {"tsconfig.json": '{"compilerOptions":{"strict":true,"outDir":"build"},"files":["index.ts"]}',
                   "index.ts": "const answer: number = 42; console.log(answer);\n"},
         "args": ["tsc", "--project", "tsconfig.json"], "entry": "typescript/bin/tsc",
         "artifact": "build/index.js", "expect_artifact": "42"},
        {"name": "react-vite", "deps": {"vite": "6.3.5", "react": "19.1.0", "react-dom": "19.1.0"},
         "files": {"index.html": '<div id="root"></div><script type="module" src="/src.jsx"></script>',
                   "src.jsx": 'import React from "react"; import {createRoot} from "react-dom/client"; createRoot(document.getElementById("root")).render(<h1>Rivet corpus</h1>);'},
         "args": ["vite", "build"], "entry": "vite/bin/vite.js",
         "expect": "built in", "artifact": "dist/index.html", "expect_artifact": "assets/"},
        {"name": "eslint", "deps": {"eslint": "9.25.1"},
         "files": {"eslint.config.mjs": 'export default [{rules:{"no-unused-vars":"error"}}];',
                   "input.js": "const answer = 42; console.log(answer);\n"},
         "args": ["eslint", "input.js"], "entry": "eslint/bin/eslint.js"},
    ]
    results = {"target": HOST_TARGET, "node": subprocess.check_output(["node", "--version"], text=True).strip(),
               "platform": platform.platform(), "audit_mode": "static", "samples_per_command": 3,
               "cache": "warm after successful functional execution; local registry",
               "cli_sha256": hashlib.sha256(Path(rivet).read_bytes()).hexdigest(), "cases": []}
    failures = []
    log = (base / "projects.log").open("w")

    def execute(args, project, timeout=300):
        start = time.monotonic()
        try:
            result = subprocess.run(list(map(str, args)), cwd=project, env=env,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    timeout=timeout)
        except subprocess.TimeoutExpired as error:
            output = error.stdout or b""
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
            result = subprocess.CompletedProcess(args, 124, output + "\nTIMEOUT")
        elapsed = time.monotonic() - start
        log.write(f"$ {' '.join(map(str, args))}\nexit={result.returncode} seconds={elapsed:.6f}\n{result.stdout}\n")
        log.flush()
        return result, elapsed

    def success(result):
        if result.returncode:
            raise RuntimeError(result.stdout[-8000:])

    try:
        for case in cases:
            print("==> real project: " + case["name"], flush=True)
            project = base / ("project-" + case["name"])
            project.mkdir()
            (project / "package.json").write_text(json.dumps({"name": case["name"], "private": True, "devDependencies": case["deps"], "scripts": {"check": " ".join(case["args"])}}) + "\n")
            (project / "rivet.toml").write_text("[policy]\nmin_release_age_hours = 0\n")
            for name, content in case["files"].items():
                (project / name).write_text(content)
            record = {"name": case["name"], "dependencies": case["deps"], "status": "failed", "phase": "install"}
            results["cases"].append(record)
            try:
                installed, elapsed = execute([rivet, "install"], project, timeout=900)
                record["install_s"] = elapsed
                record["install_exit"] = installed.returncode
                record["audit_or_policy_refusal"] = bool(installed.returncode and any(
                    word in installed.stdout.lower() for word in ("quarantined", "blocked", "audit", "policy")))
                success(installed)
                lock_bytes = (project / "rivet.lock").read_bytes()
                lock = json.loads(lock_bytes)
                record["lock_sha256"] = hashlib.sha256(lock_bytes).hexdigest()
                record["packages"] = len(lock["variants"][HOST_TARGET]["packages"])
                record["resolved_releases"] = sorted({p["name"] + "@" + p["version"]
                    for p in lock["variants"][HOST_TARGET]["packages"].values()})
                record["phase"] = "frozen-install"
                shutil.rmtree(project / "node_modules")
                frozen, elapsed = execute([rivet, "ci"], project, timeout=900)
                record["frozen_install_s"] = elapsed
                success(frozen)
                if (project / "rivet.lock").read_bytes() != lock_bytes:
                    raise RuntimeError("frozen install changed lock bytes")
                record["phase"] = "sandboxed-run"
                args = case["args"]
                # Explicit build output grant; network and install scripts remain disabled.
                rivet_args = [rivet, "run", "--allow-write", str(project), args[0], "--", *args[1:]]
                result, _ = execute(rivet_args, project)
                success(result)
                if case.get("expect") and case["expect"] not in result.stdout:
                    raise RuntimeError("expected command output missing: " + result.stdout)
                if case.get("artifact"):
                    artifact = project / case["artifact"]
                    if not artifact.is_file() or case["expect_artifact"] not in artifact.read_text():
                        raise RuntimeError("expected build artifact missing or incorrect")
                # Plain Node may create node_modules/.cache. Keep its mutable
                # baseline separate from the verified Rivet installation.
                baseline = base / ("baseline-" + case["name"])
                shutil.copytree(project, baseline, symlinks=True)
                samples = {"rivet": [], "plain_node": []}
                plain = ["node", baseline / "node_modules" / case["entry"], *args[1:]]
                record["phase"] = "benchmark"
                for _ in range(3):
                    for label, cmd in (("rivet", rivet_args), ("plain_node", plain)):
                        result, elapsed = execute(cmd, project if label == "rivet" else baseline)
                        success(result)
                        samples[label].append(elapsed)
                record["samples_s"] = samples
                record["warm_median_s"] = {k: statistics.median(v) for k, v in samples.items()}
                record["overhead_s"] = record["warm_median_s"]["rivet"] - record["warm_median_s"]["plain_node"]
                record["status"] = "passed"
                record["phase"] = "complete"
            except Exception as error:
                record["error"] = str(error)
                failures.append(case["name"])
            finally:
                (base / "projects.json").write_text(json.dumps(results, indent=2) + "\n")
    finally:
        log.close()
    if failures:
        raise AssertionError("real-project failures: " + ", ".join(failures))
