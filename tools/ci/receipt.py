#!/usr/bin/env python3
"""Write source and tool identities beside CI results, including dirty local runs."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys


def output(*args):
    return subprocess.check_output(args, text=True).strip()


files = subprocess.check_output(["git", "ls-files", "-co", "--exclude-standard", "-z"]).split(b"\0")
hashes = {}
for raw in sorted(set(files)):
    if raw:
        path = Path(os.fsdecode(raw))
        if path.is_file():
            hashes[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
receipt = {"commit": output("git", "rev-parse", "HEAD"),
           "worktree_status": output("git", "status", "--porcelain"),
           "source_sha256": hashes, "platform": platform.platform(),
           "run_id": os.getenv("GITHUB_RUN_ID"), "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
           "event_sha": os.getenv("GITHUB_SHA"), "job": os.getenv("GITHUB_JOB")}
for tool in ("rustc", "cargo", "go", "node", "docker"):
    try:
        receipt[tool] = output(tool, "version" if tool == "go" else "--version")
    except (OSError, subprocess.CalledProcessError):
        pass
path = Path(sys.argv[1])
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(receipt, indent=2) + "\n")
