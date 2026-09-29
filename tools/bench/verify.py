#!/usr/bin/env python3
"""Compare two release CLIs on one installed project with alternating order.

Run while the project's registry is available and its installed tree is stable:
  python3 tools/bench/verify.py OLD NEW semver 1.2.3 -r '^1.0.0'

The script inherits RIVET_HOME and RIVET_REGISTRY_URL from its environment.
It measures verification and sandbox preparation with --dry-run; the normal
end-to-end benchmark separately measures command execution.
"""

import json
import statistics
import subprocess
import sys
import time


def sample(binary, command):
    start = time.perf_counter()
    process = subprocess.run(
        [binary, "run", "--json", "--dry-run", *command],
        check=True,
        capture_output=True,
        text=True,
    )
    elapsed_ms = (time.perf_counter() - start) * 1000
    response = json.loads(process.stdout)
    return {
        "wall_ms": elapsed_ms,
        "packages_verified": response["packages_verified"],
        "verify_timings_ms": response["verify_timings_ms"],
    }


def main():
    if len(sys.argv) < 4:
        raise SystemExit("usage: verify.py OLD_RELEASE NEW_RELEASE COMMAND [ARGS...] ")
    before, after, *command = sys.argv[1:]
    samples = {"before": [], "after": []}
    for binary in (before, after):
        sample(binary, command)
    for _ in range(5):
        for label, binary in (
            ("before", before),
            ("after", after),
            ("after", after),
            ("before", before),
        ):
            samples[label].append(sample(binary, command))
    counts = {s["packages_verified"] for runs in samples.values() for s in runs}
    if len(counts) != 1:
        raise SystemExit(f"inconsistent verified package counts: {sorted(counts)}")
    result = {"command": command, "packages_verified": counts.pop(), "samples": samples}
    for label, runs in samples.items():
        result[f"{label}_median_ms"] = {
            "wall": round(statistics.median(s["wall_ms"] for s in runs), 1),
            **{
                phase: statistics.median(
                    s["verify_timings_ms"][phase] for s in runs
                )
                for phase in ("total_ms", "layout_ms", "fetch_ms", "hash_ms", "other_ms")
            },
        }
    print(json.dumps(result))


if __name__ == "__main__":
    main()
