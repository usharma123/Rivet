#!/usr/bin/env python3
"""Compare 2, 4, and 8 hashing workers on one installed project.

Run while the registry and project are stable:
  python3 tools/bench/workers.py BIN_2 BIN_4 BIN_8 semver 1.2.3 -r '^1.0.0'
"""

import json
import statistics
import sys

from verify import sample


def main():
    if len(sys.argv) < 5:
        raise SystemExit("usage: workers.py BIN_2 BIN_4 BIN_8 COMMAND [ARGS...]")
    binaries = dict(zip(("2", "4", "8"), sys.argv[1:4]))
    command = sys.argv[4:]
    samples = {key: [] for key in binaries}
    for binary in binaries.values():
        sample(binary, command)
    for _ in range(5):
        for key in ("2", "4", "8", "8", "4", "2"):
            samples[key].append(sample(binaries[key], command))
    counts = {s["packages_verified"] for runs in samples.values() for s in runs}
    if len(counts) != 1:
        raise SystemExit(f"inconsistent verified package counts: {sorted(counts)}")
    print(json.dumps({
        "command": command,
        "packages_verified": counts.pop(),
        "samples": samples,
        "median_ms": {
            key: {
                "wall": round(statistics.median(s["wall_ms"] for s in runs), 1),
                **{
                    phase: statistics.median(
                        s["verify_timings_ms"][phase] for s in runs
                    )
                    for phase in ("total_ms", "layout_ms", "fetch_ms", "hash_ms", "other_ms")
                },
            }
            for key, runs in samples.items()
        },
    }))


if __name__ == "__main__":
    main()
