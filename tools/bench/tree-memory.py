#!/usr/bin/env python3
"""Compare per-process peak RSS while hashing a large extracted package.

Build cli/examples/tree_hash.rs against the baseline commit and the candidate,
then pass both release binaries here. The helper checks digest equality and
uses wait4 to read each direct child's peak RSS, independent of Node or cargo.
  python3 tools/bench/tree-memory.py OLD_HELPER NEW_HELPER [MIB]
"""

import json
import os
import statistics
import sys
import tempfile
import time


def sample(binary, directory):
    start = time.perf_counter()
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        os.dup2(write_fd, 1)
        os.close(write_fd)
        os.execl(binary, binary, directory)
    os.close(write_fd)
    with os.fdopen(read_fd, "rb") as output:
        digest = output.read().decode().strip()
    _, status, usage = os.wait4(pid, 0)
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise RuntimeError(f"{binary} exited with status {status}")
    rss = usage.ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024)
    return {"wall_ms": (time.perf_counter() - start) * 1000, "rss_mib": rss, "digest": digest}


def main():
    if len(sys.argv) not in (3, 4):
        raise SystemExit("usage: tree-memory.py OLD_HELPER NEW_HELPER [MIB]")
    before, after = map(os.path.abspath, sys.argv[1:3])
    mib = int(sys.argv[3]) if len(sys.argv) == 4 else 192
    if not 1 <= mib <= 256:
        raise SystemExit("MIB must be between 1 and 256")
    with tempfile.TemporaryDirectory(prefix="rivet-tree-memory-") as directory:
        path = os.path.join(directory, "large.bin")
        with open(path, "wb") as handle:
            chunk = bytes(range(256)) * 4096
            for _ in range(mib):
                handle.write(chunk)
        samples = {"before": [], "after": []}
        for binary in (before, after):
            sample(binary, directory)
        for _ in range(3):
            for label, binary in (
                ("before", before), ("after", after),
                ("after", after), ("before", before),
            ):
                samples[label].append(sample(binary, directory))
        digests = {s["digest"] for runs in samples.values() for s in runs}
        if len(digests) != 1:
            raise SystemExit("old and new tree digests differ")
        print(json.dumps({
            "file_mib": mib,
            "digest": digests.pop(),
            "samples": samples,
            "median": {
                label: {
                    "wall_ms": round(statistics.median(s["wall_ms"] for s in runs), 1),
                    "peak_rss_mib": round(statistics.median(s["rss_mib"] for s in runs), 1),
                }
                for label, runs in samples.items()
            },
        }))


if __name__ == "__main__":
    main()
