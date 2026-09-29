#!/usr/bin/env python3
"""Receive one gVisor SecCheck remote stream outside the audited sandbox.

The wire format is documented in gVisor's seccheck/sinks/remote README and
points/*.proto. This parser deliberately accepts only the fields Rivet uses.
"""

import json
import os
import re
import socket
import struct
import sys
import time

ROOT = "/trace"
MAX_PACKET = 65536
MAX_PACKETS = 100000
MAX_BYTES = 8 * 1024 * 1024
MAX_EVENTS = 256
DEADLINE = 600
# Alias creation plus namespace and mount changes that can move a protected
# credential path. The trace config enables only the relevant numbers for the
# sandbox architecture.
UNSUPPORTED_SYSCALLS = {
    36: "symlinkat (arm64)", 37: "linkat (arm64)",
    38: "renameat (arm64)", 276: "renameat2 (arm64)",
    39: "umount2 (arm64)", 40: "mount (arm64)",
    41: "pivot_root (arm64)", 51: "chroot (arm64)",
    97: "unshare (arm64)", 268: "setns (arm64)",
    82: "rename (amd64)", 86: "link (amd64)",
    88: "symlink (amd64)", 264: "renameat (amd64)",
    265: "linkat (amd64)", 266: "symlinkat (amd64)",
    316: "renameat2 (amd64)", 155: "pivot_root (amd64)",
    161: "chroot (amd64)", 165: "mount (amd64)",
    166: "umount2 (amd64)", 272: "unshare (amd64)",
    308: "setns (amd64)",
    426: "io_uring_enter", 427: "io_uring_register", 428: "open_tree",
    429: "move_mount", 430: "fsopen", 431: "fsconfig",
    432: "fsmount", 433: "fspick", 437: "openat2",
}
OUTBOUND_SYSCALLS = {206, 211, 269, 44, 46, 307}
# Mount, user, PID, network, IPC, UTS and cgroup namespaces. These flags are
# observed on a successful clone regardless of which clone syscall was used.
CLONE_NAMESPACE_FLAGS = 0x7E020000
MAGIC_ALIAS = re.compile(
    r"^/(?:proc/(?:self|thread-self|[0-9]+)(?:/task/[0-9]+)?/(?:root|cwd|fd)(?:/|$)|dev/(?:fd(?:/|$)|stdin$|stdout$|stderr$))"
)


def fields(data):
    """Parse bounded protobuf wire fields, skipping unknown fields."""
    pos = 0

    def varint():
        nonlocal pos
        value = 0
        for shift in range(0, 70, 7):
            if pos >= len(data):
                raise ValueError("truncated protobuf varint")
            byte = data[pos]
            pos += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
        raise ValueError("oversized protobuf varint")

    while pos < len(data):
        tag = varint()
        number, wire = tag >> 3, tag & 7
        if not number:
            raise ValueError("invalid protobuf field")
        if wire == 0:
            value = varint()
        elif wire == 2:
            size = varint()
            if size > MAX_PACKET or pos + size > len(data):
                raise ValueError("invalid protobuf field length")
            value = data[pos : pos + size]
            pos += size
        elif wire == 1:
            if pos + 8 > len(data):
                raise ValueError("truncated protobuf fixed64")
            value = data[pos : pos + 8]
            pos += 8
        elif wire == 5:
            if pos + 4 > len(data):
                raise ValueError("truncated protobuf fixed32")
            value = data[pos : pos + 4]
            pos += 4
        else:
            raise ValueError("unsupported protobuf wire type")
        yield number, value


def first(data, field, default=None):
    return next((value for number, value in fields(data) if number == field), default)


def string(value):
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else ""


def context(data):
    raw = first(data, 1)
    if not isinstance(raw, bytes):
        raise ValueError("missing trace context")
    values = list(fields(raw))
    cred = next((value for number, value in values if number == 7), None)
    container = string(first(raw, 6, b""))
    pid = first(raw, 4, 0)
    if not isinstance(cred, bytes) or not container or not isinstance(pid, int) or pid < 1:
        raise ValueError("trace event missing credentials or task identity")
    list(fields(cred))
    uid = first(cred, 2, 0)
    if not isinstance(uid, int) or uid > 0xFFFFFFFF:
        raise ValueError("invalid trace effective UID")
    return {
        "container": container,
        "pid": pid,
        "uid": uid,
        "cwd": string(first(raw, 8, b"")),
        "process": string(first(raw, 9, b""))[:64],
    }


def signed64(value):
    return value - (1 << 64) if value >= (1 << 63) else value


def uses_magic_alias(path):
    # Check each prefix before applying a later '..': the kernel follows
    # /proc/self/cwd first, so normpath on the whole string loses evidence.
    parts = []
    for component in path.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if parts:
                parts.pop()
        else:
            parts.append(component)
        if MAGIC_ALIAS.match("/" + "/".join(parts)):
            return True
    return False


def linux_normpath(path):
    normalized = os.path.normpath(path)
    # Python retains exactly two leading slashes under POSIX rules. Linux
    # resolves them as one, including when the file is later read by mmap.
    return "/" + normalized.lstrip("/") if normalized.startswith("/") else normalized


def parse_packet(data, result, expected_id, nonce):
    if len(data) < 8:
        raise ValueError("short trace header")
    header_size, kind, dropped = struct.unpack_from("<HHI", data)
    if header_size < 8 or header_size > len(data):
        raise ValueError("invalid trace header size")
    if dropped:
        raise ValueError(f"gVisor dropped {dropped} trace points")
    payload = data[header_size:]
    # A field used by first() can precede a malformed tail. Validate the
    # complete message before accepting a start, exec, or completion marker.
    list(fields(payload))
    if kind == 1:  # container/start
        container = string(first(payload, 2, b""))
        if container != expected_id:
            raise ValueError("trace container ID mismatch")
        if context(payload)["container"] != expected_id:
            raise ValueError("trace start context mismatch")
        result["started"] = True
        return
    if kind == 6 and first(payload, 4) == 425 and isinstance(first(payload, 2), bytes):
        # Pinned gVisor emits raw exit points without ContextData even when
        # requested. The paired enter point supplies UID and task ordering.
        # A successful setup anywhere in this sandbox is unsupported.
        if first(payload, 1) is not None and context(payload)["container"] != expected_id:
            raise ValueError("io_uring_setup exit container ID mismatch")
        exit_data = first(payload, 2)
        list(fields(exit_data))
        errorno = first(exit_data, 2, 0)
        if not isinstance(errorno, int):
            raise ValueError("invalid io_uring_setup exit status")
        if errorno == 0:
            raise ValueError("unsupported successful io_uring_setup in audit sandbox")
        if result["io_uring_pending"] < 1:
            raise ValueError("io_uring_setup exit lacks an observed enter")
        result["io_uring_pending"] -= 1
        return
    if kind not in (2, 3, 5, 6, 7, 9, 10, 11, 12, 29):
        return
    ctx = context(payload)
    if ctx["container"] != expected_id:
        raise ValueError("trace event container ID mismatch")
    if kind == 6 and first(payload, 4) == 425:
        result["io_uring_pending"] += 1
    if kind == 7 and ctx["uid"] == 0 and ctx["pid"] == 1:
        path = linux_normpath(string(first(payload, 6, b"")))
        if path == "/rivet-audit-complete-" + nonce:
            if result["completed"]:
                raise ValueError("duplicate supervisor completion marker")
            result["completed"] = True
            with open(ROOT + "/marker", "x") as marker:
                marker.write(nonce)
            return
    if ctx["uid"] != 2000:
        return
    if result["completed"]:
        raise ValueError("package activity after supervisor completion")
    result["package_events"] += 1
    if kind == 2:
        flags = first(payload, 6, 0)
        if not isinstance(flags, int):
            raise ValueError("invalid clone flags")
        if flags & CLONE_NAMESPACE_FLAGS:
            raise ValueError("unsupported clone namespace during package probe")
        event = {"kind": "clone", "flags": flags, "pid": ctx["pid"]}
    elif kind in (3, 11):
        command = string(first(payload, 2 if kind == 3 else 6, b""))[:512]
        result["execs"] += 1
        event = {"kind": "exec", "command": command, "pid": ctx["pid"]}
    elif kind == 7:
        path = string(first(payload, 6, b""))
        if not path:
            raise ValueError("gVisor trace contains an empty package open path")
        if not path.startswith("/"):
            fd = signed64(first(payload, 4, 0))
            base = ctx["cwd"] if fd == -100 else string(first(payload, 5, b""))
            if not base:
                result["unresolved_opens"] += 1
                base = "[unresolved-dirfd]"
            path = os.path.join(base, path)
        if uses_magic_alias(path):
            raise ValueError("unsupported proc or fd path alias during package probe")
        path = linux_normpath(path)
        event = {"kind": "open", "path": path[:512], "pid": ctx["pid"]}
        if path.startswith("/tmp/rivet-work/home/") and len(result["honey_paths"]) < 32:
            result["honey_paths"].append(path[:512])
    elif kind == 9:
        path = string(first(payload, 5, b""))
        if uses_magic_alias(path):
            raise ValueError("unsupported proc or fd path alias during package probe")
        path = linux_normpath(path)
        event = {"kind": "read", "path": path[:512], "pid": ctx["pid"]}
        if path.startswith("/tmp/rivet-work/home/") and len(result["honey_paths"]) < 32:
            result["honey_paths"].append(path[:512])
    elif kind == 10:
        address = first(payload, 6, b"")
        family = struct.unpack_from("<H", address)[0] if isinstance(address, bytes) and len(address) >= 2 else 0
        if family in (2, 10):
            result["network_attempts"] += 1
        event = {"kind": "connect", "family": family, "pid": ctx["pid"]}
    elif kind == 6:
        sysno = first(payload, 4)
        if sysno == 425:
            event = {"kind": "io_uring_setup_attempt", "pid": ctx["pid"]}
        elif sysno in UNSUPPORTED_SYSCALLS:
            name = UNSUPPORTED_SYSCALLS[sysno]
            raise ValueError(f"unsupported {name} syscall during package probe")
        elif sysno in OUTBOUND_SYSCALLS:
            result["network_attempts"] += 1
            event = {"kind": "outbound_syscall", "sysno": sysno, "pid": ctx["pid"]}
        else:
            raise ValueError(f"unexpected raw syscall {sysno} during package probe")
    else:
        event = {"kind": str(kind), "pid": ctx["pid"]}
    if len(result["events"]) < MAX_EVENTS:
        result["events"].append(event)


def main():
    expected_id = os.environ["RIVET_CONTAINER_ID"]
    nonce = os.environ["RIVET_AUDIT_NONCE"]
    result = {
        "container_id": expected_id,
        "nonce": nonce,
        "started": False,
        "completed": False,
        "package_events": 0,
        "execs": 0,
        "network_attempts": 0,
        "io_uring_pending": 0,
        "unresolved_opens": 0,
        "honey_paths": [],
        "events": [],
        "packets": 0,
        "bytes": 0,
    }
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener.bind(ROOT + "/events.sock")
    listener.listen(1)
    end = time.monotonic() + DEADLINE
    listener.settimeout(DEADLINE)
    open(ROOT + "/ready", "w").close()
    try:
        connection, _ = listener.accept()
        connection.settimeout(max(0.1, end - time.monotonic()))
        with connection:
            hello, _, flags, _ = connection.recvmsg(1024)
            if flags & socket.MSG_TRUNC or first(hello, 1) != 1 or not list(fields(hello)):
                raise ValueError("invalid gVisor handshake")
            connection.sendall(b"\x08\x01")
            while True:
                if time.monotonic() >= end:
                    raise TimeoutError("gVisor trace exceeded absolute deadline")
                connection.settimeout(max(0.1, end - time.monotonic()))
                packet, _, flags, _ = connection.recvmsg(MAX_PACKET)
                if not packet:
                    break
                if flags & socket.MSG_TRUNC:
                    raise ValueError("oversized gVisor trace packet")
                result["packets"] += 1
                result["bytes"] += len(packet)
                if result["packets"] > MAX_PACKETS or result["bytes"] > MAX_BYTES:
                    raise ValueError("gVisor trace exceeded limits")
                try:
                    parse_packet(packet, result, expected_id, nonce)
                except ValueError as error:
                    kind = struct.unpack_from("<H", packet, 2)[0] if len(packet) >= 4 else -1
                    raise ValueError(f"{error} (trace kind {kind})") from error
        if not result["started"] or not result["completed"] or not result["execs"]:
            raise ValueError("gVisor trace missing start, completion, or package exec")
        if result["io_uring_pending"]:
            raise ValueError("gVisor trace missing io_uring_setup exit")
        if result["unresolved_opens"]:
            raise ValueError("gVisor trace contains unresolved package open paths")
        result["complete"] = True
    except Exception as error:
        result["complete"] = False
        result["error"] = str(error)[:256]
    finally:
        listener.close()
        with open(ROOT + "/result.json", "w") as output:
            json.dump(result, output, separators=(",", ":"))
        print(json.dumps({"complete": result["complete"], "error": result.get("error"), "packets": result["packets"]}))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
