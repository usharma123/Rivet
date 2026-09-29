import os
import struct
import tempfile
import unittest
from unittest.mock import patch

import observer


def varint(value):
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def number(field, value):
    return varint(field << 3) + varint(value)


def blob(field, value):
    return varint((field << 3) | 2) + varint(len(value)) + value


def packet(kind, payload, dropped=0):
    return struct.pack("<HHI", 8, kind, dropped) + payload


def event(path, uid=0, pid=1, container="correct", credentials=True, dirfd=None, fd_path=None):
    context = number(4, pid) + blob(6, container.encode()) + blob(8, b"/tmp/rivet-work")
    if credentials:
        context += blob(7, number(2, uid) if uid else b"")
    payload = blob(1, context) + blob(6, path.encode())
    if dirfd is not None:
        payload += number(4, dirfd if dirfd >= 0 else (1 << 64) + dirfd)
    if fd_path is not None:
        payload += blob(5, fd_path.encode())
    return packet(7, payload)


def empty_result():
    return {
        "started": False,
        "completed": False,
        "package_events": 0,
        "execs": 0,
        "network_attempts": 0,
        "io_uring_pending": 0,
        "unresolved_opens": 0,
        "honey_paths": [],
        "events": [],
    }


class ObserverParserTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.patch = patch.object(observer, "ROOT", self.temp.name)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.result = empty_result()

    def read(self, packet_bytes):
        observer.parse_packet(packet_bytes, self.result, "correct", "fresh")

    def test_root_marker_requires_present_credentials_and_exact_identity(self):
        with self.assertRaisesRegex(ValueError, "missing credentials"):
            self.read(event("/rivet-audit-complete-fresh", credentials=False))
        self.assertFalse(self.result["completed"])
        self.read(event("/rivet-audit-complete-old"))
        self.assertFalse(self.result["completed"])
        self.read(event("/rivet-audit-complete-fresh", uid=2000, pid=1))
        self.assertFalse(self.result["completed"])
        self.read(event("/rivet-audit-complete-fresh", uid=0, pid=2))
        self.assertFalse(self.result["completed"])
        self.read(event("/rivet-audit-complete-fresh"))
        self.assertTrue(self.result["completed"])
        with open(os.path.join(self.temp.name, "marker")) as marker:
            self.assertEqual(marker.read(), "fresh")

    def test_wrong_container_and_dropped_points_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "container ID mismatch"):
            self.read(event("/tmp/file", uid=2000, container="old"))
        with self.assertRaisesRegex(ValueError, "dropped 1"):
            self.read(packet(7, b"", dropped=1))

    def test_post_marker_package_activity_fails(self):
        self.read(event("/rivet-audit-complete-fresh"))
        with self.assertRaisesRegex(ValueError, "after supervisor completion"):
            self.read(event("/etc/passwd", uid=2000, pid=4))

    def test_dirfd_and_read_path_resolve_honeytoken(self):
        self.read(event(".npmrc", uid=2000, pid=4, dirfd=5, fd_path="/tmp/rivet-work/home"))
        self.assertEqual(self.result["honey_paths"], ["/tmp/rivet-work/home/.npmrc"])
        self.read(event("relative", uid=2000, pid=4, dirfd=5))
        self.assertEqual(self.result["unresolved_opens"], 1)
        read_payload = blob(1, number(4, 4) + blob(6, b"correct") + blob(7, number(2, 2000)))
        read_payload += blob(5, b"/tmp/rivet-work/home/.aws/credentials")
        self.read(packet(9, read_payload))
        self.assertIn("/tmp/rivet-work/home/.aws/credentials", self.result["honey_paths"])

    def test_absolute_alias_and_long_prefix_are_normalized_before_matching(self):
        self.read(event("/tmp/rivet-work/package/../home/.npmrc", uid=2000, pid=4))
        self.read(event("/" + "./" * 600 + "tmp/rivet-work/home/.npmrc", uid=2000, pid=4))
        self.read(event("//tmp/rivet-work/home/.npmrc", uid=2000, pid=4))
        self.assertEqual(self.result["honey_paths"], ["/tmp/rivet-work/home/.npmrc"] * 3)

    def test_raw_send_and_native_connect_count(self):
        context = number(4, 4) + blob(6, b"correct") + blob(7, number(2, 2000))
        self.read(packet(6, blob(1, context) + number(4, 206)))
        sockaddr = struct.pack("<H", 2) + b"\x00\x09\x7f\x00\x00\x01"
        self.read(packet(10, blob(1, context) + blob(6, sockaddr)))
        self.assertEqual(self.result["network_attempts"], 2)

    def test_clone_namespace_refused(self):
        context = number(4, 4) + blob(6, b"correct") + blob(7, number(2, 2000))
        for flag in (0x00020000, 0x10000000, 0x20000000, 0x40000000):
            with self.subTest(flag=flag), self.assertRaisesRegex(ValueError, "clone namespace"):
                self.read(packet(2, blob(1, context) + number(6, flag)))

    def test_io_uring_setup_requires_failed_exit(self):
        context = number(4, 4) + blob(6, b"correct") + blob(7, number(2, 2000))
        enter = blob(1, context) + number(4, 425)
        exit_payload = number(4, 425)
        self.read(packet(6, enter))
        self.assertEqual(self.result["events"][-1]["kind"], "io_uring_setup_attempt")
        self.read(packet(6, exit_payload + blob(2, number(2, 38))))
        self.assertEqual(self.result["io_uring_pending"], 0)
        self.read(packet(6, enter))
        with self.assertRaisesRegex(ValueError, "successful io_uring_setup"):
            self.read(packet(6, exit_payload + blob(2, b"")))
        with self.assertRaisesRegex(ValueError, "truncated protobuf varint"):
            self.read(packet(6, exit_payload + blob(2, number(2, 38) + b"\x80")))
        self.result["io_uring_pending"] = 0
        with self.assertRaisesRegex(ValueError, "lacks an observed enter"):
            self.read(packet(6, exit_payload + blob(2, number(2, 38))))

    def test_alias_mutation_and_proc_magic_paths_refuse_certification(self):
        context = number(4, 4) + blob(6, b"correct") + blob(7, number(2, 2000))
        for sysno, name in observer.UNSUPPORTED_SYSCALLS.items():
            with self.subTest(sysno=sysno), self.assertRaisesRegex(ValueError, "unsupported " + name.split(" ")[0]):
                self.read(packet(6, blob(1, context) + number(4, sysno)))
        for path in (
            "/proc/self/root/tmp/rivet-work/home/.npmrc",
            "/proc/self/cwd/../home/.npmrc",
            "/proc/thread-self/root/tmp/rivet-work/home/.npmrc",
            "/proc/23/task/23/fd/5",
            "/dev/fd/5",
            "/./proc/23/root/tmp/rivet-work/home/.npmrc",
            "/proc/././self/cwd/../home/.npmrc",
            "/proc/self/././cwd/../home/.npmrc",
            "/tmp/../proc/self/cwd/../home/.npmrc",
        ):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "proc or fd path alias"):
                self.read(event(path, uid=2000, pid=4))

    def test_malformed_packet_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "short trace header"):
            self.read(b"\x00")
        with self.assertRaisesRegex(ValueError, "invalid protobuf field length"):
            self.read(packet(7, b"\x0a\x20\x00"))
        root_context = number(4, 1) + blob(6, b"correct") + blob(7, b"")
        package_context = number(4, 4) + blob(6, b"correct") + blob(7, number(2, 2000))
        for kind, payload in (
            (1, blob(1, root_context) + blob(2, b"correct") + b"\x80"),
            (3, blob(1, package_context) + blob(2, b"/bin/probe") + b"\x80"),
            (7, blob(1, root_context) + blob(6, b"/rivet-audit-complete-fresh") + b"\x80"),
        ):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "truncated protobuf varint"):
                self.read(packet(kind, payload))
        self.assertFalse(self.result["started"])
        self.assertFalse(self.result["completed"])
        with self.assertRaisesRegex(ValueError, "truncated protobuf varint"):
            bad_credentials = blob(1, number(4, 4) + blob(6, b"correct") + blob(7, number(2, 2000) + b"\x80"))
            self.read(packet(3, bad_credentials + blob(2, b"/bin/probe")))
        with self.assertRaisesRegex(ValueError, "invalid trace effective UID"):
            wrong_uid_wire = blob(1, number(4, 4) + blob(6, b"correct") + blob(7, blob(2, b"2000")))
            self.read(packet(3, wrong_uid_wire + blob(2, b"/bin/probe")))


if __name__ == "__main__":
    unittest.main()
