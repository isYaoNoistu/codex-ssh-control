"""Real Linux openat2 tests; pure policy tests also run on Windows.

Run: python3 -B test/guard_test.py -v
Fixtures are confined to a fresh /tmp directory and cleaned by TemporaryDirectory.
No SSH, network, mount, daemon, or system configuration changes are performed.
"""
import base64
import contextlib
import ctypes
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import socket
import stat
import struct
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("file_guard", Path(__file__).resolve().parents[1] / "remote" / "guard.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


def set_attribute(path, name, value):
    """Use libc so stripped Python builds still create real kernel xattr fixtures."""
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.setxattr(ctypes.c_char_p(os.fsencode(path)), ctypes.c_char_p(name.encode()), ctypes.c_char_p(value), ctypes.c_size_t(len(value)), ctypes.c_int(0))
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


def get_attribute(path, name):
    libc = ctypes.CDLL(None, use_errno=True)
    libc.getxattr.restype = ctypes.c_ssize_t
    size = libc.getxattr(ctypes.c_char_p(os.fsencode(path)), ctypes.c_char_p(name.encode()), None, ctypes.c_size_t(0))
    if size < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    buffer = ctypes.create_string_buffer(size)
    actual = libc.getxattr(ctypes.c_char_p(os.fsencode(path)), ctypes.c_char_p(name.encode()), buffer, ctypes.c_size_t(size))
    if actual < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return buffer.raw[:actual]

class GuardPolicyTests(unittest.TestCase):
    def test_docker_auth_content_is_sensitive_at_any_path(self):
        auth = base64.b64encode(b"fixture-user:fixture-password").decode()
        config = {"auths": {"registry.example.invalid": {"auth": auth}}}
        for text in [json.dumps(config), json.dumps(config, indent=2), json.dumps(config).replace("auths", "a\\u0075ths").replace('"auth"', '"a\\u0075th"'), 'output:\n"auth": "' + auth + '"\nend']:
            with self.subTest(text=text):
                self.assertTrue(guard.sensitive(text))
        for text in ['{"auth":true}', '{"auth":"required"}', '{"auth":"dGVzdA=="}', '{"auths":{}}', '{"auths":{"registry.example.invalid":{}}}', '{"auths":{"registry.example.invalid":{"auth":""}},"credsStore":"desktop"}', '{"auths":{"registry.example.invalid":{"auth":null}}}']:
            with self.subTest(text=text):
                self.assertFalse(guard.sensitive(text))

    def test_sensitive_content_matches_local_policy_examples(self):
        for text in ["-----BEGIN OPENSSH PRIVATE KEY-----\nfixture", "password=hunter2", 'export API_TOKEN="abc123"', "AWS_SECRET_ACCESS_KEY=abc", '{"client_secret":"abc"}', "Authorization: Bearer abc", "Authorization: Basic dGVzdA==", "postgres://user:pass@db/app", "pwd=abc", "private_key=abc", "credential=abc", "authorization=abc"]:
            with self.subTest(text=text):
                self.assertTrue(guard.sensitive(text))
        for text in ["port=8080", '{"host":"localhost"}', "password=", 'password=""', "token: null", "token: false", "# credential documentation"]:
            with self.subTest(text=text):
                self.assertFalse(guard.sensitive(text))

    def test_protected_paths_match_local_policy_examples(self):
        for path in ["/proc/self/environ", "/sys/kernel/a", "/dev/null", "/run/docker.sock", "/etc/ssh/config", "/etc/ssl/private/a", "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/group", "/home/u/.ssh/config", "/a/.aws/config", "/a/.azure/a", "/a/.kube/config", "/a/.gnupg/a", "/srv/.env", "/srv/.env.production", "/srv/id_rsa.pub", "/srv/id_ed25519", "/srv/cert.pem", "/srv/client.key", "/srv/my-credentials.json", "/srv/secrets.txt", "/etc/sudoers", "/etc/sudoers.d/deploy", "/etc/pam.d/login", "/etc/security/access.conf", "/etc/cron.daily/job", "/etc/crontab", "/etc/systemd/system/app.service", "/etc/docker/daemon.json", "/etc/ufw/user.rules", "/etc/nftables.conf", "/etc/iptables/rules.v4", "/home/u/.bashrc", "/home/u/.profile", "/home/u/.zshrc", "/home/u/.config/fish/config.fish"]:
            with self.subTest(path=path):
                self.assertTrue(guard.protected(path, []))
        self.assertFalse(guard.protected("/etc/passwd-backup", []))
        self.assertFalse(guard.protected("/srv/app/cache-other", ["/srv/app/cache"]))
        self.assertTrue(guard.protected("/srv/app/cache/file", ["/srv/app/cache"]))

    def test_ambiguous_paths_are_rejected_before_syscalls(self):
        for path in ["relative", "/a/../b", "/a/./b", "/a//b", "/a\x00b", "/a\x7fb", "/a\\b", "/a\nb"]:
            with self.subTest(path=repr(path)):
                with self.assertRaises(guard.Denied):
                    guard.valid_path(path)

    def test_errors_never_include_request_content(self):
        request = {"operation": {"kind": "read", "path": "/bad"}, "root": "/allowed", "relativePath": "bad", "blockedPaths": [], "unexpected": "private-fixture-text"}
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            guard.main(request)
        result = json.loads(output.getvalue())
        self.assertFalse(result["ok"])
        self.assertNotIn("private-fixture-text", output.getvalue())


@unittest.skipUnless(platform.system() == "Linux", "real openat2 requires Linux")
class GuardLinuxTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix="ssh-guard-test-", dir="/tmp")
        self.addCleanup(self.fixture.cleanup)
        self.base = Path(self.fixture.name)
        self.root = self.base / "allowed"
        self.outside = self.base / "outside"
        self.root.mkdir()
        self.outside.mkdir()
        self.outside_file = self.outside / "unchanged.txt"
        self.outside_file.write_text("outside-sentinel", encoding="utf-8")
        self.original_outside_inode = self.outside_file.stat().st_ino
        self.addCleanup(self.verify_outside_unchanged)

    def verify_outside_unchanged(self):
        self.assertEqual(self.outside_file.read_text(encoding="utf-8"), "outside-sentinel")
        self.assertEqual(self.outside_file.stat().st_ino, self.original_outside_inode)
        self.assertEqual(sorted(p.name for p in self.outside.iterdir()), ["unchanged.txt"])

    def request(self, kind, relative="a.txt", content=None, **changes):
        operation = {"kind": kind, "path": str(self.root / relative)}
        if kind == "write":
            operation["content"] = "new contents" if content is None else content
        request = {"operation": operation, "root": str(self.root), "relativePath": relative, "blockedPaths": []}
        request.update(changes)
        return request

    def denied(self, request):
        with self.assertRaises((guard.Denied, OSError)):
            guard.handle(request)

    def test_read_create_replace_delete_roundtrip_and_mode(self):
        self.assertEqual(guard.handle(self.request("write", content="plain 中文")), {"written": True, "bytes": len("plain 中文".encode())})
        self.assertEqual(guard.handle(self.request("read")), {"content": "plain 中文"})
        path = self.root / "a.txt"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        path.chmod(0o755)
        self.assertTrue(guard.handle(self.request("write", content="updated"))["written"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
        self.assertTrue(guard.handle(self.request("delete"))["deleted"])
        self.assertFalse(path.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_docker_directory_is_hidden_and_cannot_be_read_or_modified(self):
        directory = self.root / ".docker"
        directory.mkdir()
        path = directory / "config.json"
        path.write_text("{}", encoding="utf-8")
        self.assertEqual(guard.handle(self.request("list", "."))["entries"], [])
        self.denied(self.request("list", ".docker"))
        for kind in ["read", "write", "delete"]:
            self.denied(self.request(kind, ".docker/config.json"))
            self.assertEqual(path.read_text(encoding="utf-8"), "{}")

    def test_renamed_docker_auth_file_never_returns_changes_or_deletes(self):
        content = json.dumps({"auths": {"registry.example.invalid": {"auth": base64.b64encode(b"fixture-user:fixture-password").decode()}}})
        path = self.root / "config-copy.json"
        path.write_text(content, encoding="utf-8")
        for kind in ["read", "write", "delete"]:
            self.denied(self.request(kind, "config-copy.json", content="{}"))
            self.assertEqual(path.read_text(encoding="utf-8"), content)
        self.denied(self.request("write", "new-config.json", content=content))
        self.assertFalse((self.root / "new-config.json").exists())
        safe = '{"auths":{},"auth":true}'
        self.assertTrue(guard.handle(self.request("write", "ordinary-config.json", content=safe))["written"])
        self.assertEqual(guard.handle(self.request("read", "ordinary-config.json")), {"content": safe})

    def test_replace_preserves_nonroot_owner_group_and_ordinary_modes(self):
        if os.geteuid() != 0:
            self.skipTest("changing fixture owner/group requires root")
        path = self.root / "a.txt"
        for mode in [0o600, 0o640, 0o750, 0o755]:
            with self.subTest(mode=oct(mode)):
                path.write_text("original", encoding="utf-8")
                os.chown(path, 12345, 23456)
                path.chmod(mode)
                before = path.stat()
                self.assertTrue(guard.handle(self.request("write", content="replacement"))["written"])
                after = path.stat()
                self.assertEqual(path.read_text(encoding="utf-8"), "replacement")
                self.assertEqual((after.st_uid, after.st_gid), (12345, 23456))
                self.assertEqual(stat.S_IMODE(after.st_mode), mode)
                self.assertNotEqual(after.st_ino, before.st_ino)
                self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["a.txt"])

    def test_extended_attribute_overwrite_is_denied_without_modification(self):
        path = self.root / "a.txt"
        path.write_text("original", encoding="utf-8")
        path.chmod(0o640)
        set_attribute(path, "user.guard-test", b"fixture-metadata")
        before = path.stat()
        with self.assertRaisesRegex(guard.Denied, "ACL|扩展属性"):
            guard.handle(self.request("write", content="replacement"))
        after = path.stat()
        self.assertEqual(path.read_text(encoding="utf-8"), "original")
        self.assertEqual(get_attribute(path, "user.guard-test"), b"fixture-metadata")
        self.assertEqual((after.st_ino, after.st_uid, after.st_gid, after.st_mode, after.st_mtime_ns), (before.st_ino, before.st_uid, before.st_gid, before.st_mode, before.st_mtime_ns))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["a.txt"])

    def test_posix_acl_overwrite_is_denied_without_modification(self):
        path = self.root / "a.txt"
        path.write_text("original", encoding="utf-8")
        # Linux POSIX ACL v2 with an additional read-only user; fixture only.
        entries = [(0x01, 6, 0xFFFFFFFF), (0x02, 4, 12345), (0x04, 4, 0xFFFFFFFF), (0x10, 4, 0xFFFFFFFF), (0x20, 0, 0xFFFFFFFF)]
        acl = struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)
        set_attribute(path, "system.posix_acl_access", acl)
        before = path.stat()
        self.assertEqual(get_attribute(path, "system.posix_acl_access"), acl)
        with self.assertRaisesRegex(guard.Denied, "ACL|扩展属性"):
            guard.handle(self.request("write", content="replacement"))
        after = path.stat()
        self.assertEqual(path.read_text(encoding="utf-8"), "original")
        self.assertEqual(get_attribute(path, "system.posix_acl_access"), acl)
        self.assertEqual((after.st_ino, after.st_mode, after.st_mtime_ns), (before.st_ino, before.st_mode, before.st_mtime_ns))
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["a.txt"])

    def test_traversal_prefix_collision_and_relative_mismatch(self):
        for target, relative in [(str(self.root / ".." / "outside" / "unchanged.txt"), "../outside/unchanged.txt"), (str(self.root) + "-other/a", "a"), (str(self.outside_file), "a")]:
            for kind in ["read", "write", "delete"]:
                request = self.request(kind)
                request["operation"]["path"] = target
                request["relativePath"] = relative
                self.denied(request)
        request = self.request("read")
        request["relativePath"] = "other.txt"
        self.denied(request)

    def test_symlink_at_leaf_parent_and_authorized_root_never_follows(self):
        (self.root / "link.txt").symlink_to(self.outside_file)
        (self.root / "parent").symlink_to(self.outside, target_is_directory=True)
        root_link = self.base / "root-link"
        root_link.symlink_to(self.root, target_is_directory=True)
        for kind in ["read", "write", "delete"]:
            self.denied(self.request(kind, "link.txt"))
            self.denied(self.request(kind, "parent/unchanged.txt"))
            request = self.request(kind)
            request["root"] = str(root_link)
            request["operation"]["path"] = str(root_link / "a.txt")
            self.denied(request)
        self.assertTrue((self.root / "link.txt").is_symlink())

    def test_hardlinks_and_special_files_reject_without_blocking(self):
        os.link(self.outside_file, self.root / "linked.txt")
        os.mkfifo(self.root / "pipe")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(sock.close)
        sock.bind(str(self.root / "socket"))
        for relative in ["linked.txt", "pipe", "socket"]:
            for kind in ["read", "write", "delete"]:
                started = time.monotonic()
                self.denied(self.request(kind, relative))
                self.assertLess(time.monotonic() - started, 1, (kind, relative))
        (self.root / "linked.txt").unlink()

    def test_setuid_and_directory_file_operations_reject(self):
        path = self.root / "a.txt"
        path.write_text("safe", encoding="utf-8")
        path.chmod(0o4755)
        for kind in ["read", "write", "delete"]:
            self.denied(self.request(kind))
            self.denied(self.request(kind, "."))
        (self.root / "dir").mkdir()
        for kind in ["read", "write", "delete"]:
            self.denied(self.request(kind, "dir"))

    def test_protected_entries_links_and_hardlinks_are_hidden_from_list(self):
        (self.root / "ok.txt").write_text("ok", encoding="utf-8")
        (self.root / "b-dir").mkdir()
        (self.root / ".env").write_text("x", encoding="utf-8")
        (self.root / "blocked").mkdir()
        (self.root / "link").symlink_to(self.outside_file)
        os.link(self.outside_file, self.root / "hardlink")
        os.mkfifo(self.root / "pipe")
        request = self.request("list", ".", blockedPaths=[str(self.root / "blocked")])
        result = guard.handle(request)
        self.assertEqual([entry["name"] for entry in result["entries"]], ["b-dir", "ok.txt"])
        self.assertFalse(result["truncated"])
        (self.root / "hardlink").unlink()

    def test_read_limits_invalid_utf8_and_binary_content(self):
        path = self.root / "a.txt"
        for data in [b"x" * (guard.MAX_BYTES + 1), b"\xff\xfe", b"abc\x00def"]:
            path.write_bytes(data)
            self.denied(self.request("read"))
        path.write_text("abcd", encoding="utf-8")
        self.denied(self.request("read", limit=3))
        self.assertEqual(guard.handle(self.request("read", limit=4)), {"content": "abcd"})

    def test_sensitive_existing_content_never_returns_changes_or_deletes(self):
        path = self.root / "a.txt"
        for content in ["password=fixture", "Authorization: Bearer fixture", "postgres://test:fixture@host/db", "private_key=fixture"]:
            path.write_text(content, encoding="utf-8")
            for kind in ["read", "write", "delete"]:
                with self.subTest(kind=kind, content=content):
                    self.denied(self.request(kind, content="safe replacement"))
                    self.assertEqual(path.read_text(encoding="utf-8"), content)

    def test_sensitive_new_content_never_creates_file(self):
        for content in ["password=fixture", "Authorization: Bearer fixture", "postgres://test:fixture@host/db", "private_key=fixture"]:
            with self.subTest(content=content):
                self.denied(self.request("write", content=content))
                self.assertFalse((self.root / "a.txt").exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_mount_boundaries_are_rejected_by_kernel_resolution(self):
        root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaises(OSError) as caught:
                guard.openat2(root_fd, "proc", os.O_RDONLY | os.O_DIRECTORY)
            self.assertEqual(caught.exception.errno, errno.EXDEV)
        finally:
            os.close(root_fd)

    def test_large_directory_output_is_bounded_and_reports_truncation(self):
        for index in range(600):
            (self.root / ("entry-%04d.txt" % index)).write_text("x", encoding="utf-8")
        result = guard.handle(self.request("list", ".", limit=16384))
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["entries"]), 512)
        self.assertLess(len(json.dumps(result, ensure_ascii=False).encode("utf-8")), 16384)

    def test_failed_atomic_replace_cleans_temporary_file_and_preserves_original(self):
        path = self.root / "a.txt"
        path.write_text("original", encoding="utf-8")
        with patch.object(guard.os, "replace", side_effect=OSError(errno.EIO, "simulated failure")):
            self.denied(self.request("write", content="replacement"))
        self.assertEqual(path.read_text(encoding="utf-8"), "original")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["a.txt"])

    def test_unsupported_platform_fails_closed(self):
        with patch.object(guard.platform, "system", return_value="Unsupported"):
            self.denied(self.request("write"))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_symlink_swap_race_never_reads_or_modifies_outside(self):
        leaf = self.root / "racy"
        stop = threading.Event()
        def swap():
            while not stop.is_set():
                try:
                    leaf.symlink_to(self.outside_file)
                except FileExistsError:
                    pass
                try:
                    leaf.unlink()
                except FileNotFoundError:
                    pass
        worker = threading.Thread(target=swap, daemon=True)
        worker.start()
        try:
            for _ in range(120):
                for kind in ["read", "write", "delete"]:
                    try:
                        result = guard.handle(self.request(kind, "racy"))
                    except (guard.Denied, OSError):
                        continue
                    if kind == "read":
                        self.assertNotEqual(result["content"], "outside-sentinel")
        finally:
            stop.set()
            worker.join(timeout=2)
            self.assertFalse(worker.is_alive())


if __name__ == "__main__":
    unittest.main()
