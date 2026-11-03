"""One-shot Linux file broker. Source and one request arrive through SSH stdin.

The remote OS/admin is trusted. Every lookup uses openat2; there is no unsafe
fallback. Requests cannot provide executable Python or choose resolution flags.
"""
import base64
import ctypes
import errno
import json
import os
import platform
import re
import secrets
import stat

MAX_BYTES = 128 * 1024
CORE = ("/proc", "/sys", "/dev", "/run", "/etc/ssh", "/etc/ssl/private",
        "/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/group",
        "/etc/sudoers", "/etc/sudoers.d", "/etc/pam.d", "/etc/security",
        "/etc/systemd", "/etc/docker", "/etc/ufw", "/etc/nftables.conf", "/etc/iptables",
        "/etc/firewalld", "/etc/fail2ban", "/etc/audit", "/etc/selinux", "/etc/apparmor",
        "/etc/apparmor.d", "/etc/environment", "/etc/profile", "/etc/profile.d",
        "/etc/bash.bashrc", "/etc/ld.so.preload", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/fish")
SEGMENTS = {".ssh", ".aws", ".azure", ".kube", ".gnupg", ".docker"}
STARTUP = {".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshrc", ".zprofile", ".zshenv", ".zlogin"}


class Denied(Exception):
    pass


def valid_path(value):
    if (not isinstance(value, str) or not value.startswith("/") or len(value) > 4096
            or any(ord(c) < 32 or ord(c) == 127 for c in value) or "\\" in value or "//" in value
            or any(p in (".", "..") for p in value.split("/"))):
        raise Denied("路径格式无效")
    return value.rstrip("/") or "/"


def within(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def protected(path, blocked):
    parts = path.lower().split("/")
    name = parts[-1]
    return (any(within(path.lower(), item) for item in CORE) or any(within(path, item) for item in blocked)
            or any(p in SEGMENTS or p in STARTUP or p.startswith((".env", "id_rsa", "id_ed25519"))
                   or p.endswith((".pem", ".key")) or "credential" in p or "secret" in p for p in parts)
            or path.lower().startswith("/etc/cron") or "/.config/fish/" in path.lower() + "/")


def sensitive(text):
    if re.search(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----", text):
        return True
    if re.search(r"\bAuthorization\s*:\s*(?:Bearer|Basic)\s+\S+|\b[a-z][a-z0-9+.-]*://[^\s/:]+:[^\s/@]+@", text, re.I):
        return True
    # Docker config may be renamed or live under DOCKER_CONFIG; decode JSON keys too.
    try:
        config = json.loads(text)
        auths = config.get("auths") if isinstance(config, dict) else None
        if isinstance(auths, dict) and any(isinstance(entry, dict) and isinstance(entry.get("auth"), str) and entry["auth"].strip() for entry in auths.values()):
            return True
    except (ValueError, RecursionError):
        pass  # Streamed/non-JSON content is checked by the assignment scanner below.
    for match in re.finditer(r"(?:^|[\s{,;])[\"']?auth[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9+/]+={0,2})(?=[\"'\s,;}]|$)", text, re.I):
        value = match[1]
        try:
            decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
            if b":" in decoded and base64.b64encode(decoded).decode().rstrip("=") == value.rstrip("="):
                return True
        except ValueError:
            pass
    assignments = re.finditer(r"(?:^|[\s{,;])(?:export\s+)?[\"']?([A-Za-z_][A-Za-z0-9_.-]*)[\"']?\s*[:=]\s*([^\r\n,;}]+)", text)
    for match in assignments:
        if not re.search(r"password|passwd|(?:^|[_.-])pwd(?:$|[_.-])|token|secret|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization", match[1], re.I):
            continue
        value = re.sub(r"^[\"']|[\"']$", "", match[2].strip()).strip()
        if value and value.lower() not in ("null", "none", "false"):
            return True
    return False


class OpenHow(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_uint64), ("mode", ctypes.c_uint64), ("resolve", ctypes.c_uint64)]


def openat2(directory, path, flags, *, root=False, mode=0):
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "aarch64", "riscv64"):
        raise Denied("文件工具需要 Linux openat2；不支持时拒绝访问")
    # Root may be its own mount. Descendants cannot cross mount boundaries.
    resolve = 0x02 | 0x04 | (0 if root else 0x08 | 0x01)
    how = OpenHow(flags | os.O_CLOEXEC | os.O_NOFOLLOW, mode, resolve)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(ctypes.c_long(437), ctypes.c_int(directory), ctypes.c_char_p(os.fsencode(path)),
                          ctypes.byref(how), ctypes.sizeof(how))
    if result < 0:
        error = ctypes.get_errno()
        if error in (errno.ENOSYS, errno.EINVAL):
            raise Denied("内核不支持安全路径解析，已拒绝访问")
        raise OSError(error, os.strerror(error))
    return result


def regular(fd):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise Denied("只允许无硬链接的普通文件")
    if info.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise Denied("禁止访问带有特殊权限的文件")
    return info


def has_extended_attributes(fd):
    # Some standalone Python builds omit os.listxattr even on a capable Linux.
    # Use the same pinned descriptor with libc; failure never permits overwrite.
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        function = libc.flistxattr
    except AttributeError:
        raise Denied("无法检查文件扩展属性，已拒绝覆盖")
    function.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
    function.restype = ctypes.c_ssize_t
    size = function(fd, None, 0)
    if size < 0:
        raise Denied("无法检查文件扩展属性，已拒绝覆盖")
    return size > 0


def read_text(fd, limit):
    info = regular(fd)
    if info.st_size > limit:
        raise Denied("文件超过读取限制")
    data = bytearray()
    while len(data) <= limit:
        chunk = os.read(fd, min(8192, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    if len(data) > limit:
        raise Denied("文件超过读取限制")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise Denied("只支持 UTF-8 文本文件")
    if "\x00" in text or sensitive(text):
        raise Denied("文件包含敏感信息或非文本内容，未返回内容")
    return text


def handle(request):
    if not isinstance(request, dict) or set(request) - {"operation", "root", "relativePath", "blockedPaths", "limit"}:
        raise Denied("请求格式无效")
    operation = request["operation"]
    if not isinstance(operation, dict) or set(operation) - {"kind", "path", "content"}:
        raise Denied("操作格式无效")
    kind = operation.get("kind")
    if kind not in ("list", "read", "write", "delete"):
        raise Denied("不支持的文件操作")
    target, root = valid_path(operation["path"]), valid_path(request["root"])
    blocked = [valid_path(p) for p in request["blockedPaths"]]
    if not within(target, root) or protected(target, blocked) or protected(root, blocked):
        raise Denied("目录不在授权范围内，或属于保护路径")
    relative = os.path.relpath(target, root)
    if relative != request["relativePath"]:
        raise Denied("路径范围不一致")
    limit = request.get("limit", MAX_BYTES)
    if type(limit) is not int or not 1 <= limit <= MAX_BYTES:
        raise Denied("输出限制无效")
    root_fd = openat2(-100, root, os.O_RDONLY | os.O_DIRECTORY, root=True)
    try:
        if kind == "list":
            fd = openat2(root_fd, relative, os.O_RDONLY | os.O_DIRECTORY)
            try:
                entries, total, truncated = [], 0, False
                with os.scandir(fd) as iterator:
                    for entry in iterator:
                        if protected(target.rstrip("/") + "/" + entry.name, blocked):
                            continue
                        info = entry.stat(follow_symlinks=False)
                        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode) and info.st_nlink == 1):
                            continue
                        item = {"name": entry.name, "type": "directory" if stat.S_ISDIR(info.st_mode) else "file", "bytes": info.st_size}
                        size = len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
                        if len(entries) >= 512 or total + size > max(512, limit - 1024):
                            truncated = True
                            break
                        entries.append(item)
                        total += size
                return {"entries": sorted(entries, key=lambda e: e["name"]), "truncated": truncated}
            finally:
                os.close(fd)
        if relative == ".":
            raise Denied("不能将授权根目录作为文件操作")
        if kind == "read":
            fd = openat2(root_fd, relative, os.O_RDONLY | os.O_NONBLOCK)
            try:
                return {"content": read_text(fd, limit)}
            finally:
                os.close(fd)
        parent, name = os.path.split(relative)
        parent_fd = openat2(root_fd, parent or ".", os.O_RDONLY | os.O_DIRECTORY)
        try:
            existing = None
            try:
                fd = openat2(parent_fd, name, os.O_RDONLY | os.O_NONBLOCK)
            except FileNotFoundError:
                if kind == "delete":
                    raise
            else:
                try:
                    existing = regular(fd)
                    read_text(fd, MAX_BYTES)  # Never replace/delete a recognized secret.
                    if kind == "write" and has_extended_attributes(fd):
                        raise Denied("文件具有 ACL 或扩展属性，安全写入不支持覆盖此类文件")
                finally:
                    os.close(fd)
            if kind == "delete":
                # unlinkat never follows a last-component symlink; parent is pinned.
                os.unlink(name, dir_fd=parent_fd)
                os.fsync(parent_fd)
                return {"deleted": True}
            content = operation.get("content")
            if not isinstance(content, str) or len(content.encode("utf-8")) > MAX_BYTES or "\x00" in content or sensitive(content):
                raise Denied("写入内容过大、非文本或包含敏感信息")
            temporary = ".ssh-control-" + secrets.token_hex(16) + ".tmp"
            temporary_fd = openat2(parent_fd, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode=0o600)
            try:
                data = content.encode("utf-8")
                offset = 0
                while offset < len(data):
                    offset += os.write(temporary_fd, data[offset:])
                # Preserve ordinary mode and ownership. Files needing ACL/xattr
                # preservation were rejected above, before creating a temp file.
                if existing:
                    temporary_info = os.fstat(temporary_fd)
                    if (temporary_info.st_uid, temporary_info.st_gid) != (existing.st_uid, existing.st_gid):
                        os.fchown(temporary_fd, existing.st_uid, existing.st_gid)
                    os.fchmod(temporary_fd, stat.S_IMODE(existing.st_mode) & 0o777)
                os.fsync(temporary_fd)
                os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                os.fsync(parent_fd)
            finally:
                os.close(temporary_fd)
                try:
                    os.unlink(temporary, dir_fd=parent_fd)
                except FileNotFoundError:
                    pass
            return {"written": True, "bytes": len(data)}
        finally:
            os.close(parent_fd)
    finally:
        os.close(root_fd)


def main(request):
    try:
        result = {"ok": True, "result": handle(request)}
    except (Denied, OSError, KeyError, ValueError, TypeError) as error:
        # Never return file data or exception paths in errors.
        reason = str(error) if isinstance(error, Denied) else "文件访问失败（路径、类型或权限不满足安全规则）"
        result = {"ok": False, "error": reason}
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
