#!/usr/bin/env python3
"""Disposable, unprivileged workloads and assertions for a running test observer."""
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import resource
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

socket_path = sys.argv[1]
user_home = Path(pwd.getpwuid(os.getuid()).pw_dir)
root = Path(tempfile.mkdtemp(prefix="electric-eye-regression-", dir=user_home))
(root / "a").mkdir()
(root / "b").mkdir()
expected = {}
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl(15, b"ee-regression", 0, 0, 0)


def request(op, **fields):
    with socket.socket(socket.AF_UNIX) as stream:
        stream.settimeout(3)
        stream.connect(socket_path)
        stream.sendall(json.dumps(dict(op=op, **fields)).encode() + b"\n")
        data = b""
        while chunk := stream.recv(65536):
            data += chunk
    result = json.loads(data)
    assert "error" not in result, result
    return result


def write(path, data):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        count = os.write(fd, data)
    finally:
        os.close(fd)
    expected[str(path.absolute())] = count


# Event-time cwd, directory descriptors, symlinks, and very short-lived writers.
os.chdir(root / "a")
write("relative-a", b"aaa")
os.chdir(root / "b")
write("relative-b", b"bbbb")
dirfd = os.open(root / "a", os.O_RDONLY | os.O_DIRECTORY)
fd = os.open("dirfd-file", os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=dirfd)
os.write(fd, b"dirfd")
os.close(fd)
expected[str(root / "a/dirfd-file")] = 5
os.symlink(root / "a", root / "link")
write(root / "link/symlink-file", b"symlink")
del expected[str(root / "link/symlink-file")]
expected[str(root / "a/symlink-file")] = 7
subprocess.run([sys.executable, "-c", "import os,sys; f=os.open(sys.argv[1],os.O_WRONLY|os.O_CREAT,0o600);os.write(f,b'child');os.close(f)", str(root / "short-child")], check=True)
expected[str(root / "short-child")] = 5

# A dup2 from an untracked pipe must not retain the previous file target.
stale = root / "stale-dup-target"
fd = os.open(stale, os.O_WRONLY | os.O_CREAT, 0o600)
r, w = os.pipe()
os.dup2(w, fd)
os.write(fd, b"not a file write")
os.close(fd)
os.close(w)
os.close(r)
expected[str(stale)] = 0

# A failed read-only-fd write must not add requested bytes.
write(root / "failed-write", b"seed")
fd = os.open(root / "failed-write", os.O_RDONLY)
try:
    os.write(fd, b"must not count")
    raise AssertionError("read-only write unexpectedly succeeded")
except OSError as error:
    assert error.errno == errno.EBADF
os.close(fd)

# RLIMIT_FSIZE produces both a real short write and an EFBIG failure.
old_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
old_handler = signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, (4, old_limit[1]))
fd = os.open(root / "short-write", os.O_WRONLY | os.O_CREAT, 0o600)
assert os.write(fd, b"x" * 4096) == 4
try:
    os.write(fd, b"still must not count")
    raise AssertionError("size-limited write unexpectedly succeeded")
except OSError as error:
    assert error.errno == errno.EFBIG
os.close(fd)
resource.setrlimit(resource.RLIMIT_FSIZE, old_limit)
signal.signal(signal.SIGXFSZ, old_handler)
expected[str(root / "short-write")] = 4

# Vectored writes must count all vectors, not the first 64 requested lengths.
fd = os.open(root / "writev", os.O_WRONLY | os.O_CREAT, 0o600)
assert os.writev(fd, [b"z"] * 100) == 100
os.close(fd)
expected[str(root / "writev")] = 100
source = os.open(root / "failed-write", os.O_RDONLY)
for operation in ("sendfile", "copy_file_range"):
    target = os.open(root / operation, os.O_WRONLY | os.O_CREAT, 0o600)
    os.lseek(source, 0, os.SEEK_SET)
    count = os.sendfile(target, source, None, 10000) if operation == "sendfile" else os.copy_file_range(source, target, 10000)
    assert count == 4
    os.close(target)
    expected[str(root / operation)] = 4
os.close(source)

# Mutations use successful syscall results and the VFS-resolved dirfd paths.
os.rename("dirfd-file", "dirfd-renamed", src_dir_fd=dirfd, dst_dir_fd=dirfd)
os.unlink("dirfd-renamed", dir_fd=dirfd)
missing = root / "nonexistent"
for operation in (lambda: os.unlink(missing), lambda: os.rename(missing, root / "never-renamed")):
    try:
        operation()
        raise AssertionError("missing-path mutation succeeded")
    except FileNotFoundError:
        pass
os.close(dirfd)

# A failed sensitive open is not a READ; a successful relative one is.
sensitive_dir = user_home / ".ssh"
sensitive_dir.mkdir(exist_ok=True)
sensitive = sensitive_dir / (root.name + "-fake-key")
write(sensitive, b"fake test key")
os.chdir(sensitive_dir)
fd = os.open(sensitive.name, os.O_RDONLY)
os.read(fd, 100)
os.close(fd)
try:
    os.open(sensitive.name + "-missing", os.O_RDONLY)
    raise AssertionError("missing sensitive file opened")
except FileNotFoundError:
    pass
os.chdir(root)

# More than 32 paths, plus pure document overwrites for the bulk rule.
(root / "Documents").mkdir()
for index in range(60):
    write(root / "Documents" / f"document-{index}", b"payload")

# Local network only. TCP/UDP return values feed immutable byte deltas.
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen()
port = listener.getsockname()[1]
errors = []


def server():
    try:
        with listener.accept()[0] as peer:
            while peer.recv(4096):
                pass
            peer.sendall(b"reply")
    except Exception as error:
        errors.append(error)


thread = threading.Thread(target=server)
thread.start()
with socket.create_connection(("127.0.0.1", port)) as client:
    client.sendall(b"payload")
    client.shutdown(socket.SHUT_WR)
    assert client.recv(100) == b"reply"
thread.join()
listener.close()
assert not errors, errors
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
    udp.bind(("127.0.0.1", 0))
    udp.sendto(b"udp", udp.getsockname())
    assert udp.recv(100) == b"udp"

# One idle API client must not hold capture or another API worker.
with socket.socket(socket.AF_UNIX) as slow:
    slow.connect(socket_path)
    write(root / "during-slow-client", b"captured")
    assert request("status")["daemon"] == "electric-eyed"

# Wait for the five-second aggregation window and the asynchronous writer.
time.sleep(6)
for path, count in expected.items():
    result = request("why", path=path)
    writes = [row for row in result["events"] if row["kind"] == "file.write"]
    actual = sum(row["bytes"] for row in writes)
    assert actual == count, (path, actual, count, result)
    for row in writes:
        assert row["entry"]["exe"], row
        assert row["entry"]["process"]["start_ns"] > 0, row
        assert row["entry"]["path_resolution"] == "kernel", row

assert all(row["kind"].endswith(".attempt") and row["entry"]["syscall_result"] < 0 for row in request("why", path=str(missing))["events"])
assert all(row["kind"].endswith(".attempt") for row in request("why", path=str(root / "never-renamed"))["events"])
reads = request("why", path=str(sensitive))["events"]
assert any(row["kind"] == "file.read" for row in reads), reads
failed_reads = request("why", path=str(sensitive) + "-missing")["events"]
assert failed_reads and all(row["kind"] == "file.read.attempt" and row["entry"]["syscall_result"] == -errno.ENOENT for row in failed_reads), failed_reads
rename = request("why", path=str(root / "a/dirfd-renamed"))["events"]
assert any(row["kind"] == "file.rename" and row["from_path"] == str(root / "a/dirfd-file") for row in rename), rename
assert any(row["kind"] == "file.unlink" for row in rename), rename
incidents = request("incidents")["incidents"]
assert any(row["details"]["rule"] == "bulk_mutation" for row in incidents), incidents
assert any(row.get("path") == str(sensitive) and row["process"]["start_ns"] > 0 and row["id"] for row in incidents), incidents
network = request("network", limit=1000)["events"]
accepts = [row for row in network if row["kind"] == "net.accept" and row["local_port"] == port]
assert accepts and accepts[0]["comm"] == "ee-regression", accepts
traffic = [row["entry"]["event"] for row in network if row["kind"] == "net.traffic" and row["comm"] == "ee-regression" and row["pid"] == os.getpid()]
assert sum(row["sent"] for row in traffic) == 15, traffic
assert sum(row["recv"] for row in traffic) == 15, traffic
status = request("status")
assert not any(status["capture_loss"]), status
assert status["store"]["dropped"] == 0, status
print(json.dumps({"result": "passed", "root": str(root), "verified_write_paths": len(expected), "capture_loss": status["capture_loss"]}))
# Keep disposable artifacts for inspection; never touch unrelated files.
