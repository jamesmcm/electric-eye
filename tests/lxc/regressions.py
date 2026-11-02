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

# Standalone truncation (including symlink traversal) and legacy creat.
truncate_path=root/"truncate-target"
write(truncate_path,b"original")
os.symlink(truncate_path,root/"truncate-link")
os.truncate(root/"truncate-link",3)
truncate_fd=os.open(truncate_path,os.O_WRONLY)
os.ftruncate(truncate_fd,2);os.close(truncate_fd)
truncate_fd=os.open(truncate_path,os.O_RDONLY)
try:
    os.ftruncate(truncate_fd,0)
    raise AssertionError("read-only ftruncate unexpectedly succeeded")
except OSError: pass
os.close(truncate_fd)
legacy=root/"legacy-creat"
legacy_fd=libc.creat(os.fsencode(legacy),0o600)
assert legacy_fd>=0
os.close(legacy_fd)
expected[str(legacy)]=0

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
# Freshly created files are treated as generated output; wait past the bulk
# window before overwriting so the birth times are old enough to count.
(root / "Documents").mkdir()
for index in range(60):
    write(root / "Documents" / f"document-{index}", b"payload")
time.sleep(11)
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
write(root / "network-received-file", b"download-like")
listener.close()
assert not errors, errors
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
    udp.bind(("127.0.0.1", 0))
    udp.sendto(b"udp", udp.getsockname())
    assert udp.recv(100) == b"udp"

# The same lifecycle and byte attribution must work for IPv6.
v6=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);v6.bind(("::1",0));v6.listen();v6_port=v6.getsockname()[1]
def v6_server():
    with v6.accept()[0] as peer:
        assert peer.recv(100)==b"v6";peer.sendall(b"six")
v6_thread=threading.Thread(target=v6_server);v6_thread.start()
with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as client:
    client.connect(("::1",v6_port));client.sendall(b"v6");assert client.recv(100)==b"six"
v6_thread.join();v6.close()
with socket.socket(socket.AF_INET6,socket.SOCK_DGRAM) as v6_udp:
    v6_udp.bind(("::1",0));v6_udp_port=v6_udp.getsockname()[1];v6_udp.sendto(b"uv6",("::1",v6_udp_port));assert v6_udp.recv(100)==b"uv6"

# A fork-only child must retain exact ancestry and metadata after it exits.
fork_child=os.fork()
if fork_child==0:
    fd=os.open(root/"fork-only",os.O_WRONLY|os.O_CREAT,0o600);os.write(fd,b"fork");os.close(fd);os._exit(23)
os.waitpid(fork_child,0)
expected[str(root/"fork-only")]=4
secret="DO-NOT-PERSIST-THIS-TOKEN"
exec_child=subprocess.Popen([sys.executable,"-c","pass","--token",secret]);exec_child.wait()

# A shared UDP socket has one creator and separate contributing processes.
shared=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);shared.bind(("127.0.0.1",0));shared_port=shared.getsockname()[1]
shared_child=os.fork()
if shared_child==0:
    shared.sendto(b"share",("127.0.0.1",shared_port));os._exit(0)
assert shared.recv(100)==b"share";os.waitpid(shared_child,0);shared.close()
# A refused local connect must be represented as failure, not establishment.
probe=socket.socket();probe.bind(("127.0.0.1",0));refused_port=probe.getsockname()[1];probe.close()
refused = socket.socket()
try:
    refused.connect(("127.0.0.1", refused_port))
    raise AssertionError("unused port unexpectedly accepted")
except ConnectionRefusedError:
    pass
# The connect call consumed the error. Reading zero must retain the failure.
assert refused.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0
refused.close()

# IPv4-mapped loopback remains local for detection, even after a credential read.
with socket.socket(socket.AF_INET6) as mapped:
    try:
        mapped.connect(("::ffff:127.0.0.1", refused_port))
        raise AssertionError("unused mapped port unexpectedly accepted")
    except ConnectionRefusedError:
        pass

# Connecting UDP configures a peer without transmitting any external packets.
# Its destination must nevertheless reach history and the egress rule.
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connected_udp:
    connected_udp.connect(("8.8.8.8", 55443))

# Real compiler workload for process-tree build correlation.
source=root/"build-test.c"
write(source,b"int answer(void) { return 42; }\n")
subprocess.run(["cc","-c",str(source),"-o",str(root/"build-test.o")],check=True)
# A complete write-then-rename sequence (same process and exec generation).
write(root/"save-temporary",b"saved")
os.rename(root/"save-temporary",root/"saved-config")

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

truncations=request("why",path=str(truncate_path))["events"]
assert sum(row["kind"]=="file.truncate" for row in truncations)>=3,truncations
assert any(row["kind"]=="file.truncate.attempt" and row["entry"]["syscall_result"]<0 for row in truncations),truncations
assert all(row["entry"]["path_resolution"]=="kernel" for row in truncations if row["kind"]=="file.truncate"),truncations
assert any(row["kind"]=="file.truncate" for row in request("why",path=str(legacy))["events"])

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
assert not any(row["details"].get("rule")=="sensitive_egress" and "::ffff:127.0.0.1" in row["details"].get("destination", "") for row in incidents), incidents
assert any(row["details"].get("rule")=="sensitive_egress" and row["details"].get("destination")=="8.8.8.8:55443" for row in incidents), incidents
assert any(row.get("path") == str(sensitive) and row["process"]["start_ns"] > 0 and row["id"] for row in incidents), incidents
network = request("network", limit=1000)["events"]
assert any(row["kind"]=="net.connect" and row["addr"]=="8.8.8.8" and row["remote_port"]==55443 for row in network), network
accepts = [row for row in network if row["kind"] == "net.accept" and row["local_port"] == port]
assert accepts and accepts[0]["comm"] == "ee-regression", accepts
traffic = [row["entry"]["event"] for row in network if row["kind"] == "net.traffic" and row["comm"] == "ee-regression" and row["pid"] == os.getpid()]
assert sum(row["sent"] for row in traffic) == 23, traffic
assert sum(row["recv"] for row in traffic) == 28, traffic
fork_rows=request("process",process=str(fork_child))["processes"]
assert fork_rows and fork_rows[0]["exit_code"]==23, fork_rows
assert fork_rows[0]["parent"]["pid"]==os.getpid() and fork_rows[0]["parent"]["start_ns"]>0, fork_rows
assert fork_rows[0]["cwd"]==str(root) and fork_rows[0]["cgroup"], fork_rows
exec_rows=request("process",process=str(exec_child.pid))
assert exec_rows["execs"] and "[redacted]" in exec_rows["processes"][0]["argv"],exec_rows
assert secret not in json.dumps(exec_rows),exec_rows
assert any(p["identity"]["pid"]==fork_child for p in request("tree",process=str(os.getpid()))["processes"])
flows=request("flows",limit=1000)["flows"]
tcp=[f for f in flows if f["protocol"]=="TCP" and (f["remote"].endswith(":"+str(port)) or f["local"].endswith(":"+str(port)))]
assert any(f["sent"]==7 and f["received"]==5 for f in tcp),tcp
assert any(f["sent"]==5 and f["received"]==7 for f in tcp),tcp
assert all(f["closed_ms"] is not None for f in tcp),tcp
assert any(f["state"]=="failed" and f["errno"]==errno.ECONNREFUSED and f["remote"].endswith(":"+str(refused_port)) for f in flows),flows
assert any(f["remote"]=="[::1]:"+str(v6_port) and f["sent"]==2 and f["received"]==3 and f["closed_ms"] is not None for f in flows),flows
assert any(f["remote"]=="[::1]:"+str(v6_udp_port) and f["sent"]==3 and f["received"]==3 and f["closed_ms"] is not None for f in flows),flows
shared_rows=[f for f in flows if f["kind"]=="udp_peer" and f["remote"].endswith(":"+str(shared_port))]
assert shared_rows and shared_rows[0]["sent"]==5 and shared_rows[0]["received"]==5,shared_rows
assert len(shared_rows[0]["contributors"])==2 and shared_rows[0]["owner"]["pid"]==os.getpid(),shared_rows
assert exec_rows["processes"][0]["package"]["package"]["name"]=="python",exec_rows
assert exec_rows["processes"][0]["application"]["task_id"],exec_rows
summaries=request("summaries",limit=1000)["summaries"]
assert any(s["kind"]=="build_session" and str(root/"build-test.o") in s["files"] and s["root_exit_code"]==0 for s in summaries),summaries
assert any(s["kind"]=="save_sequence" and str(root/"saved-config") in s["files"] and len(s["evidence"])==2 for s in summaries),summaries
assert any(s["kind"]=="download_like" and str(root/"network-received-file") in s["files"] and s["confidence"]=="heuristic" for s in summaries),summaries
assert any(s["kind"]=="application_start" for s in summaries),summaries
cli=Path(__file__).parent/"electric-eye"
human=subprocess.check_output([str(cli),"--socket",socket_path,"process",str(os.getpid())],text=True)
assert "Package: python " in human and "Arguments:" in human,human
structured=json.loads(subprocess.check_output([str(cli),"--json","--socket",socket_path,"flows"],text=True))
assert structured["flows"],structured
# CLI traffic uses a different process; query loss counters only after these finish.
status = request("status")
assert not any(status["capture_loss"]), status
assert status["config"]["limits"]["aggregation_ms"] == 1000 and status["config"]["limits"]["api_workers"] == 3, status
assert status["config"]["capture"]["ring_bytes"] == 33554432, status
assert status["store"]["dropped"] == 0, status
print(json.dumps({"result": "passed", "root": str(root), "verified_write_paths": len(expected), "capture_loss": status["capture_loss"], "pid": os.getpid()}))
# Keep disposable artifacts for inspection; never touch unrelated files.
