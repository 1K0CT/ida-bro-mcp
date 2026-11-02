"""Instance discovery for IDA Pro MCP.

IDA plugin instances register themselves by writing JSON files to
{ida_user_dir}/mcp/instances/. The MCP server discovers running
instances by reading these files and validating PID liveness.
"""

import datetime
import glob
import http.client
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import TypedDict


class LaunchInstanceResult(TypedDict, total=False):
    success: bool
    host: str
    port: int
    binary: str
    pid: int
    message: str
    error: str


class InstanceInfo(TypedDict, total=False):
    host: str
    port: int
    pid: int
    binary: str
    idb_path: str
    started_at: str
    backend: str  # "gui" or "worker"


def _get_ida_user_dir() -> str:
    if sys.platform == "win32":
        return os.path.join(os.environ["APPDATA"], "Hex-Rays", "IDA Pro")
    return os.path.join(os.path.expanduser("~"), ".idapro")


def get_instances_dir() -> str:
    return os.path.join(_get_ida_user_dir(), "mcp", "instances")


def _instance_file_path(port: int) -> str:
    return os.path.join(get_instances_dir(), f"instance_{port}.json")


def register_instance(
    host: str, port: int, pid: int, binary: str, idb_path: str, backend: str = "gui"
) -> str:
    """Write an instance registration file. Returns the file path."""
    info: InstanceInfo = {
        "host": host,
        "port": port,
        "pid": pid,
        "binary": binary,
        "idb_path": idb_path,
        "started_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "backend": backend,
    }
    instances_dir = get_instances_dir()
    os.makedirs(instances_dir, exist_ok=True)
    file_path = _instance_file_path(port)
    # Atomic write
    fd, tmp_path = tempfile.mkstemp(dir=instances_dir, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)
        os.replace(tmp_path, file_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    return file_path


def unregister_instance(port: int) -> bool:
    """Remove an instance registration file. Returns True if removed."""
    file_path = _instance_file_path(port)
    try:
        os.unlink(file_path)
        return True
    except OSError:
        return False


def is_pid_alive(pid: int) -> bool:
    """Check if a process is still running."""
    if sys.platform == "win32":
        import ctypes

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION, False, pid
        )
        if handle:
            ctypes.windll.kernel32.CloseHandle(handle)
            return True
        return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except PermissionError:
            return True  # Process exists, we lack permission
        except ProcessLookupError:
            return False
        except OSError:
            return False


def probe_instance(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if an instance is reachable via TCP."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def _connectable_host(host: str) -> str:
    """Map a recorded bind address to an address we can connect to.

    A registration stores the address the instance bound to, and a wildcard
    bind is not connectable: Winsock rejects connect("0.0.0.0") / connect("::")
    with WSAEADDRNOTAVAIL (10049) where BSD sockets route them to loopback, so
    a live instance read its own registration as unreachable.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host  # a name ("localhost") or an explicit interface address
    if address.is_unspecified:
        return "127.0.0.1" if address.version == 4 else "::1"
    return host


def discover_instances() -> list[InstanceInfo]:
    """Scan for registered instances, cleaning up stale entries."""
    instances_dir = get_instances_dir()
    if not os.path.isdir(instances_dir):
        return []

    result: list[InstanceInfo] = []
    pattern = os.path.join(instances_dir, "instance_*.json")
    for file_path in glob.glob(pattern):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                info: InstanceInfo = json.load(f)
        except (json.JSONDecodeError, OSError):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        if not all(k in info for k in ("host", "port", "pid")):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        # Consumers (the probe below and the supervisor sessions adopted from
        # this result) connect to this host, so record a connectable one.
        info["host"] = _connectable_host(info["host"])

        if not is_pid_alive(info["pid"]):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        # Secondary check: verify the instance is actually listening.
        # Catches PID reuse (Windows can recycle PIDs quickly) and
        # cases where the process is alive but the server crashed.
        if not probe_instance(info["host"], info["port"], timeout=1.0):
            try:
                os.unlink(file_path)
            except OSError:
                pass
            continue

        result.append(info)

    result.sort(key=lambda x: x.get("started_at", ""))
    return result


def _find_existing_idb(file_path: str) -> str | None:
    """Return the path of an existing IDB next to `file_path`, if any.

    IDA 9 normally creates ``<input>.i64`` (e.g. ``test.exe.i64``); older
    versions replaced the extension (``test.i64``). Check both conventions.
    """
    base = os.path.splitext(file_path)[0]
    candidates = (
        file_path + ".i64",
        base + ".i64",
        file_path + ".idb",
        base + ".idb",
    )
    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
    return None


def _get_ida_executable() -> str:
    """Find the IDA GUI executable.

    When called from inside IDA, ``sys.executable`` is IDA itself. The idalib
    supervisor runs under a normal Python interpreter, so also consult
    IDA_MCP_IDA_EXE / IDA_EXE / IDADIR and the usual install layout.
    """
    candidates: list[str] = []
    for env_name in ("IDA_MCP_IDA_EXE", "IDA_EXE"):
        value = os.environ.get(env_name)
        if value:
            candidates.append(os.path.expandvars(os.path.expanduser(value)))

    idadir = os.environ.get("IDADIR")
    if idadir:
        candidates.extend(
            [
                os.path.join(idadir, "ida.exe"),
                os.path.join(idadir, "idat.exe"),
                os.path.join(idadir, "ida"),
                os.path.join(idadir, "idat"),
            ]
        )

    sys_exe = os.path.abspath(sys.executable)
    if os.path.basename(sys_exe).lower() in (
        "ida.exe",
        "ida64.exe",
        "idat.exe",
        "ida",
        "idat",
    ):
        return sys_exe

    parent = os.path.dirname(sys_exe)
    if os.path.basename(parent).lower().startswith("python"):
        root = os.path.dirname(parent)
        candidates.extend(
            [
                os.path.join(root, "ida.exe"),
                os.path.join(root, "idat.exe"),
                os.path.join(root, "ida"),
                os.path.join(root, "idat"),
            ]
        )

    candidates.append(sys_exe)
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate

    for name in ("ida.exe", "idat.exe", "ida", "idat"):
        found = shutil.which(name)
        if found:
            return found
    return sys_exe


def _instance_matches_launch(
    inst: dict,
    proc_pid: int | None,
    absolute_path: str,
    target: str,
) -> bool:
    """Return True if a newly registered instance belongs to this launch.

    With multiple agents launching IDA concurrently, a newly discovered
    instance may belong to someone else. Match the launched PID first; for
    elevated/runas launches (no PID available), match the target binary and
    database directory.
    """
    if proc_pid is not None:
        try:
            if int(inst.get("pid", 0)) == int(proc_pid):
                return True
        except (TypeError, ValueError):
            pass

    expected_names: set[str] = set()
    expected_dirs: set[str] = set()
    for path in (absolute_path, target):
        try:
            abs_path = os.path.abspath(path)
            base = os.path.basename(abs_path)
            expected_names.add(base.casefold())
            expected_names.add(os.path.splitext(base)[0].casefold())
            expected_dirs.add(os.path.dirname(abs_path).casefold())
        except Exception:
            pass

    inst_binary = str(inst.get("binary", "") or "").casefold()
    try:
        inst_idb = os.path.abspath(str(inst.get("idb_path", "") or ""))
        inst_dir = os.path.dirname(inst_idb).casefold()
        inst_idb_norm = os.path.normcase(inst_idb)
    except Exception:
        inst_dir = ""
        inst_idb_norm = ""

    if inst_binary and inst_binary in expected_names:
        if not inst_dir or inst_dir in expected_dirs:
            return True

    if inst_idb_norm:
        for path in (absolute_path, target):
            try:
                pn = os.path.normcase(os.path.abspath(path))
            except Exception:
                continue
            if inst_idb_norm == pn or inst_idb_norm == os.path.normcase(pn + ".i64"):
                return True
    return False


def _call_instance_tool(
    host: str,
    port: int,
    name: str,
    arguments: dict,
    timeout: float = 30.0,
) -> dict | None:
    """Call an MCP tool on a freshly launched IDA instance."""
    payload = {
        "jsonrpc": "2.0",
        "id": "launch-gui",
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request(
            "POST",
            "/mcp",
            json.dumps(payload).encode("utf-8"),
            {"Content-Type": "application/json", "Accept": "application/json"},
        )
        response = conn.getresponse()
        raw = response.read().decode("utf-8", "replace")
        if response.status >= 400:
            raise RuntimeError(f"HTTP {response.status}: {raw[:300]}")
        data = json.loads(raw) if raw else {}
    finally:
        conn.close()

    if "error" in data:
        raise RuntimeError(data["error"].get("message", "tool call failed"))
    result = data.get("result", {})
    if result.get("isError"):
        content = result.get("content", [])
        raise RuntimeError(
            content[0].get("text", "tool call failed") if content else "tool call failed"
        )
    return result.get("structuredContent")


def launch_gui_instance(
    file_path: str,
    *,
    autonomous: bool = False,
    new_database: bool = False,
    timeout: int = 30,
) -> LaunchInstanceResult:
    """Launch a new IDA GUI process for `file_path` and wait for it to register.

    The process is started with ``-A`` so loader/CPU-selection/PDB startup
    dialogs cannot block plugin registration. For interactive launches
    (``autonomous=False``) the plugin's ``enable_interactive_mode`` tool is
    called after registration to restore Jump (g), Cross-references (x), and
    other dialog boxes. ``autonomous=True`` leaves IDA dialog-free.
    """
    absolute_path = os.path.abspath(
        os.path.expandvars(os.path.expanduser(file_path))
    )
    if not os.path.isfile(absolute_path):
        return {"success": False, "error": f"File not found: {absolute_path}"}

    ida_exe = _get_ida_executable()
    if not os.path.isfile(ida_exe):
        return {"success": False, "error": f"Cannot find IDA executable: {ida_exe}"}

    target = absolute_path
    if not new_database:
        existing_idb = _find_existing_idb(absolute_path)
        if existing_idb:
            target = existing_idb

    # Always start with -A to suppress startup dialogs; interactive launches
    # clear batch mode after the plugin registers (see below).
    args = [ida_exe, "-A"]
    if new_database:
        args.append("-c")
    args.append(target)

    before = {(i["host"], i["port"]) for i in discover_instances()}

    try:
        proc = subprocess.Popen(
            args,
            cwd=os.path.dirname(ida_exe) or None,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=(
                subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
                if sys.platform == "win32"
                else 0
            ),
            close_fds=True,
        )
    except Exception as e:
        return {"success": False, "error": f"Failed to launch IDA: {e}"}

    proc_pid = proc.pid

    if timeout == 0:
        message = "IDA launched, not waiting for registration"
        if autonomous:
            message += " in autonomous mode (-A); interactive dialogs are disabled"
        else:
            message += (
                "; it starts with temporary -A; call enable_interactive_mode "
                "after it registers to restore interactive dialogs"
            )
        return {"success": True, "pid": proc_pid, "message": message}

    deadline = time.monotonic() + timeout
    new_instance = None
    saw_unrelated = False
    while time.monotonic() < deadline:
        time.sleep(0.5)
        for inst in discover_instances():
            key = (inst["host"], inst["port"])
            if key in before:
                continue
            if inst.get("backend", "gui") == "worker":
                continue
            if _instance_matches_launch(inst, proc_pid, absolute_path, target):
                new_instance = inst
                break
            saw_unrelated = True

        if new_instance:
            break

    if not new_instance:
        message = f"IDA launched but did not register within {timeout}s."
        if saw_unrelated:
            message += (
                " Another IDA instance registered during the wait but did not "
                "match the launched PID/target."
            )
        return {"success": True, "pid": proc_pid, "message": message}

    result: LaunchInstanceResult = {
        "success": True,
        "host": new_instance["host"],
        "port": new_instance["port"],
        "binary": new_instance.get("binary", ""),
        "pid": int(new_instance["pid"]) if new_instance.get("pid") is not None else 0,
    }

    if autonomous:
        result["message"] = (
            "IDA launched in autonomous mode (-A); interactive dialogs are disabled."
        )
    else:
        try:
            _call_instance_tool(
                new_instance["host"],
                int(new_instance["port"]),
                "enable_interactive_mode",
                {"delay_ms": 200},
                timeout=30.0,
            )
            time.sleep(0.35)
            result["message"] = (
                "Startup dialogs were suppressed with temporary -A; interactive "
                "IDA dialogs are now restored."
            )
        except Exception as e:
            result["message"] = (
                "IDA was launched with -A to suppress startup dialogs, but "
                f"interactive dialog restoration failed: {e}"
            )
    return result
