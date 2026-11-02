#!/usr/bin/env python3
"""Persistent GUI IDA Pro MCP supervisor for 127.0.0.1:13337.

Why this exists
---------------
ida-pro-mcp's streamable-HTTP endpoint lives inside the IDA plugin. With no
IDA instance running, nothing listens on 13337, so an MCP client configured
with ``http://127.0.0.1:13337/mcp`` cannot even connect -- it never gets the
chance to call ``open_file``.

This supervisor always owns 13337. It speaks MCP itself and:

* serves local management tools (``open_file``/``list_instances``/
  ``select_instance``) before any IDA instance exists;
* implements ``open_file`` by launching a GUI IDA itself, matching the new
  registration by PID/target so concurrent agents cannot hijack each other;
* starts IDA with a temporary ``-A`` so loader/CPU-selection/PDB startup
  dialogs cannot block plugin registration, then restores interactive
  dialogs through the plugin's ``enable_interactive_mode`` tool;
* isolates instance selection per MCP session, with optional stable
  ``?agent=NAME`` slots and ``?instance=PORT`` pins for multi-agent use;
* proxies tool/resource/prompt requests to the selected GUI instance once it
  registers (IDA instances bind 13338+ because the supervisor owns 13337);
* supports GET /mcp SSE and ``notifications/tools/list_changed``.

The tool catalogue is cached in the user data directory and refreshed from
live instances; a first run with no cache exposes only the local tools.

Run (from a checkout or an installed package)::

    uv run ida-pro-mcp-supervisor
    python -m ida_pro_mcp.gui_supervisor

Control::

    uv run ida-pro-mcp-supervisor --status
    uv run ida-pro-mcp-supervisor --stop

If the supervisor is not running under IDA's bundled Python, point it at the
GUI executable with ``--ida-exe`` or ``IDA_MCP_IDA_EXE``/``IDADIR``.
"""

import argparse
import datetime
import json
import logging
import logging.handlers
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path
from typing import Annotated, Any, Optional
from urllib.parse import parse_qs, urlparse

# IMPORTANT: preload the standard-library ``http`` package before adding the
# ida_mcp directory to sys.path.  That directory contains its own http.py,
# which would otherwise shadow the stdlib module imported by zeromcp.
import http  # noqa: F401
import http.client
import http.server  # noqa: F401

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_TOOL_NAMES = ("list_instances", "select_instance", "open_file")
PROXY_HEADER = "X-MCP-Proxied"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 13337

log = logging.getLogger("ida_mcp_supervisor")


# ---------------------------------------------------------------------------
# Locate the installed ida_pro_mcp helper modules without importing the
# IDA-side package (its __init__ imports ida_* modules and only works inside
# IDA).  zeromcp and discovery are importable standalone.
# ---------------------------------------------------------------------------


def _locate_ida_mcp_dir() -> str:
    candidate = os.path.join(HERE, "ida_mcp")
    if os.path.isdir(candidate):
        return candidate

    env = os.environ.get("IDA_MCP_PACKAGE_DIR")
    if env and os.path.isdir(env):
        return env

    try:
        import importlib.util

        spec = importlib.util.find_spec("ida_pro_mcp")
        if spec and spec.submodule_search_locations:
            candidate = os.path.join(
                list(spec.submodule_search_locations)[0], "ida_mcp"
            )
            if os.path.isdir(candidate):
                return candidate
    except Exception:
        pass

    raise RuntimeError(
        "Cannot locate ida_pro_mcp/ida_mcp. Set IDA_MCP_PACKAGE_DIR to that directory."
    )


IDA_MCP_DIR = _locate_ida_mcp_dir()
sys.path.insert(0, IDA_MCP_DIR)

from zeromcp import McpServer  # noqa: E402
from zeromcp.mcp import McpHttpRequestHandler  # noqa: E402
import discovery  # noqa: E402


def _default_data_dir() -> str:
    """Store cache/log/pid under the IDA user directory's mcp folder."""
    try:
        mcp_dir = os.path.dirname(discovery.get_instances_dir())
        if mcp_dir:
            return os.path.join(mcp_dir, "supervisor")
    except Exception:
        pass
    return os.path.join(HERE, ".supervisor")


DATA_DIR = _default_data_dir()
DEFAULT_CACHE = os.path.join(DATA_DIR, "tools_cache.json")
DEFAULT_LOG = os.path.join(DATA_DIR, "logs", "supervisor.log")
DEFAULT_PID = os.path.join(DATA_DIR, "supervisor.pid")


# ---------------------------------------------------------------------------
# Configuration / logging
# ---------------------------------------------------------------------------


class SupervisorConfig:
    def __init__(
        self,
        host: str,
        port: int,
        cache_path: str,
        log_path: str,
        pid_path: str,
        ida_exe: Optional[str],
        proxy_timeout: float,
        verbose: bool,
    ):
        self.host = host
        self.port = port
        self.cache_path = cache_path
        self.log_path = log_path
        self.pid_path = pid_path
        self.ida_exe = ida_exe
        self.proxy_timeout = proxy_timeout
        self.verbose = verbose


def setup_logging(cfg: SupervisorConfig) -> None:
    os.makedirs(os.path.dirname(cfg.log_path), exist_ok=True)
    log.setLevel(logging.DEBUG if cfg.verbose else logging.INFO)
    log.propagate = False
    for handler in list(log.handlers):
        log.removeHandler(handler)

    fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s [%(threadName)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler = logging.handlers.RotatingFileHandler(
        cfg.log_path, maxBytes=2 * 1024 * 1024, backupCount=3, encoding="utf-8"
    )
    file_handler.setFormatter(fmt)
    log.addHandler(file_handler)

    # pythonw.exe has no console (stderr/stdout may be None).
    if sys.stderr is not None:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(fmt)
        log.addHandler(stream_handler)


# ---------------------------------------------------------------------------
# Tool schema cache
# ---------------------------------------------------------------------------

CACHE_LOCK = threading.Lock()
CACHE_TOOLS: list[dict[str, Any]] = []
_CACHE_SIGNATURE: str = ""


def _normalise_tools(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        value = value.get("tools")
    if not isinstance(value, list):
        return []
    return [t for t in value if isinstance(t, dict) and isinstance(t.get("name"), str)]


def load_cache(path: str) -> list[dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        tools = _normalise_tools(data)
        log.info("Loaded %d cached tool schemas from %s", len(tools), path)
        return tools
    except FileNotFoundError:
        log.warning("No tool schema cache at %s yet", path)
    except Exception as e:
        log.warning("Failed to load tool schema cache %s: %s", path, e)
    return []


def _cache_signature(tools: list[dict[str, Any]]) -> str:
    return json.dumps(tools, sort_keys=True, ensure_ascii=False)


def save_cache(path: str, tools: list[dict[str, Any]]) -> None:
    global _CACHE_SIGNATURE
    signature = _cache_signature(tools)
    if signature == _CACHE_SIGNATURE:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {
        "cache_version": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": "ida-pro-mcp supervisor",
        "tools": tools,
    }
    fd, tmp_path = tempfile.mkstemp(
        dir=os.path.dirname(path), prefix=".tools_cache_", suffix=".json"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp_path, path)
        _CACHE_SIGNATURE = signature
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Instance selection / discovery
# ---------------------------------------------------------------------------

STATE_LOCK = threading.RLock()
LAUNCH_LOCK = threading.Lock()
CFG: SupervisorConfig

# ---------------------------------------------------------------------------
# Per-session instance isolation
#
# MCP sessions are identified by zeromcp's transport session id
# ("http:<Mcp-Session-Id>").  Each session has its own selected instance.
# Instances launched/selected by a session are "claimed" so another session
# never silently auto-selects the same IDA database.
# ---------------------------------------------------------------------------

_SESSION_TARGETS: dict[str, tuple[str, int]] = {}
_SESSION_LAST_SEEN: dict[str, float] = {}
_SESSION_TTL_SEC = 24 * 3600
_LAST_SESSION_PRUNE = 0.0

_INSTANCE_OWNERS: dict[tuple[str, int], str] = {}

# Per-request pin: ?instance=PORT or X-IDA-MCP-Instance: PORT.
_REQUEST_INSTANCE = threading.local()
# Per-request agent slot: ?agent=NAME or X-IDA-MCP-Agent: NAME.  This is a
# stable routing key independent of the MCP transport session, so multiple
# sub-agents in one Claude Code session can use different server entries and
# each keep its own selected IDA instance.
_REQUEST_AGENT = threading.local()


def _instance_key(inst: dict[str, Any]) -> tuple[str, int]:
    return str(inst.get("host", DEFAULT_HOST)), int(inst.get("port", 0))


def _target_instance(target: tuple[str, int]) -> dict[str, Any]:
    return {"host": target[0], "port": target[1]}


def _is_self(host: str, port: int) -> bool:
    return int(port) == int(CFG.port) and host in (CFG.host, "127.0.0.1", "localhost")


def _reachable(inst: dict[str, Any], timeout: float = 0.75) -> bool:
    try:
        return discovery.probe_instance(
            str(inst.get("host", DEFAULT_HOST)), int(inst.get("port", 0)), timeout=timeout
        )
    except Exception:
        return False


def _target_reachable(target: tuple[str, int]) -> bool:
    host, port = target
    if _is_self(host, port):
        return False
    return _reachable({"host": host, "port": port})


def _broadcast_tools_changed() -> None:
    msg = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
    broadcast_message(msg)


def _agent_slot() -> Optional[str]:
    value = getattr(_REQUEST_AGENT, "name", None)
    return str(value) if value else None


def _session_key() -> str:
    """Return the routing key for the current request.

    Priority: explicit agent slot (?agent=) > MCP transport session id.
    Falls back to "anonymous" for direct in-process calls and for clients that
    do not support Mcp-Session-Id.
    """
    agent = _agent_slot()
    if agent:
        return f"agent:{agent}"

    server = globals().get("mcp")
    try:
        sid = server.get_current_transport_session_id() if server is not None else None
    except Exception:
        sid = None
    return sid or "anonymous"


def _short_session(session_key: str) -> str:
    if session_key.startswith("agent:"):
        return session_key
    return session_key[-12:] if len(session_key) > 12 else session_key


def _pinned_port() -> Optional[int]:
    value = getattr(_REQUEST_INSTANCE, "port", None)
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _touch_session_locked(session_key: str) -> None:
    global _LAST_SESSION_PRUNE
    now = time.time()
    _SESSION_LAST_SEEN[session_key] = now
    if now - _LAST_SESSION_PRUNE > 3600:
        _LAST_SESSION_PRUNE = now
        stale = [
            key
            for key, seen in _SESSION_LAST_SEEN.items()
            if now - seen > _SESSION_TTL_SEC
        ]
        for key in stale:
            _SESSION_LAST_SEEN.pop(key, None)
            _SESSION_TARGETS.pop(key, None)
        if stale:
            for key, owner in list(_INSTANCE_OWNERS.items()):
                if owner in stale:
                    _INSTANCE_OWNERS.pop(key, None)


def _set_session_target(
    session_key: str, inst: Optional[dict[str, Any]]
) -> None:
    new_key = _instance_key(inst) if inst else None
    with STATE_LOCK:
        _touch_session_locked(session_key)
        old_key = _SESSION_TARGETS.get(session_key)
        if new_key is None:
            _SESSION_TARGETS.pop(session_key, None)
        else:
            _SESSION_TARGETS[session_key] = new_key
    if new_key != old_key:
        if new_key is None:
            log.info(
                "Session %s: no active IDA instance", _short_session(session_key)
            )
        else:
            log.info(
                "Session %s: active IDA instance %s:%s",
                _short_session(session_key),
                new_key[0],
                new_key[1],
            )
        _broadcast_tools_changed()


def _claim_instance(
    inst: dict[str, Any], session_key: str, *, only_if_unowned: bool = False
) -> None:
    key = _instance_key(inst)
    with STATE_LOCK:
        if only_if_unowned and _INSTANCE_OWNERS.get(key) not in (
            None,
            session_key,
        ):
            return
        _INSTANCE_OWNERS[key] = session_key


def _session_target(session_key: str) -> Optional[tuple[str, int]]:
    with STATE_LOCK:
        _touch_session_locked(session_key)
        return _SESSION_TARGETS.get(session_key)


def _discover_reachable() -> list[dict[str, Any]]:
    try:
        instances = discovery.discover_instances()
    except Exception as e:
        log.warning("Instance discovery failed: %s", e)
        return []

    reachable: list[dict[str, Any]] = []
    alive_keys: set[tuple[str, int]] = set()
    for inst in instances:
        if str(inst.get("backend", "gui")) == "worker":
            # Headless idalib workers are managed by idalib-mcp, not this GUI
            # supervisor; keep their lifecycle out of GUI instance selection.
            continue
        host = str(inst.get("host", DEFAULT_HOST))
        port = int(inst.get("port", 0))
        if _is_self(host, port):
            continue
        if _reachable(inst):
            reachable.append(inst)
            alive_keys.add((host, port))

    with STATE_LOCK:
        for key in list(_INSTANCE_OWNERS):
            if key not in alive_keys:
                _INSTANCE_OWNERS.pop(key, None)
    return reachable


def _pinned_instance() -> Optional[dict[str, Any]]:
    port = _pinned_port()
    if port is None or _is_self(DEFAULT_HOST, port):
        return None
    inst = {"host": DEFAULT_HOST, "port": port}
    return inst if _reachable(inst) else None


def ensure_instance(
    force_scan: bool = False,
    session_key: Optional[str] = None,
    auto_select: bool = True,
) -> Optional[dict[str, Any]]:
    """Return the instance bound to *this MCP session*.

    Priority: explicit per-request pin (?instance=PORT) > this session's
    selection > an unclaimed reachable instance (auto-claimed) > None.
    A session never silently takes an instance claimed by another session.
    """
    pinned_port = _pinned_port()
    if pinned_port is not None:
        return _pinned_instance()

    session_key = session_key or _session_key()

    if not force_scan:
        target = _session_target(session_key)
        if target is not None and _target_reachable(target):
            return _target_instance(target)

    if not auto_select:
        return None

    reachable = _discover_reachable()
    if not reachable:
        _set_session_target(session_key, None)
        return None

    target = _session_target(session_key)
    chosen: Optional[dict[str, Any]] = None

    if target is not None and not force_scan:
        for inst in reachable:
            if _instance_key(inst) == target:
                chosen = inst
                break

    if chosen is None:
        with STATE_LOCK:
            for inst in reachable:
                key = _instance_key(inst)
                owner = _INSTANCE_OWNERS.get(key)
                if owner in (None, session_key):
                    chosen = inst
                    if owner is None:
                        _INSTANCE_OWNERS[key] = session_key
                    break

    if chosen is None:
        # Every reachable instance belongs to another session.  Do not silently
        # hijack one; the caller can select_instance explicitly or open_file.
        _set_session_target(session_key, None)
        return None

    with STATE_LOCK:
        key = _instance_key(chosen)
        if _INSTANCE_OWNERS.get(key) is None:
            _INSTANCE_OWNERS[key] = session_key
    _set_session_target(session_key, chosen)
    return chosen


def _invalidate_instance(inst: dict[str, Any], session_key: str) -> None:
    key = _instance_key(inst)
    with STATE_LOCK:
        if _SESSION_TARGETS.get(session_key) == key:
            _SESSION_TARGETS.pop(session_key, None)
    ensure_instance(force_scan=True, session_key=session_key)


def _no_instance_message(session_key: Optional[str] = None) -> str:
    pinned_port = _pinned_port()
    if pinned_port is not None:
        return (
            f"This MCP endpoint is pinned to IDA instance port {pinned_port}, "
            "but it is not reachable. Start that instance, or remove "
            f"?instance={pinned_port} from the URL."
        )

    session_key = session_key or _session_key()
    try:
        instances = discovery.discover_instances()
    except Exception:
        instances = []

    reachable: list[dict[str, Any]] = []
    for inst in instances:
        host = str(inst.get("host", DEFAULT_HOST))
        port = int(inst.get("port", 0))
        if _is_self(host, port):
            continue
        if _reachable(inst):
            reachable.append(inst)

    if reachable:
        with STATE_LOCK:
            available = [
                inst
                for inst in reachable
                if _INSTANCE_OWNERS.get(_instance_key(inst))
                in (None, session_key)
            ]
        if not available:
            return (
                "All reachable IDA instances are assigned to other MCP "
                "sessions/agents. Call open_file to launch your own instance, or "
                "call select_instance(port=...) to explicitly share an existing one."
            )

    return ZERO_INSTANCE_MESSAGE


# ---------------------------------------------------------------------------
# MCP server and local tools
# ---------------------------------------------------------------------------

mcp = McpServer("ida-pro-mcp", version="2.0.0-supervisor")
mcp.require_streamable_http_session = True
_ORIGINAL_DISPATCH = mcp.registry.dispatch

# Compatibility shim for stateless clients.  Compliant MCP clients receive a
# server-assigned Mcp-Session-Id and get full per-agent isolation.  Clients that
# ignore it fall back to a single "anonymous" session (legacy behavior) instead
# of receiving HTTP 400.  An orchestrator may also assign a stable session id
# via the X-IDA-MCP-Session header.
_ORIGINAL_HANDLE_MCP_POST = McpHttpRequestHandler._handle_mcp_post
_ALLOW_ANONYMOUS_SESSION = os.environ.get(
    "IDA_MCP_ALLOW_ANONYMOUS", "0"
).strip().lower() not in ("0", "false", "no", "off")


def _compat_handle_mcp_post(self, body):
    log.debug(
        "MCP POST headers: session=%r client_session=%r custom=%r ua=%r",
        self.headers.get("Mcp-Session-Id"),
        self.headers.get("X-Mcp-Client-Session-Id"),
        self.headers.get("X-IDA-MCP-Session"),
        self.headers.get("User-Agent"),
    )
    if self.headers.get("Mcp-Session-Id") is None:
        custom = self.headers.get("X-IDA-MCP-Session")
        if custom:
            self.headers["Mcp-Session-Id"] = custom.strip()
        else:
            try:
                parsed = json.loads(body)
            except Exception:
                parsed = None
            method = parsed.get("method") if isinstance(parsed, dict) else None
            if method != "initialize" and _ALLOW_ANONYMOUS_SESSION:
                self.headers["Mcp-Session-Id"] = "anonymous"
    return _ORIGINAL_HANDLE_MCP_POST(self, body)


McpHttpRequestHandler._handle_mcp_post = _compat_handle_mcp_post

# Advertise tools.listChanged so clients may refresh after an instance appears.
_ORIGINAL_INITIALIZE = mcp.registry.methods["initialize"]


def _initialize_with_list_changed(protocolVersion, capabilities, clientInfo, _meta=None):
    result = _ORIGINAL_INITIALIZE(protocolVersion, capabilities, clientInfo, _meta)
    try:
        capabilities = result.setdefault("capabilities", {})
        tools_cap = capabilities.setdefault("tools", {})
        tools_cap["listChanged"] = True
    except Exception:
        pass
    return result


mcp.registry.methods["initialize"] = _initialize_with_list_changed


def _generated_local_schemas() -> dict[str, dict[str, Any]]:
    try:
        result = mcp._mcp_tools_list(None)
        return {t["name"]: t for t in result.get("tools", []) if "name" in t}
    except Exception as e:
        log.debug("Could not generate local tool schemas: %s", e)
        return {}


def _local_schemas() -> dict[str, dict[str, Any]]:
    """Local management tool schemas generated from the current supervisor code.

    The cache exists for the (large) remote IDA tool catalogue; cached copies of
    local tools may be stale after a supervisor upgrade, so they are not used.
    """
    return _generated_local_schemas()


def _merge_remote_tools(remote_tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
    local = _local_schemas()
    merged = [
        t
        for t in remote_tools
        if isinstance(t, dict)
        and t.get("name") not in LOCAL_TOOL_NAMES
        # idalib_server adds its own session-management tools; this supervisor
        # targets GUI IDA instances and must not cache them.
        and not str(t.get("name", "")).startswith("idalib_")
    ]
    for name in LOCAL_TOOL_NAMES:
        if name in local:
            merged.append(local[name])
    return merged


def _update_cache(tools: list[dict[str, Any]]) -> None:
    global CACHE_TOOLS
    if not tools:
        return
    with CACHE_LOCK:
        CACHE_TOOLS = tools
    try:
        save_cache(CFG.cache_path, tools)
    except Exception as e:
        log.warning("Could not save tool schema cache: %s", e)


def _proxy_path() -> str:
    """Preserve ?ext= extension groups on forwarded requests."""
    enabled = sorted(getattr(mcp._enabled_extensions, "data", set()))
    if enabled:
        return f"/mcp?ext={','.join(enabled)}"
    return "/mcp"


def _proxy_request(
    inst: dict[str, Any],
    request: dict[str, Any],
    timeout: float,
) -> Optional[dict[str, Any]]:
    host = str(inst.get("host", DEFAULT_HOST))
    port = int(inst.get("port", 0))
    body = json.dumps(request).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        PROXY_HEADER: "1",  # prevent the target from forwarding again
    }
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("POST", _proxy_path(), body, headers)
        response = conn.getresponse()
        raw = response.read()
        if response.status >= 400:
            raise RuntimeError(
                f"HTTP {response.status} {response.reason}: "
                f"{raw.decode('utf-8', 'replace')[:500]}"
            )
        if not raw:
            return None
        return json.loads(raw.decode("utf-8"))
    finally:
        conn.close()


def _call_ida_tool(
    inst: dict[str, Any],
    name: str,
    arguments: dict[str, Any],
    timeout: float = 30.0,
) -> Any:
    """Call an MCP tool on a specific IDA instance and return structured content."""
    response = _proxy_request(
        inst,
        {
            "jsonrpc": "2.0",
            "id": "supervisor-tool",
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        timeout=timeout,
    )
    if not response:
        raise RuntimeError("empty tool response")
    if "error" in response:
        raise RuntimeError(response["error"].get("message", "Unknown tool error"))
    result = response.get("result", {})
    if result.get("isError"):
        content = result.get("content", [])
        message = (
            content[0].get("text", "Unknown tool error")
            if content
            else "Unknown tool error"
        )
        raise RuntimeError(message)
    return result.get("structuredContent")


def _fetch_remote_tools(inst: dict[str, Any]) -> list[dict[str, Any]]:
    response = _proxy_request(
        inst,
        {"jsonrpc": "2.0", "id": "supervisor-tools-list", "method": "tools/list", "params": {}},
        timeout=10.0,
    )
    if not response:
        raise RuntimeError("empty tools/list response")
    if "error" in response:
        raise RuntimeError(response["error"].get("message", "tools/list failed"))
    tools = response.get("result", {}).get("tools")
    if not isinstance(tools, list):
        raise RuntimeError("tools/list response has no tools array")
    return tools


def _advertised_tools(session_key: Optional[str] = None) -> list[dict[str, Any]]:
    # Do not auto-select an instance just for tools/list; keep the cached
    # catalogue until the session actually binds to an IDA instance.
    inst = ensure_instance(session_key=session_key, auto_select=False)
    if inst is not None:
        try:
            remote = _fetch_remote_tools(inst)
            if remote:
                merged = _merge_remote_tools(remote)
                _update_cache(merged)
                return merged
        except Exception as e:
            log.warning("Could not fetch tools/list from %s:%s: %s", inst.get("host"), inst.get("port"), e)

    with CACHE_LOCK:
        cached = list(CACHE_TOOLS)
    if cached:
        # Replace cached local-tool entries with schemas from the current code.
        return _merge_remote_tools(cached)
    local = _local_schemas()
    return [local[name] for name in LOCAL_TOOL_NAMES if name in local]


ZERO_INSTANCE_MESSAGE = (
    "No IDA Pro instance is running. IDA analysis tools are gated; call "
    "open_file with an absolute path to a binary, leaving autonomous=false so "
    "IDA's interactive dialogs work (Jump 'g', Cross-references 'x'). "
    "autonomous=true launches with -A and suppresses all dialogs; it requires "
    "allow_autonomous=true. (list_instances/select_instance remain available "
    "for management.)"
)


def _rpc_error(request: dict[str, Any], message: str, code: int = -32000) -> Optional[dict[str, Any]]:
    request_id = request.get("id")
    if request_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _tool_error(request: dict[str, Any], message: str) -> Optional[dict[str, Any]]:
    request_id = request.get("id")
    if request_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        },
    }


def _parse_request(request: Any) -> Optional[dict[str, Any]]:
    if isinstance(request, dict):
        return request
    try:
        if isinstance(request, (bytes, bytearray)):
            request = request.decode("utf-8")
        parsed = json.loads(request)
        return parsed if isinstance(parsed, dict) else None
    except Exception:
        return None


def dispatch(request: Any):
    request_obj = _parse_request(request)
    if request_obj is None:
        try:
            return _ORIGINAL_DISPATCH(request)
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {e}"},
            }

    method = request_obj.get("method", "")
    if not isinstance(method, str):
        return _rpc_error(request_obj, "Invalid method", -32600)

    session_key = _session_key()

    if method == "initialize":
        params = request_obj.get("params") or {}
        log.debug(
            "initialize: transport_session=%s client=%r",
            session_key,
            params.get("clientInfo"),
        )
    elif method == "tools/call":
        params = request_obj.get("params") or {}
        log.debug(
            "tools/call: session=%s meta=%r",
            session_key,
            params.get("_meta"),
        )

    if method == "initialize" or method.startswith("notifications/") or method == "ping":
        return _ORIGINAL_DISPATCH(request)

    if method == "tools/list":
        tools = _advertised_tools(session_key)
        return {
            "jsonrpc": "2.0",
            "id": request_obj.get("id"),
            "result": {"tools": tools},
        }

    if method == "tools/call":
        return _handle_tools_call(request_obj, request, session_key)

    empty_list_methods = ("resources/list", "resources/templates/list", "prompts/list")
    inst = ensure_instance(session_key=session_key)
    if inst is not None:
        try:
            return _proxy_request(inst, request_obj, timeout=CFG.proxy_timeout)
        except Exception as e:
            log.warning("Proxy %s failed: %s", method, e)
            _invalidate_instance(inst, session_key)
            if method not in empty_list_methods:
                return _rpc_error(
                    request_obj,
                    f"IDA instance {inst.get('host')}:{inst.get('port')} is unreachable: {e}",
                )

    if method in empty_list_methods:
        empty_key = {
            "resources/list": "resources",
            "resources/templates/list": "resourceTemplates",
            "prompts/list": "prompts",
        }[method]
        return {
            "jsonrpc": "2.0",
            "id": request_obj.get("id"),
            "result": {empty_key: []},
        }

    return _rpc_error(request_obj, _no_instance_message(session_key))


def _handle_tools_call(
    request_obj: dict[str, Any],
    raw_request: Any,
    session_key: Optional[str] = None,
):
    params = request_obj.get("params") or {}
    if not isinstance(params, dict):
        params = {}
    name = params.get("name", "")

    # Local tools never require an IDA instance.  open_file must work before any
    # instance exists; list_instances/select_instance are management tools and
    # must remain callable when all instances are assigned to other sessions.
    if name in LOCAL_TOOL_NAMES:
        return _ORIGINAL_DISPATCH(raw_request)

    session_key = session_key or _session_key()
    inst = ensure_instance(session_key=session_key)
    if inst is None:
        return _tool_error(request_obj, _no_instance_message(session_key))

    try:
        return _proxy_request(inst, request_obj, timeout=CFG.proxy_timeout)
    except Exception as e:
        log.warning(
            "Tool %s failed against %s:%s: %s",
            name,
            inst.get("host"),
            inst.get("port"),
            e,
        )
        _invalidate_instance(inst, session_key)
        return _tool_error(
            request_obj,
            f"Failed to reach IDA instance {inst.get('host')}:{inst.get('port')}: {e}",
        )


mcp.registry.dispatch = dispatch


# ---------------------------------------------------------------------------
# Local tools
# ---------------------------------------------------------------------------


@mcp.tool
def list_instances() -> list[dict[str, Any]]:
    """List discovered IDA Pro instances and this MCP session/agent slot's active instance.

    The selection is per MCP session (or per ?agent= slot): another agent's
    select_instance does not change which instance this agent uses.
    """
    session_key = _session_key()
    pinned_port = _pinned_port()
    if pinned_port is not None:
        active_key: Optional[tuple[str, int]] = (DEFAULT_HOST, int(pinned_port))
    else:
        active_key = _session_target(session_key)

    result = []
    try:
        instances = discovery.discover_instances()
    except Exception as e:
        log.warning("list_instances discovery failed: %s", e)
        instances = []
    for inst in instances:
        if str(inst.get("backend", "gui")) == "worker":
            continue
        key = _instance_key(inst)
        reachable = _reachable(inst)
        result.append(
            {
                **inst,
                "reachable": reachable,
                "active": key == active_key and reachable,
            }
        )
    return result


@mcp.tool
def select_instance(
    port: Annotated[int, "Port number of the IDA instance to connect to"],
    host: Annotated[str, "Host address of the IDA instance"] = "127.0.0.1",
) -> dict[str, Any]:
    """Select the IDA instance for *this MCP session/agent slot only*.

    Each agent (MCP session or ?agent= slot) has its own selection; another
    agent calling select_instance will not redirect your tool calls. Instances
    launched by an agent are claimed to prevent other agents from silently
    auto-selecting them. Use port=0 to reset to the first unassigned instance.
    """
    session_key = _session_key()
    pinned_port = _pinned_port()
    if pinned_port is not None:
        return {
            "success": False,
            "error": (
                f"This MCP endpoint is pinned to IDA instance port {pinned_port}; "
                "select_instance is disabled for pinned endpoints."
            ),
        }

    if port == 0:
        with STATE_LOCK:
            _SESSION_TARGETS.pop(session_key, None)
        inst = ensure_instance(force_scan=True, session_key=session_key)
        if inst is None:
            return {
                "success": True,
                "message": (
                    "Reset; no unassigned IDA instance was found. Use open_file "
                    "to launch one, or select_instance(port=...) to share one."
                ),
            }
        return {
            "success": True,
            "host": inst.get("host"),
            "port": inst.get("port"),
            "message": "Reset to the first available unassigned instance",
        }

    if _is_self(host, port):
        return {"success": False, "error": f"{host}:{port} is the supervisor endpoint"}
    if not discovery.probe_instance(host, port):
        return {"success": False, "error": f"Instance at {host}:{port} is not reachable"}

    candidate = next(
        (
            inst
            for inst in discovery.discover_instances()
            if _instance_key(inst) == (host, int(port))
        ),
        {"host": host, "port": int(port)},
    )
    _set_session_target(session_key, candidate)
    _claim_instance(candidate, session_key, only_if_unowned=True)
    return {
        "success": True,
        "host": host,
        "port": int(port),
        "message": "Selected for this MCP session only",
    }


def _resolve_ida_exe() -> Optional[str]:
    if CFG.ida_exe:
        candidate = os.path.expandvars(os.path.expanduser(CFG.ida_exe))
        return candidate if os.path.isfile(candidate) else None

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

    # Running under IDA's bundled Python: <IDA>/python311/pythonIDA.exe.
    sys_exe = os.path.abspath(sys.executable)
    sys_name = os.path.basename(sys_exe).lower()
    if sys_name in ("ida.exe", "ida64.exe", "idat.exe", "ida", "idat"):
        return sys_exe
    parent = os.path.dirname(sys_exe)
    if os.path.basename(parent).lower().startswith("python"):
        ida_root = os.path.dirname(parent)
        candidates.extend(
            [
                os.path.join(ida_root, "ida.exe"),
                os.path.join(ida_root, "idat.exe"),
                os.path.join(ida_root, "ida"),
                os.path.join(ida_root, "idat"),
            ]
        )

    # Installed layout: .../python311/Lib/site-packages/ida_pro_mcp/ida_mcp.
    try:
        ida_root = str(Path(IDA_MCP_DIR).parents[4])
        candidates.extend(
            [
                os.path.join(ida_root, "ida.exe"),
                os.path.join(ida_root, "idat.exe"),
                os.path.join(ida_root, "ida"),
                os.path.join(ida_root, "idat"),
            ]
        )
    except Exception:
        pass

    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return candidate

    for name in ("ida.exe", "idat.exe", "ida", "idat"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _is_admin() -> bool:
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _shell_execute_runas(ida_exe: str, args: list[str], cwd: Optional[str]) -> None:
    """Start IDA through the shell's runas verb (shows a UAC prompt)."""
    import ctypes

    params = subprocess.list2cmdline(args[1:])
    shell32 = ctypes.windll.shell32
    shell32.ShellExecuteW.restype = ctypes.c_void_p
    result = shell32.ShellExecuteW(
        None, "runas", ida_exe, params, cwd, 1  # SW_SHOWNORMAL
    )
    code = int(result or 0)
    if code <= 32:
        last_error = ctypes.get_last_error()
        raise OSError(
            f"ShellExecuteW(runas) failed (code {code}, last_error={last_error}). "
            "The UAC prompt may have been declined or dismissed."
        )


@mcp.tool
def open_file(
    file_path: Annotated[
        str, "Absolute path to the binary file to open in a new IDA instance"
    ],
    switch: Annotated[
        bool, "Automatically switch to the new instance once it starts"
    ] = True,
    autonomous: Annotated[
        bool,
        "Leave IDA in autonomous (-A) mode after launch, suppressing all "
        "dialogs (including Jump g / Cross-references x). By default -A is used "
        "only during startup to skip loader/CPU/PDB dialogs, then interactive "
        "dialogs are restored; staying autonomous requires allow_autonomous=true.",
    ] = False,
    new_database: Annotated[
        bool, "Force creating a new database even if one exists"
    ] = False,
    timeout: Annotated[
        int, "Seconds to wait for the new instance to register (0 = don't wait)"
    ] = 30,
    allow_autonomous: Annotated[
        bool,
        "Explicitly allow -A autonomous mode. Use only for batch jobs that do "
        "not need an interactive UI.",
    ] = False,
) -> dict[str, Any]:
    """Open a file in a new IDA Pro instance.

    Works even when no IDA instance is running: this supervisor launches IDA
    directly, then waits for the new plugin instance to register itself.

    Interactive use: leave autonomous=False (the default). The supervisor starts
    IDA with -A so loader/CPU-selection/PDB startup dialogs cannot block plugin
    registration, then calls the plugin's enable_interactive_mode tool to
    restore Jump (g), Cross-references (x) and other dialog boxes. autonomous=True
    keeps the instance dialog-free and is refused unless allow_autonomous=True.
    """
    if autonomous and not allow_autonomous:
        return {
            "success": False,
            "error": (
                "Refusing to launch IDA with -A (autonomous mode): IDA will not "
                "display dialog boxes, so interactive actions such as Jump (g) "
                "and Cross-references (x) stop working. Call open_file again with "
                "autonomous=false (the default) for a user-facing instance, or "
                "pass allow_autonomous=true only for a batch job that needs no UI."
            ),
        }

    pinned_port = _pinned_port()
    if pinned_port is not None:
        return {
            "success": False,
            "error": (
                f"This MCP endpoint is pinned to IDA instance port {pinned_port}; "
                "open_file is disabled here. Use the unpinned /mcp endpoint to "
                "launch instances."
            ),
        }

    session_key = _session_key()
    autonomous_warning = (
        "IDA launched in autonomous mode (-A); interactive dialogs are disabled."
        if autonomous
        else ""
    )

    raw_path = os.path.expandvars(os.path.expanduser(str(file_path)))
    absolute_path = os.path.abspath(raw_path)
    if not os.path.isfile(absolute_path):
        return {"success": False, "error": f"File not found: {absolute_path}"}

    ida_exe = _resolve_ida_exe()
    if not ida_exe:
        return {
            "success": False,
            "error": (
                "Cannot locate ida.exe. Set IDA_MCP_IDA_EXE to the full path of "
                "ida.exe (or idat.exe)."
            ),
        }

    target = absolute_path
    if not new_database:
        existing_idb = discovery._find_existing_idb(absolute_path)
        if existing_idb:
            target = existing_idb

    try:
        timeout_int = max(0, min(int(timeout), 600))
    except Exception:
        timeout_int = 30

    # Always start with -A: this suppresses loader/CPU-selection/PDB startup
    # dialogs that would otherwise block the MCP plugin from registering.  For
    # interactive launches we re-enable dialog boxes after registration via the
    # plugin's enable_interactive_mode tool (Qt event-loop timer).
    args = [ida_exe, "-A"]
    if new_database:
        args.append("-c")
    args.append(target)

    creationflags = 0
    if sys.platform == "win32":
        creationflags = (
            subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        )

    with LAUNCH_LOCK:
        try:
            before = {
                _instance_key(inst) for inst in discovery.discover_instances()
            }
        except Exception:
            before = set()

        launch_cwd = os.path.dirname(ida_exe) or None
        log.info("Launching IDA: %s", args)
        proc: Optional[subprocess.Popen] = None
        launch_mode = "direct"
        try:
            proc = subprocess.Popen(
                args,
                cwd=launch_cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=creationflags,
                close_fds=True,
            )
        except OSError as e:
            # WinError 740: the executable's compatibility settings require
            # elevation (this machine has RUNASADMIN set for ida.exe).  Ask the
            # shell to elevate; the user approves one UAC prompt.
            if sys.platform == "win32" and getattr(e, "winerror", None) == 740:
                log.info(
                    "ida.exe requires elevation; requesting UAC (runas) for this launch"
                )
                try:
                    _shell_execute_runas(ida_exe, args, launch_cwd)
                except Exception as elevation_error:
                    log.exception("Elevated launch failed")
                    return {
                        "success": False,
                        "error": (
                            "IDA requires administrator privileges, and the "
                            f"elevated launch failed: {elevation_error}"
                        ),
                    }
                launch_mode = "runas"
            else:
                log.exception("Failed to launch IDA")
                return {"success": False, "error": f"Failed to launch IDA: {e}"}

        if timeout_int == 0:
            message = (
                "IDA launch requested; not waiting for registration "
                f"(mode={launch_mode})"
            )
            if autonomous_warning:
                message = f"{message} {autonomous_warning}"
            elif not autonomous:
                message += (
                    "; it starts with temporary -A; call enable_interactive_mode "
                    "after it registers to restore interactive dialogs"
                )
            result = {
                "success": True,
                "binary": os.path.basename(target),
                "message": message,
            }
            if proc is not None:
                result["pid"] = proc.pid
            return result

        deadline = time.monotonic() + timeout_int
        new_instance: Optional[dict[str, Any]] = None
        exited_at: Optional[float] = None
        saw_unrelated = False

        while time.monotonic() < deadline:
            time.sleep(0.5)
            try:
                current = discovery.discover_instances()
            except Exception:
                current = []
            for inst in current:
                if _instance_key(inst) in before or _is_self(
                    str(inst.get("host", DEFAULT_HOST)), int(inst.get("port", 0))
                ):
                    continue
                if str(inst.get("backend", "gui")) == "worker":
                    continue
                if discovery._instance_matches_launch(
                    inst,
                    proc.pid if proc is not None else None,
                    absolute_path,
                    target,
                ):
                    new_instance = inst
                    break
                saw_unrelated = True
                log.info(
                    "open_file: ignoring unrelated new instance %s (pid=%s, "
                    "port=%s) while waiting for %s",
                    inst.get("binary", "?"),
                    inst.get("pid", "?"),
                    inst.get("port", "?"),
                    os.path.basename(target),
                )
            if new_instance is not None:
                break

            if proc is not None and proc.poll() is not None:
                if exited_at is None:
                    exited_at = time.monotonic()
                elif time.monotonic() - exited_at > 3.0:
                    return {
                        "success": False,
                        "pid": proc.pid,
                        "error": (
                            f"IDA exited with code {proc.returncode} before the MCP "
                            "plugin registered. Check that the ida_mcp plugin is "
                            "installed and autostart is enabled."
                        ),
                    }

        if new_instance is None:
            message = (
                f"IDA launch requested (mode={launch_mode}) but no matching new "
                f"instance registered within {timeout_int}s. Use list_instances to "
                "check later. If IDA is waiting on a startup/loader dialog, interact "
                "with it, or relaunch with allow_autonomous=true for a dialog-free "
                "batch instance."
            )
            if saw_unrelated:
                message += (
                    " Another IDA instance registered during the wait but did not "
                    "match the launched PID/target."
                )
            if autonomous_warning:
                message = f"{message} {autonomous_warning}"
            result = {
                "success": True,
                "binary": os.path.basename(target),
                "message": message,
            }
            if proc is not None:
                result["pid"] = proc.pid
            return result

        result = {
            "success": True,
            "host": new_instance.get("host", DEFAULT_HOST),
            "port": new_instance.get("port"),
            "binary": new_instance.get("binary") or os.path.basename(target),
            "switched": bool(switch),
        }
        pid = new_instance.get("pid") or (proc.pid if proc is not None else None)
        if pid is not None:
            result["pid"] = pid
        _claim_instance(new_instance, session_key)
        if switch:
            _set_session_target(session_key, new_instance)

        if autonomous:
            if autonomous_warning:
                result["message"] = autonomous_warning
        else:
            # The process was started with -A only to keep startup dialog-free.
            # Clear the persistent batch flag on the Qt event loop after this
            # tool call's transient idc.batch(1) window has been restored.
            try:
                _call_ida_tool(
                    new_instance,
                    "enable_interactive_mode",
                    {"delay_ms": 200},
                    timeout=30.0,
                )
                time.sleep(0.35)
                result["message"] = (
                    "Startup dialogs were suppressed with temporary -A; "
                    "interactive IDA dialogs are now restored."
                )
            except Exception as e:
                log.warning(
                    "Could not restore interactive mode on %s:%s: %s",
                    new_instance.get("host"),
                    new_instance.get("port"),
                    e,
                )
                result["message"] = (
                    "IDA was launched with -A to suppress startup dialogs, but "
                    f"interactive dialog restoration failed: {e}"
                )

        log.info(
            "New IDA instance registered: %s:%s (pid=%s)",
            result["host"],
            result["port"],
            pid,
        )
        return result


# ---------------------------------------------------------------------------
# GET /mcp SSE support for server -> client notifications
# ---------------------------------------------------------------------------


class _StreamClient:
    def __init__(self, wfile):
        self.wfile = wfile
        self.alive = True
        self.lock = threading.Lock()

    def send_raw(self, data: bytes) -> bool:
        if not self.alive:
            return False
        with self.lock:
            try:
                self.wfile.write(data)
                self.wfile.flush()
                return True
            except (BrokenPipeError, ConnectionResetError, OSError):
                self.alive = False
                return False

    def send_message(self, message: dict[str, Any]) -> bool:
        payload = json.dumps(message, separators=(",", ":")).encode("utf-8")
        return self.send_raw(b"event: message\ndata: " + payload + b"\n\n")


_STREAM_LOCK = threading.Lock()
_STREAM_CLIENTS: set[_StreamClient] = set()


def broadcast_message(message: dict[str, Any]) -> None:
    with _STREAM_LOCK:
        clients = list(_STREAM_CLIENTS)
    for client in clients:
        if not client.send_message(message):
            with _STREAM_LOCK:
                _STREAM_CLIENTS.discard(client)


class SupervisorHttpRequestHandler(McpHttpRequestHandler):
    """Adds the streamable-HTTP GET SSE notification stream at /mcp."""

    def do_POST(self):
        self._apply_request_context()
        try:
            super().do_POST()
        finally:
            _REQUEST_INSTANCE.port = None
            _REQUEST_AGENT.name = None

    def _apply_request_context(self):
        """Bind this request to ?instance=PORT / ?agent=NAME (or headers).

        ?instance= is an absolute per-request instance pin and wins over the
        agent slot.  ?agent= is a stable routing key for multi-agent setups and
        overrides the MCP transport session key.
        """
        try:
            query = parse_qs(urlparse(self.path).query)
        except Exception:
            query = {}

        instance_value = query.get("instance", [None])[0]
        if instance_value is None:
            instance_value = self.headers.get("X-IDA-MCP-Instance")
        port = None
        try:
            if instance_value is not None:
                port = int(str(instance_value).strip())
        except (TypeError, ValueError):
            port = None
        if port is not None and (
            port < 1 or port > 65535 or _is_self(DEFAULT_HOST, port)
        ):
            port = None

        agent_value = query.get("agent", [None])[0]
        if agent_value is None:
            agent_value = self.headers.get("X-IDA-MCP-Agent")
        agent = None
        if agent_value is not None:
            candidate = str(agent_value).strip()
            if (
                1 <= len(candidate) <= 64
                and all(c.isalnum() or c in "_.-" for c in candidate)
            ):
                agent = candidate

        _REQUEST_INSTANCE.port = port
        _REQUEST_AGENT.name = agent

    def do_GET(self):
        path = urlparse(self.path).path
        accept = (self.headers.get("Accept") or "").lower()
        if path == "/mcp" and "text/event-stream" in accept:
            self._handle_mcp_sse()
            return
        super().do_GET()

    def _handle_mcp_sse(self):
        if not self._check_api_request():
            return

        client = _StreamClient(self.wfile)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        session_id = self.headers.get("Mcp-Session-Id")
        if session_id:
            self.send_header("Mcp-Session-Id", session_id)
        self.send_cors_headers()
        self.end_headers()

        with _STREAM_LOCK:
            _STREAM_CLIENTS.add(client)

        sock = self.connection
        try:
            if sock is not None:
                try:
                    sock.settimeout(1.0)
                except OSError:
                    pass
            client.send_raw(b": connected\n\n")
            last_ping = time.time()
            while client.alive and mcp._running:
                if sock is not None:
                    try:
                        readable, _, _ = select.select([sock], [], [], 1.0)
                        if readable and sock.recv(1, socket.MSG_PEEK) == b"":
                            break
                    except (OSError, ConnectionResetError, BrokenPipeError):
                        break
                else:
                    time.sleep(1.0)

                if time.time() - last_ping > 15.0:
                    if not client.send_raw(b": ping\n\n"):
                        break
                    last_ping = time.time()
        finally:
            client.alive = False
            with _STREAM_LOCK:
                _STREAM_CLIENTS.discard(client)


# ---------------------------------------------------------------------------
# PID / process control
# ---------------------------------------------------------------------------


def _pid_alive(pid: int) -> bool:
    try:
        return discovery.is_pid_alive(pid)
    except Exception:
        return False


def _read_pid(path: str) -> Optional[int]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except Exception:
        return None


def _write_pid(path: str, pid: int) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(pid))


def _remove_pid(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def _port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (OSError, socket.timeout):
        return False


def cmd_status(cfg: SupervisorConfig) -> int:
    pid = _read_pid(cfg.pid_path)
    running = pid is not None and _pid_alive(pid)
    listening = _port_open(cfg.host, cfg.port)
    print(f"pid file: {cfg.pid_path} -> {pid if pid is not None else 'missing'}")
    print(f"process alive: {running}")
    print(f"{cfg.host}:{cfg.port} listening: {listening}")
    if running and listening:
        print("status: running")
        return 0
    print("status: not running")
    return 1


def cmd_stop(cfg: SupervisorConfig) -> int:
    pid = _read_pid(cfg.pid_path)
    if pid is None:
        print("No pid file; supervisor is not running (or was not started by this script).")
        return 1
    if not _pid_alive(pid):
        print(f"PID {pid} is not alive; removing stale pid file.")
        _remove_pid(cfg.pid_path)
        return 1
    try:
        os.kill(pid, signal.SIGTERM)
    except Exception as e:
        print(f"Failed to stop PID {pid}: {e}")
        return 1
    for _ in range(20):
        if not _pid_alive(pid):
            break
        time.sleep(0.25)
    _remove_pid(cfg.pid_path)
    print(f"Stopped supervisor PID {pid}.")
    return 0


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def build_config(args) -> SupervisorConfig:
    return SupervisorConfig(
        host=args.host,
        port=args.port,
        cache_path=os.path.abspath(args.cache),
        log_path=os.path.abspath(args.log),
        pid_path=os.path.abspath(args.pid_file),
        ida_exe=args.ida_exe,
        proxy_timeout=args.proxy_timeout,
        verbose=args.verbose,
    )


def main() -> int:
    global CFG, CACHE_TOOLS, _CACHE_SIGNATURE

    parser = argparse.ArgumentParser(
        description="Persistent IDA Pro MCP supervisor for 127.0.0.1:13337"
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--cache", default=DEFAULT_CACHE)
    parser.add_argument("--log", default=DEFAULT_LOG)
    parser.add_argument("--pid-file", default=DEFAULT_PID)
    parser.add_argument(
        "--ida-exe",
        default=None,
        help="Full path to ida.exe/idat.exe (default: auto-detect)",
    )
    parser.add_argument(
        "--proxy-timeout",
        type=float,
        default=120.0,
        help="Seconds to wait for proxied IDA tool calls (default: 120)",
    )
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--status", action="store_true", help="Show supervisor status")
    parser.add_argument("--stop", action="store_true", help="Stop the supervisor")
    args = parser.parse_args()

    cfg = build_config(args)
    CFG = cfg

    if args.status:
        return cmd_status(cfg)
    if args.stop:
        return cmd_stop(cfg)

    setup_logging(cfg)

    existing_pid = _read_pid(cfg.pid_path)
    if existing_pid is not None and _pid_alive(existing_pid) and _port_open(cfg.host, cfg.port):
        log.error(
            "Supervisor already running (pid=%s) on %s:%s", existing_pid, cfg.host, cfg.port
        )
        return 1

    CACHE_TOOLS = load_cache(cfg.cache_path)
    _CACHE_SIGNATURE = _cache_signature(CACHE_TOOLS) if CACHE_TOOLS else ""

    ida_exe = _resolve_ida_exe()
    log.info("=" * 72)
    log.info("IDA Pro MCP supervisor starting")
    log.info("  endpoint:   http://%s:%s/mcp", cfg.host, cfg.port)
    log.info("  ida_mcp:    %s", IDA_MCP_DIR)
    log.info("  ida.exe:    %s", ida_exe or "<not found>")
    log.info(
        "  elevated:   %s",
        "yes"
        if _is_admin()
        else "no (open_file will request UAC if Windows requires elevation)",
    )
    log.info("  cache:      %s (%d tools)", cfg.cache_path, len(CACHE_TOOLS))
    log.info("  instances:  %s", discovery.get_instances_dir())
    log.info("  sessions:   per-agent instance isolation (Mcp-Session-Id)")
    log.info("  agents:     ?agent=NAME or X-IDA-MCP-Agent header")
    log.info("  pinning:    ?instance=PORT or X-IDA-MCP-Instance header")
    log.info(
        "  anonymous:  %s",
        "allowed (shared bucket)"
        if _ALLOW_ANONYMOUS_SESSION
        else "disabled (strict Mcp-Session-Id)",
    )
    log.info("  log:        %s", cfg.log_path)

    try:
        mcp.serve(cfg.host, cfg.port, request_handler=SupervisorHttpRequestHandler)
    except OSError as e:
        log.error(
            "Cannot bind %s:%s: %s. If an IDA instance already owns this port, "
            "close it once and start the supervisor again.",
            cfg.host,
            cfg.port,
            e,
        )
        return 1
    except Exception:
        log.exception("Failed to start MCP server")
        return 1

    _write_pid(cfg.pid_path, os.getpid())
    log.info(
        "Supervisor listening (pid=%s); per-session instance isolation enabled",
        os.getpid(),
    )

    try:
        discovered = discovery.discover_instances()
        log.info(
            "Startup discovery: %d IDA instance(s); sessions bind on first use",
            len(discovered),
        )
    except Exception as e:
        log.warning("Startup discovery failed: %s", e)

    try:
        while True:
            time.sleep(3600)
    except (KeyboardInterrupt, SystemExit):
        log.info("Shutting down")
    finally:
        try:
            mcp.stop()
        except Exception:
            pass
        _remove_pid(cfg.pid_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
