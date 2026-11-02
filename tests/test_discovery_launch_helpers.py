"""Tests for pure-Python GUI launch helpers in ida_mcp/discovery.py."""

import importlib.util
from pathlib import Path

DISCOVERY_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "ida_pro_mcp"
    / "ida_mcp"
    / "discovery.py"
)
spec = importlib.util.spec_from_file_location("test_discovery_helpers", DISCOVERY_PATH)
assert spec is not None and spec.loader is not None
discovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(discovery)


def test_find_existing_idb_ida9_suffix(tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    idb = tmp_path / "sample.exe.i64"
    idb.write_bytes(b"idb")
    assert discovery._find_existing_idb(str(binary)) == str(idb)


def test_find_existing_idb_legacy_suffix(tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    idb = tmp_path / "sample.i64"
    idb.write_bytes(b"idb")
    assert discovery._find_existing_idb(str(binary)) == str(idb)


def test_instance_matches_launch_by_pid(tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    inst = {
        "pid": 1234,
        "binary": "unrelated.exe",
        "idb_path": str(tmp_path / "unrelated.exe.i64"),
    }
    assert discovery._instance_matches_launch(inst, 1234, str(binary), str(binary))


def test_instance_matches_launch_by_target(tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    inst = {
        "pid": 9999,
        "binary": "sample.exe",
        "idb_path": str(tmp_path / "sample.exe.i64"),
    }
    assert discovery._instance_matches_launch(inst, None, str(binary), str(binary))


def test_instance_matches_launch_rejects_unrelated(tmp_path):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    other_dir = tmp_path / "other"
    other_dir.mkdir()
    inst = {
        "pid": 9999,
        "binary": "XSafe.sys",
        "idb_path": str(other_dir / "XSafe.sys.i64"),
    }
    assert not discovery._instance_matches_launch(
        inst, None, str(binary), str(binary)
    )


def test_launch_gui_instance_matches_pid_and_restores_dialogs(
    tmp_path, monkeypatch
):
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ")
    fake_ida = tmp_path / "ida.exe"
    fake_ida.write_bytes(b"x")

    monkeypatch.setattr(discovery, "_get_ida_executable", lambda: str(fake_ida))

    state = {"launched": False}

    def fake_discover():
        if not state["launched"]:
            state["launched"] = True
            return []
        return [
            {
                "host": "127.0.0.1",
                "port": 13339,
                "pid": 4242,
                "binary": "sample.exe",
                "idb_path": str(tmp_path / "sample.exe.i64"),
                "backend": "gui",
            }
        ]

    monkeypatch.setattr(discovery, "discover_instances", fake_discover)

    class FakeProcess:
        pid = 4242

    launched_args = []

    def fake_popen(args, **_kwargs):
        launched_args.append(args)
        return FakeProcess()

    monkeypatch.setattr(discovery.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(discovery.time, "sleep", lambda *_a, **_k: None)

    restored = []

    def fake_call(host, port, name, arguments, timeout=30.0):
        restored.append((host, port, name, arguments, timeout))
        return {"scheduled": True}

    monkeypatch.setattr(discovery, "_call_instance_tool", fake_call)

    result = discovery.launch_gui_instance(str(binary), timeout=2)

    assert result["success"] is True
    assert result["port"] == 13339
    assert result["pid"] == 4242
    assert launched_args and "-A" in launched_args[0]
    assert restored and restored[0][2] == "enable_interactive_mode"
    assert "restored" in result["message"]
