"""Tests for GUI supervisor launch-wait identity handling."""

from ...gui_supervisor import _instance_identity, _instance_was_present
from ..framework import test


@test()
def test_gui_supervisor_port_reuse_is_not_pre_existing():
    """A new PID on a reused port must not be mistaken for the old instance."""
    old = {
        "host": "127.0.0.1",
        "port": 13341,
        "pid": 100,
        "started_at": "2026-01-01T00:00:00",
        "idb_path": "F:/tmp/old.i64",
        "binary": "old.dll",
    }
    before = {("127.0.0.1", 13341): _instance_identity(old)}

    assert _instance_was_present(old, before)

    reuse = dict(old, pid=200, started_at="2026-01-01T00:00:01")
    assert not _instance_was_present(reuse, before)

    moved = dict(old, port=13342)
    assert not _instance_was_present(moved, before)


@test()
def test_gui_supervisor_port_reuse_without_pid_uses_start_time():
    old = {
        "host": "127.0.0.1",
        "port": 13341,
        "pid": None,
        "started_at": "2026-01-01T00:00:00",
        "idb_path": "F:/tmp/old.i64",
        "binary": "old.dll",
    }
    before = {("127.0.0.1", 13341): _instance_identity(old)}

    assert _instance_was_present(dict(old), before)
    assert not _instance_was_present(
        dict(old, started_at="2026-01-01T00:00:02"), before
    )
