"""Tests for the x86_64 exception-handling flow helpers."""

from ..api_eh import exception_flow
from ..eh import _classify_kind
from ..framework import test


@test()
def test_eh_classifies_msvc_filter_and_finally_names():
    """MSVC's $filt$ / $fin$ routine names distinguish the clause kind."""
    assert _classify_kind("main$filt$0", 0, True) == "except"
    assert _classify_kind("multi$fin$1", 0, True) == "finally"
    assert _classify_kind(None, 1, False) == "except"
    assert _classify_kind(None, 0, False) == "unknown"


@test(binary="crackme03.elf")
def test_exception_flow_reports_no_eh_for_plain_c_binary():
    """A plain C function returns a valid empty flow, not an error."""
    result = exception_flow({"addr": "main"})
    assert len(result) == 1
    item = result[0]
    assert item["error"] is None
    assert item["function"]["name"] == "main"
    assert item["try_blocks"] == [], item["try_blocks"]
    assert item["nodes"] == []
    assert item["edges"] == []
