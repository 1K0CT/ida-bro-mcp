"""Tests for the BinDiff low-similarity workflow helpers."""

import sqlite3
import tempfile
from pathlib import Path

from ..bindiff import (
    _normalize_insn,
    best_match,
    parse_binexport_dump,
    query_low_similarity,
)
from ..framework import test


def _make_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE metadata(version TEXT,file1 INT,file2 INT,description TEXT,
            created DATE,modified DATE,similarity REAL,confidence REAL);
        CREATE TABLE file(id INT,filename TEXT,exefilename TEXT,hash TEXT,
            functions INT,libfunctions INT,calls INT,basicblocks INT,
            libbasicblocks INT,edges INT,libedges INT,instructions INT,
            libinstructions INT);
        CREATE TABLE function(id INT,address1 BIGINT,name1 TEXT,address2 BIGINT,
            name2 TEXT,similarity REAL,confidence REAL,flags INT,algorithm INT,
            evaluate BOOLEAN,commentsported BOOLEAN,basicblocks INT,edges INT,
            instructions INT);
        CREATE TABLE functionalgorithm(id INT,name TEXT);
        INSERT INTO metadata VALUES ('test',1,2,'','now','now',0.8,0.9);
        INSERT INTO file VALUES (1,'old','old','',10,0,0,0,0,0,0,0,0);
        INSERT INTO file VALUES (2,'new','new','',10,0,0,0,0,0,0,0,0);
        INSERT INTO functionalgorithm VALUES (1,'function: hash matching');
        INSERT INTO function VALUES
            (1,0x1000,'same_name',0x2000,'same_name',1.0,0.99,0,1,0,0,3,2,5),
            (2,0x1100,'low_name',0x2100,'low_name',0.5,0.8,3,1,0,0,4,3,8),
            (3,0x1200,'tiny',0x2200,'tiny',0.2,0.7,0,1,0,0,1,0,2);
        """
    )
    conn.commit()
    conn.close()


@test()
def test_bindiff_parse_dump_and_normalize_instruction():
    dump = """Original executable name: test.dll
Functions:
0000000000001000 n Foo
0000000000002000 n Bar

0000000000001000 ; Foo
0000000000001000 ; ----------------------------------------
0000000000001000                 mov rax, rbx
0000000000001004                 call Bar ; comment
0000000000002000 ; Bar
0000000000002000 ; ----------------------------------------
0000000000002000                 retn
"""
    parsed = parse_binexport_dump(dump)
    assert parsed["functions"][0x1000] == "Foo"
    assert parsed["functions"][0x2000] == "Bar"
    assert len(parsed["sections"][0x1000]["instructions"]) == 2
    assert parsed["sections"][0x1000]["instructions"][1][1] == "call Bar ; comment"
    assert parsed["sections"][0x2000]["instructions"][0][0] == 0x2000
    assert _normalize_insn("call Bar ; comment") == "call Bar"
    assert _normalize_insn("mov  rax,  rbx") == "mov rax, rbx"


@test()
def test_bindiff_low_similarity_orders_and_filters():
    with tempfile.TemporaryDirectory(prefix="bindiff_test_") as tmp:
        db = Path(tmp) / "test.BinDiff"
        _make_db(db)

        result = query_low_similarity(
            db, max_similarity=1.0, min_instructions=3, limit=20
        )
        assert result["total"] == 2
        assert [f["id"] for f in result["functions"]] == [2, 1]
        assert result["functions"][0]["primary"]["addr"] == "0x1100"
        assert result["functions"][0]["algorithm_name"] == "function: hash matching"

        filtered = query_low_similarity(
            db, max_similarity=0.99, min_instructions=3,
            name_contains="low_name", limit=20,
        )
        assert filtered["total"] == 1
        assert filtered["functions"][0]["id"] == 2

        exact = query_low_similarity(
            db, max_similarity=0.99, min_instructions=3, limit=20
        )
        assert exact["total"] == 1
        assert exact["functions"][0]["id"] == 2


@test()
def test_bindiff_function_diff_uses_matched_and_flow_graph_sets():
    from unittest.mock import patch
    from ..bindiff import function_diff

    with tempfile.TemporaryDirectory(prefix="bindiff_test_") as tmp:
        root = Path(tmp)
        db = root / "test.BinDiff"
        conn = sqlite3.connect(db)
        conn.executescript(
            """
            CREATE TABLE metadata(version TEXT,file1 INT,file2 INT,description TEXT,
                created DATE,modified DATE,similarity REAL,confidence REAL);
            CREATE TABLE file(id INT,filename TEXT,exefilename TEXT,hash TEXT,
                functions INT,libfunctions INT,calls INT,basicblocks INT,
                libbasicblocks INT,edges INT,libedges INT,instructions INT,
                libinstructions INT);
            CREATE TABLE function(id INT,address1 BIGINT,name1 TEXT,address2 BIGINT,
                name2 TEXT,similarity REAL,confidence REAL,flags INT,algorithm INT,
                evaluate BOOLEAN,commentsported BOOLEAN,basicblocks INT,edges INT,
                instructions INT);
            CREATE TABLE functionalgorithm(id INT,name TEXT);
            CREATE TABLE basicblock(id INT,functionid INT,address1 BIGINT,
                address2 BIGINT,algorithm INT,evaluate BOOLEAN);
            CREATE TABLE instruction(basicblockid INT,address1 BIGINT,address2 BIGINT);
            INSERT INTO function VALUES
                (1,4096,'foo',8192,'foo',0.5,0.8,0,1,0,0,1,0,3);
            INSERT INTO functionalgorithm VALUES (1,'test algorithm');
            INSERT INTO basicblock VALUES (1,1,4096,8192,1,0);
            INSERT INTO instruction VALUES (1,4096,8192),(1,4100,8196);
            """
        )
        conn.commit()
        conn.close()
        primary = root / "primary.BinExport"
        secondary = root / "secondary.BinExport"
        primary.write_bytes(b"x")
        secondary.write_bytes(b"x")

        def fake_dump(path, tools=None):
            if Path(path).name == "primary.BinExport":
                return {"sections": {4096: {"instructions": [
                    (4096, "mov eax, 1"), (4100, "nop"), (4104, "ret"),
                ], "blocks": [4096]}}}
            return {"sections": {8192: {"instructions": [
                (8192, "mov eax, 2"), (8196, "nop"), (8200, "ret"),
            ], "blocks": [8192]}}}

        with patch("ida_pro_mcp.ida_mcp.bindiff._dump_for", side_effect=fake_dump):
            result = function_diff(
                db, "0x1000", primary_binexport=primary,
                secondary_binexport=secondary, max_differences=10,
            )
        assert result["function"]["primary"]["name"] == "foo"
        assert result["counts"]["matched_instructions"] == 2
        assert result["counts"]["changed_matched_instructions"] == 1
        assert result["counts"]["primary_only_instructions"] == 1
        assert result["counts"]["secondary_only_instructions"] == 1
        assert result["changed_matched_instructions"][0]["disasm1"] == "mov eax, 1"
        assert result["primary_only_instructions"][0]["addr"] == "0x1008"


@test()
def test_bindiff_best_match_by_address_name_and_unmatched():
    with tempfile.TemporaryDirectory(prefix="bindiff_test_") as tmp:
        db = Path(tmp) / "test.BinDiff"
        _make_db(db)

        by_addr = best_match(db, "0x1100")
        assert by_addr["error"] is None
        assert by_addr["function"]["id"] == 2
        assert by_addr["function"]["primary"]["name"] == "low_name"

        by_name = best_match(db, "low_name")
        assert by_name["function"]["id"] == 2

        missing = best_match(db, "not_present_in_db")
        assert missing["function"] is None
        assert "unmatched functions" in missing["error"]
