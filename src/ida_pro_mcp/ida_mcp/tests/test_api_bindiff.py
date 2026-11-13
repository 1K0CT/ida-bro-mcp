"""Tests for the BinDiff low-similarity workflow helpers."""

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

from ..bindiff import (
    BindiffError,
    _normalize_insn,
    best_match,
    new_functions,
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
0000000000002000 l Bar

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
    assert parsed["function_flags"][0x1000] == "n"
    assert parsed["function_flags"][0x2000] == "l"
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


def _new_function_dump_data():
    def section(base, count):
        return {
            "name": "x",
            "instructions": [(base + i, "nop") for i in range(count)],
            "blocks": [base],
        }

    primary_functions = {
        0x1000: "same_name",
        0x1100: "low_name",
        0x1200: "tiny",
        0x1300: "BrandNew",
        0x1400: "__imp_NewImport",
        0x1500: "NewThunk",
        0x1600: "LibNew",
        0x1700: "MovedByName",
    }
    primary_flags = {
        0x1000: "n",
        0x1100: "n",
        0x1200: "n",
        0x1300: "n",
        0x1400: "i",
        0x1500: "t",
        0x1600: "l",
        0x1700: "n",
    }
    primary_sections = {
        0x1000: section(0x400000, 5),
        0x1100: section(0x401000, 8),
        0x1200: section(0x402000, 2),
        0x1300: section(0x403000, 7),
        0x1400: section(0x404000, 0),
        0x1500: section(0x405000, 1),
        0x1600: section(0x406000, 3),
        0x1700: section(0x407000, 4),
    }

    secondary_functions = {
        0x2000: "same_name",
        0x2100: "low_name",
        0x2200: "tiny",
        0x2300: "MovedByName",
        0x2400: "Removed",
    }
    secondary_sections = {
        addr: section(0x500000 + idx * 0x1000, 1)
        for idx, addr in enumerate(secondary_functions)
    }
    return (
        {
            "functions": primary_functions,
            "function_flags": primary_flags,
            "sections": primary_sections,
        },
        {
            "functions": secondary_functions,
            "function_flags": {addr: "n" for addr in secondary_functions},
            "sections": secondary_sections,
        },
    )


@test()
def test_bindiff_new_functions_filters_kinds_and_marks_moves():
    primary_data, secondary_data = _new_function_dump_data()

    def fake_dump(path, tools=None):
        if Path(path).name == "primary.BinExport":
            return primary_data
        return secondary_data

    with tempfile.TemporaryDirectory(prefix="bindiff_test_") as tmp:
        root = Path(tmp)
        db = root / "test.BinDiff"
        _make_db(db)
        primary = root / "primary.BinExport"
        secondary = root / "secondary.BinExport"
        primary.write_bytes(b"x")
        secondary.write_bytes(b"x")

        with patch("ida_pro_mcp.ida_mcp.bindiff._dump_for", side_effect=fake_dump):
            result = new_functions(
                db, primary_binexport=primary,
                secondary_binexport=secondary,
            )

        assert result["summary"]["primary_functions"] == 8
        assert result["summary"]["secondary_functions"] == 5
        assert result["summary"]["matched_pairs"] == 3
        assert result["summary"]["unmatched"] == {"primary": 5, "secondary": 2}
        assert result["summary"]["filtered"] == {
            "imports": 1,
            "thunks": 1,
            "library": 1,
            "min_instructions": 0,
            "name_contains": 0,
            "name_matches": 0,
        }
        assert result["total"] == 2
        assert [f["name"] for f in result["functions"]] == [
            "BrandNew",
            "MovedByName",
        ]
        assert result["functions"][0]["kind"] == "normal"
        assert result["functions"][0]["name_in_other_version"] is False
        assert result["functions"][1]["name_in_other_version"] is True

        with patch("ida_pro_mcp.ida_mcp.bindiff._dump_for", side_effect=fake_dump):
            expanded = new_functions(
                db,
                primary_binexport=primary,
                secondary_binexport=secondary,
                include_imports=True,
                include_thunks=True,
                include_library=True,
            )
        assert expanded["total"] == 5
        assert [f["name"] for f in expanded["functions"]] == [
            "BrandNew",
            "__imp_NewImport",
            "NewThunk",
            "LibNew",
            "MovedByName",
        ]

        with patch("ida_pro_mcp.ida_mcp.bindiff._dump_for", side_effect=fake_dump):
            without_moves = new_functions(
                db,
                primary_binexport=primary,
                secondary_binexport=secondary,
                exclude_name_matches=True,
            )
        assert [f["name"] for f in without_moves["functions"]] == ["BrandNew"]

        with patch("ida_pro_mcp.ida_mcp.bindiff._dump_for", side_effect=fake_dump):
            large = new_functions(
                db,
                primary_binexport=primary,
                secondary_binexport=secondary,
                min_instructions=5,
            )
        assert [f["name"] for f in large["functions"]] == ["BrandNew"]


@test()
def test_bindiff_new_functions_name_filter_and_paging():
    primary_data, secondary_data = _new_function_dump_data()

    def fake_dump(path, tools=None):
        if Path(path).name == "primary.BinExport":
            return primary_data
        return secondary_data

    with tempfile.TemporaryDirectory(prefix="bindiff_test_") as tmp:
        root = Path(tmp)
        db = root / "test.BinDiff"
        _make_db(db)
        primary = root / "primary.BinExport"
        secondary = root / "secondary.BinExport"
        primary.write_bytes(b"x")
        secondary.write_bytes(b"x")

        with patch("ida_pro_mcp.ida_mcp.bindiff._dump_for", side_effect=fake_dump):
            named = new_functions(
                db,
                primary_binexport=primary,
                secondary_binexport=secondary,
                name_contains="brand",
            )
        assert [f["name"] for f in named["functions"]] == ["BrandNew"]

        with patch("ida_pro_mcp.ida_mcp.bindiff._dump_for", side_effect=fake_dump):
            paged = new_functions(
                db,
                primary_binexport=primary,
                secondary_binexport=secondary,
                include_imports=True,
                include_thunks=True,
                include_library=True,
                offset=1,
                limit=1,
            )
        assert paged["total"] == 5
        assert [f["name"] for f in paged["functions"]] == ["__imp_NewImport"]


@test()
def test_bindiff_new_functions_rejects_wrong_binexport():
    primary_data, secondary_data = _new_function_dump_data()
    primary_data["functions"].pop(0x1000)

    def fake_dump(path, tools=None):
        if Path(path).name == "primary.BinExport":
            return primary_data
        return secondary_data

    with tempfile.TemporaryDirectory(prefix="bindiff_test_") as tmp:
        root = Path(tmp)
        db = root / "test.BinDiff"
        _make_db(db)
        with patch("ida_pro_mcp.ida_mcp.bindiff._dump_for", side_effect=fake_dump):
            try:
                new_functions(
                    db,
                    primary_binexport=root / "primary.BinExport",
                    secondary_binexport=root / "secondary.BinExport",
                )
            except BindiffError as exc:
                assert "do not match" in str(exc)
            else:
                assert False, "expected BindiffError for mismatched BinExport"
