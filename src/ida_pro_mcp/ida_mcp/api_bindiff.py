"""MCP tools for BinDiff-based vulnerability-fix diffing.

The workflow is intentionally narrow: compare a current/new component against
an older IDB, then inspect matched functions whose similarity is low.  Matched
function pairs are the unit; unmatched functions are not part of this tool.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Annotated, NotRequired, TypedDict

from . import bindiff
from .rpc import tool
from .sync import idasync, tool_timeout


class BindiffDiffResult(TypedDict, total=False):
    database: str
    work_dir: str
    primary: dict
    secondary: dict
    summary: dict
    functions: list[dict]
    total: int
    offset: int
    limit: int
    log: dict
    error: NotRequired[str | None]


class BindiffLowSimilarityResult(TypedDict, total=False):
    database: str
    summary: dict
    functions: list[dict]
    total: int
    offset: int
    limit: int
    max_similarity: float
    error: NotRequired[str | None]


class BindiffFunctionDiffResult(TypedDict, total=False):
    database: str
    function: dict
    counts: dict
    changed_matched_instructions: list[dict]
    primary_only_instructions: list[dict]
    secondary_only_instructions: list[dict]
    truncated: dict
    text_available: bool
    note: NotRequired[str]
    error: NotRequired[str | None]


class BindiffBestMatchResult(TypedDict, total=False):
    database: str
    query: dict
    function: dict | None
    alternatives: list[dict]
    matched_count: int
    error: NotRequired[str | None]


def _workspace(output_dir: str) -> Path:
    if output_dir.strip():
        path = Path(output_dir.strip()).expanduser().resolve()
    else:
        path = Path(tempfile.mkdtemp(prefix="ida_mcp_bindiff_"))
    path.mkdir(parents=True, exist_ok=True)
    return path


def _has_binexport_idc() -> bool:
    try:
        import idaapi

        return bool(idaapi.find_idc_func("BinExport", 0))
    except Exception:
        return False


@tool
@idasync
@tool_timeout(900.0)
def bindiff_diff(
    secondary: Annotated[
        str,
        "Older/secondary IDB path (.i64/.idb) or .BinExport file; must not be open in IDA",
    ],
    primary: Annotated[
        str,
        "New/primary IDB or .BinExport path; empty means the currently open IDB",
    ] = "",
    output_dir: Annotated[
        str,
        "Output directory for .BinExport/.BinDiff; empty uses a temp directory",
    ] = "",
    max_similarity: Annotated[
        float, "Only return matched functions with similarity <= this value"
    ] = 0.99,
    min_confidence: Annotated[
        float, "Only return matches with confidence >= this value"
    ] = 0.0,
    min_instructions: Annotated[
        int, "Only return functions with at least this many matched instructions"
    ] = 5,
    name_contains: Annotated[
        str, "Optional case-sensitive substring filter on primary/secondary names"
    ] = "",
    offset: Annotated[int, "Skip the first N low-similarity functions"] = 0,
    limit: Annotated[
        int, "Max low-similarity functions to return (default: 20, max: 200)"
    ] = 20,
) -> BindiffDiffResult:
    """Diff a new IDB against an older IDB and list low-similarity matches.

    The current IDB is exported in-process with BinExportBinary, so it does not
    need to be closed or copied.  The older IDB is exported with the BinDiff
    CLI (it must be closed), then ``bindiff.exe`` produces a SQLite .BinDiff.
    Only matched functions with low similarity are returned; unmatched
    functions are intentionally ignored.

    Follow up with ``bindiff_function_diff`` on a returned primary address to
    inspect changed matched instructions and primary/secondary-only
    instructions.
    """
    try:
        if not secondary.strip():
            return {"error": "secondary IDB/BinExport path is required"}

        import idc

        tools = bindiff.find_tools()
        work = _workspace(output_dir)
        current_idb = idc.get_idb_path() or ""
        primary_binexport = work / "primary.BinExport"
        secondary_binexport = work / "secondary.BinExport"

        if not primary.strip():
            if not current_idb:
                return {"error": "no current IDB; pass primary explicitly"}
            if not _has_binexport_idc():
                return {
                    "error": "BinExport plugin/IDC function is not loaded; cannot export current IDB"
                }
            primary_source = current_idb
            bindiff.export_current_binexport(primary_binexport)
        else:
            primary_source = str(Path(primary.strip()).expanduser().resolve())
            if current_idb and Path(primary_source) == Path(current_idb).resolve():
                bindiff.export_current_binexport(primary_binexport)
            elif Path(primary_source).suffix.lower() == ".binexport":
                shutil.copy2(primary_source, primary_binexport)
            else:
                exported = bindiff.export_idb_binexport(
                    primary_source, work / "export_primary", tools
                )
                shutil.copy2(exported, primary_binexport)

        secondary_source = str(Path(secondary.strip()).expanduser().resolve())
        if Path(secondary_source).suffix.lower() == ".binexport":
            shutil.copy2(secondary_source, secondary_binexport)
        else:
            exported = bindiff.export_idb_binexport(
                secondary_source, work / "export_secondary", tools
            )
            shutil.copy2(exported, secondary_binexport)

        diff_info = bindiff.run_diff(
            primary_binexport, secondary_binexport, work, tools
        )
        database = Path(diff_info["database"])
        bindiff.write_sidecar(
            database,
            primary_binexport=primary_binexport,
            secondary_binexport=secondary_binexport,
            primary_source=primary_source,
            secondary_source=secondary_source,
        )
        summary = bindiff.query_summary(database)
        low = bindiff.query_low_similarity(
            database,
            max_similarity=max_similarity,
            min_confidence=min_confidence,
            min_instructions=min_instructions,
            name_contains=name_contains,
            offset=offset,
            limit=limit,
        )
        return {
            "database": str(database),
            "work_dir": str(work),
            "primary": {
                "source": primary_source,
                "binexport": str(primary_binexport),
                "current_idb": current_idb or None,
            },
            "secondary": {
                "source": secondary_source,
                "binexport": str(secondary_binexport),
            },
            "summary": summary,
            "functions": low["functions"],
            "total": low["total"],
            "offset": low["offset"],
            "limit": low["limit"],
            "log": {
                "stdout": diff_info.get("stdout", ""),
                "stderr": diff_info.get("stderr", ""),
            },
            "error": None,
        }
    except Exception as exc:
        return {"error": str(exc)}


@tool
@idasync
@tool_timeout(120.0)
def bindiff_low_similarity(
    database: Annotated[str, "Path to a .BinDiff SQLite database"],
    max_similarity: Annotated[
        float, "Only return matched functions with similarity <= this value"
    ] = 0.99,
    min_confidence: Annotated[
        float, "Only return matches with confidence >= this value"
    ] = 0.0,
    min_instructions: Annotated[
        int, "Only return functions with at least this many matched instructions"
    ] = 5,
    name_contains: Annotated[
        str, "Optional substring filter on primary/secondary names"
    ] = "",
    offset: Annotated[int, "Skip the first N matches"] = 0,
    limit: Annotated[int, "Max matches to return (default: 20, max: 200)"] = 20,
    sort: Annotated[
        str, "Sort by similarity, confidence, instructions, or name"
    ] = "similarity",
) -> BindiffLowSimilarityResult:
    """List only matched functions with low similarity from a .BinDiff DB.

    Use this after ``bindiff_diff`` when you want to re-query or page through
    the fix candidates without rerunning the comparison.
    """
    try:
        low = bindiff.query_low_similarity(
            database,
            max_similarity=max_similarity,
            min_confidence=min_confidence,
            min_instructions=min_instructions,
            name_contains=name_contains,
            offset=offset,
            limit=limit,
            sort=sort,
        )
        summary = bindiff.query_summary(database)
        return {
            "database": low["database"],
            "summary": summary,
            "functions": low["functions"],
            "total": low["total"],
            "offset": low["offset"],
            "limit": low["limit"],
            "max_similarity": low["max_similarity"],
            "error": None,
        }
    except Exception as exc:
        return {"error": str(exc)}


@tool
@idasync
@tool_timeout(60.0)
def bindiff_best_match(
    database: Annotated[str, "Path to a .BinDiff SQLite database"],
    addr: Annotated[
        str, "Primary/secondary function address or function name"
    ],
    side: Annotated[
        str, "Which side addr refers to: auto, primary, or secondary"
    ] = "auto",
    max_alternatives: Annotated[
        int, "Max lower-ranked duplicate-name alternatives to return (default: 10)"
    ] = 10,
) -> BindiffBestMatchResult:
    """Find the highest-similarity matched counterpart for a function.

    The BinDiff database stores matched pairs only.  For a primary/secondary
    address or unique name this returns its match; if the name occurs in
    multiple matched pairs, the pair with the highest similarity is returned
    first and the others are listed as alternatives.  Unmatched functions are
    not present and yield an explanatory error.
    """
    try:
        result = bindiff.best_match(
            database,
            addr,
            side=side,
            max_alternatives=max_alternatives,
        )
        result.setdefault("error", None)
        return result
    except Exception as exc:
        return {
            "database": str(database),
            "query": {"addr": str(addr), "side": side},
            "function": None,
            "alternatives": [],
            "matched_count": 0,
            "error": str(exc),
        }


@tool
@idasync
@tool_timeout(300.0)
def bindiff_function_diff(
    database: Annotated[str, "Path to a .BinDiff SQLite database"],
    addr: Annotated[
        str, "Primary/secondary function address or function name"
    ],
    side: Annotated[
        str, "Which side addr refers to: auto, primary, or secondary"
    ] = "auto",
    max_differences: Annotated[
        int, "Max items in each difference list (default: 200, max: 2000)"
    ] = 200,
    primary_binexport: Annotated[
        str, "Optional primary .BinExport path (otherwise read sidecar)"
    ] = "",
    secondary_binexport: Annotated[
        str, "Optional secondary .BinExport path (otherwise read sidecar)"
    ] = "",
) -> BindiffFunctionDiffResult:
    """Show instruction-level differences for one matched function pair.

    Returns changed matched instructions (same match, different disassembly) and
    instructions only present in the primary or secondary flow graph.  This is
    the main tool for looking at the fix: filter ``bindiff_diff`` by low
    similarity, then call this for the matching primary address or name.
    """
    try:
        result = bindiff.function_diff(
            database,
            addr,
            side=side,
            max_differences=max_differences,
            primary_binexport=primary_binexport or None,
            secondary_binexport=secondary_binexport or None,
        )
        result.setdefault("database", bindiff._asan_path(Path(database)))
        result.setdefault("error", None)
        return result
    except Exception as exc:
        return {"database": str(database), "error": str(exc)}
