"""BinDiff orchestration and low-similarity function diff helpers.

The target workflow is vulnerability-diffing a frequently updated component:
only matched functions with low similarity are interesting.  This module
therefore deliberately ignores unmatched functions and exposes the matched
pair, similarity/confidence, and instruction-level differences.

It uses three stable interfaces:

* the BinExport IDC function ``BinExportBinary(path)`` to export the currently
  open IDB without closing or saving it;
* the external ``bindiff.exe`` CLI to export closed IDBs and to run matching;
* the SQLite ``.BinDiff`` result database plus ``binexport2dump.exe`` text
  dumps for instruction texts.

It does not call BinDiff/Tryblk GUI actions or ``BinDiffDatabase``: those are
dialog-driven and not reliably scriptable.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from .utils import demangle_symbol_name


class BindiffError(RuntimeError):
    """Raised for BinDiff configuration/export/diff/query failures."""


# ---------------------------------------------------------------------------
# BinDiff tool discovery
# ---------------------------------------------------------------------------


def _config_dirs() -> list[Path]:
    dirs: list[Path] = []
    env_dir = os.environ.get("IDA_MCP_BINDIFF_DIR", "").strip()
    if env_dir:
        dirs.append(Path(env_dir))
    config_paths = [
        Path(os.environ.get("APPDATA", "")) / "BinDiff" / "bindiff.json",
        Path(os.environ.get("PROGRAMDATA", "")) / "BinDiff" / "bindiff.json",
    ]
    for cfg_path in config_paths:
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            directory = str(cfg.get("directory") or "").strip()
            if directory:
                dirs.append(Path(directory))
        except Exception:
            continue
    dirs.append(Path(r"C:\Program Files\BinDiff"))
    return dirs


def find_tools() -> dict[str, Path | None]:
    """Locate bindiff.exe / binexport2dump.exe.

    ``IDA_MCP_BINDIFF_EXE`` can override the executable path.
    """
    explicit = os.environ.get("IDA_MCP_BINDIFF_EXE", "").strip()
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    for directory in _config_dirs():
        candidates.append(directory / "bin" / "bindiff.exe")
        candidates.append(directory / "bindiff.exe")
    which = shutil.which("bindiff.exe")
    if which:
        candidates.append(Path(which))

    for candidate in candidates:
        if candidate.is_file():
            bindiff = candidate.resolve()
            dump = bindiff.with_name("binexport2dump.exe")
            return {
                "bindiff": bindiff,
                "binexport2dump": dump if dump.is_file() else None,
                "directory": bindiff.parent.parent,
            }
    raise BindiffError(
        "bindiff.exe not found; set IDA_MCP_BINDIFF_EXE or install BinDiff"
    )


# ---------------------------------------------------------------------------
# Process helpers
# ---------------------------------------------------------------------------


def _run(cmd: list[str], *, timeout: float = 600.0) -> subprocess.CompletedProcess:
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
    except subprocess.TimeoutExpired as exc:
        raise BindiffError(f"command timed out after {timeout:.0f}s: {cmd[0]}") from exc
    except OSError as exc:
        raise BindiffError(f"cannot run {cmd[0]}: {exc}") from exc
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise BindiffError(
            f"{Path(cmd[0]).name} exited with {proc.returncode}: {detail[:2000]}"
        )
    return proc


def _asan_path(path: Path) -> str:
    return path.resolve().as_posix()


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------


def export_current_binexport(output_path: str | Path) -> Path:
    """Export the currently open IDB via BinExportBinary(path)."""
    import idc

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    idc_path = _asan_path(output)
    if '"' in idc_path or "\n" in idc_path or "\r" in idc_path:
        raise BindiffError(f"unsupported BinExport path: {output}")
    try:
        ret = idc.eval_idc(f'BinExportBinary("{idc_path}")')
    except Exception as exc:
        raise BindiffError(f"BinExportBinary failed: {exc}") from exc
    if ret not in (0, "0", 1, "1", True):
        raise BindiffError(f"BinExportBinary returned {ret!r}")
    if not output.is_file() or output.stat().st_size == 0:
        raise BindiffError(f"BinExportBinary did not create {output}")
    return output


def _idb_export_name(source: Path) -> str:
    name = source.name
    lower = name.lower()
    for suffix in (".i64", ".idb"):
        if lower.endswith(suffix):
            return name[: -len(suffix)] + ".BinExport"
    return name + ".BinExport"


def _stage_idb(source: Path, staging_dir: Path) -> None:
    """Copy an IDB and its loose components into an isolated export dir."""
    staging_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, staging_dir / source.name)
    if source.suffix.lower() == ".idb":
        for suffix in (".id0", ".id1", ".id2", ".nam", ".til"):
            sibling = source.with_name(source.stem + suffix)
            if sibling.is_file():
                shutil.copy2(sibling, staging_dir / sibling.name)


def export_idb_binexport(
    source_path: str | Path, output_dir: str | Path, tools: dict | None = None
) -> Path:
    """Export a closed .i64/.idb (or pass through a .BinExport)."""
    source = Path(source_path).resolve()
    if not source.is_file():
        raise BindiffError(f"input does not exist: {source}")
    if source.suffix.lower() == ".binexport":
        return source

    tools = tools or find_tools()
    bindiff = tools.get("bindiff")
    if bindiff is None:
        raise BindiffError("bindiff.exe not found")

    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    staging = out_dir / "_input"
    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    _stage_idb(source, staging)

    expected = out_dir / _idb_export_name(source)
    _run(
        [
            str(bindiff),
            "--export",
            f"--output_dir={_asan_path(out_dir)}",
            "--logo=false",
            _asan_path(staging),
        ],
        timeout=600.0,
    )
    if expected.is_file() and expected.stat().st_size:
        return expected
    candidates = sorted(
        out_dir.glob("*.BinExport"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if candidates:
        return candidates[0]
    raise BindiffError(f"BinDiff export produced no .BinExport for {source}")


def _copy_binexport(source: Path, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if source.resolve() != destination.resolve():
        shutil.copy2(source, destination)
    return destination


# ---------------------------------------------------------------------------
# Diff and result database
# ---------------------------------------------------------------------------


def run_diff(
    primary_binexport: str | Path,
    secondary_binexport: str | Path,
    output_dir: str | Path,
    tools: dict | None = None,
) -> dict[str, Any]:
    """Run bindiff.exe on two BinExport files and return result metadata."""
    tools = tools or find_tools()
    bindiff = tools.get("bindiff")
    if bindiff is None:
        raise BindiffError("bindiff.exe not found")

    primary = Path(primary_binexport).resolve()
    secondary = Path(secondary_binexport).resolve()
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    for path in (primary, secondary):
        if not path.is_file() or path.stat().st_size == 0:
            raise BindiffError(f"invalid BinExport: {path}")

    proc = _run(
        [
            str(bindiff),
            f"--primary={_asan_path(primary)}",
            f"--secondary={_asan_path(secondary)}",
            f"--output_dir={_asan_path(out_dir)}",
            "--output_format=bin",
            "--logo=false",
        ],
        timeout=600.0,
    )

    expected = out_dir / f"{primary.stem}_vs_{secondary.stem}.BinDiff"
    database = expected if expected.is_file() else None
    if database is None:
        candidates = sorted(
            out_dir.glob("*.BinDiff"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        database = candidates[0] if candidates else None
    if database is None:
        raise BindiffError(
            "BinDiff completed without producing a .BinDiff database"
        )

    return {
        "database": database,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
    }


def sidecar_path(database: str | Path) -> Path:
    database = Path(database)
    return database.with_name(database.name + ".ida_mcp.json")


def write_sidecar(
    database: str | Path,
    *,
    primary_binexport: str | Path,
    secondary_binexport: str | Path,
    primary_source: str | Path,
    secondary_source: str | Path,
) -> Path:
    path = sidecar_path(database)
    payload = {
        "primary_binexport": _asan_path(Path(primary_binexport)),
        "secondary_binexport": _asan_path(Path(secondary_binexport)),
        "primary_source": _asan_path(Path(primary_source)),
        "secondary_source": _asan_path(Path(secondary_source)),
        "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def read_sidecar(database: str | Path) -> dict[str, Any]:
    path = sidecar_path(database)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _connect(database: str | Path) -> sqlite3.Connection:
    path = Path(database).resolve()
    if not path.is_file():
        raise BindiffError(f"database not found: {path}")
    conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def _name(value: Any) -> str:
    if not value:
        return ""
    try:
        return demangle_symbol_name(str(value))
    except Exception:
        return str(value)


def _hex(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return hex(int(value))
    except Exception:
        return None


def _function_summary(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "primary": {
            "addr": _hex(row["address1"]),
            "name": _name(row["name1"]),
        },
        "secondary": {
            "addr": _hex(row["address2"]),
            "name": _name(row["name2"]),
        },
        "similarity": row["similarity"],
        "confidence": row["confidence"],
        "flags": row["flags"],
        "algorithm": row["algorithm"],
        "evaluate": bool(row["evaluate"]),
        "commentsported": bool(row["commentsported"]),
        "matched_basicblocks": row["basicblocks"],
        "matched_edges": row["edges"],
        "matched_instructions": row["instructions"],
    }


def query_summary(database: str | Path) -> dict[str, Any]:
    """Return compact metadata and match statistics from a .BinDiff database."""
    conn = _connect(database)
    try:
        cur = conn.cursor()
        meta_row = cur.execute("SELECT * FROM metadata LIMIT 1").fetchone()
        file_rows = cur.execute(
            "SELECT id, filename, exefilename, hash, functions, libfunctions, "
            "calls, basicblocks, libbasicblocks, edges, libedges, "
            "instructions, libinstructions FROM file ORDER BY id"
        ).fetchall()
        matched = cur.execute("SELECT COUNT(*) FROM function").fetchone()[0]
        row = cur.execute(
            "SELECT MIN(similarity), MAX(similarity), "
            "MIN(confidence), MAX(confidence) FROM function"
        ).fetchone()
        files = []
        for file_row in file_rows:
            files.append(
                {
                    "id": file_row["id"],
                    "filename": file_row["filename"],
                    "exefilename": file_row["exefilename"],
                    "hash": file_row["hash"],
                    "functions": file_row["functions"],
                    "libfunctions": file_row["libfunctions"],
                    "calls": file_row["calls"],
                    "basicblocks": file_row["basicblocks"],
                    "libbasicblocks": file_row["libbasicblocks"],
                    "edges": file_row["edges"],
                    "libedges": file_row["libedges"],
                    "instructions": file_row["instructions"],
                    "libinstructions": file_row["libinstructions"],
                }
            )
        return {
            "database": _asan_path(Path(database)),
            "engine": meta_row["version"] if meta_row else None,
            "created": meta_row["created"] if meta_row else None,
            "modified": meta_row["modified"] if meta_row else None,
            "description": meta_row["description"] if meta_row else None,
            "similarity": meta_row["similarity"] if meta_row else None,
            "confidence": meta_row["confidence"] if meta_row else None,
            "matched_functions": matched,
            "min_similarity": row[0] if row else None,
            "max_similarity": row[1] if row else None,
            "min_confidence": row[2] if row else None,
            "max_confidence": row[3] if row else None,
            "files": files,
        }
    finally:
        conn.close()


_SORT_COLUMNS = {
    "similarity": "f.similarity ASC, f.confidence ASC, f.instructions DESC, f.id ASC",
    "confidence": "f.confidence ASC, f.similarity ASC, f.instructions DESC, f.id ASC",
    "instructions": "f.instructions DESC, f.similarity ASC, f.id ASC",
    "name": "COALESCE(f.name1, '') ASC, f.id ASC",
}


def query_low_similarity(
    database: str | Path,
    *,
    max_similarity: float = 0.99,
    min_confidence: float = 0.0,
    min_instructions: int = 0,
    name_contains: str = "",
    offset: int = 0,
    limit: int = 20,
    sort: str = "similarity",
) -> dict[str, Any]:
    """Return only matched functions with similarity <= max_similarity."""
    max_similarity = max(0.0, min(1.0, float(max_similarity)))
    min_confidence = max(0.0, min(1.0, float(min_confidence)))
    min_instructions = max(0, int(min_instructions))
    offset = max(0, int(offset))
    limit = max(1, min(200, int(limit)))
    order = _SORT_COLUMNS.get(sort, _SORT_COLUMNS["similarity"])

    where = [
        "f.similarity <= ?",
        "f.confidence >= ?",
        "f.instructions >= ?",
    ]
    params: list[Any] = [max_similarity, min_confidence, min_instructions]
    if name_contains:
        where.append("(f.name1 LIKE ? OR f.name2 LIKE ?)")
        pattern = f"%{name_contains}%"
        params.extend([pattern, pattern])

    conn = _connect(database)
    try:
        cur = conn.cursor()
        base_where = " AND ".join(where)
        total = cur.execute(
            f"SELECT COUNT(*) FROM function f WHERE {base_where}", params
        ).fetchone()[0]
        rows = cur.execute(
            "SELECT f.id, f.address1, f.name1, f.address2, f.name2, "
            "f.similarity, f.confidence, f.flags, f.algorithm, "
            "f.evaluate, f.commentsported, f.basicblocks, f.edges, "
            "f.instructions, COALESCE(a.name, '') AS algorithm_name "
            "FROM function f LEFT JOIN functionalgorithm a ON a.id = f.algorithm "
            f"WHERE {base_where} ORDER BY {order} LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()
    finally:
        conn.close()

    functions = []
    for row in rows:
        functions.append(
            {
                "id": row["id"],
                "primary": {
                    "addr": _hex(row["address1"]),
                    "name": _name(row["name1"]),
                },
                "secondary": {
                    "addr": _hex(row["address2"]),
                    "name": _name(row["name2"]),
                },
                "similarity": row["similarity"],
                "confidence": row["confidence"],
                "flags": row["flags"],
                "algorithm": row["algorithm"],
                "algorithm_name": row["algorithm_name"],
                "evaluate": bool(row["evaluate"]),
                "commentsported": bool(row["commentsported"]),
                "matched_basicblocks": row["basicblocks"],
                "matched_edges": row["edges"],
                "matched_instructions": row["instructions"],
            }
        )
    return {
        "database": _asan_path(Path(database)),
        "total": total,
        "offset": offset,
        "limit": limit,
        "max_similarity": max_similarity,
        "functions": functions,
    }


# ---------------------------------------------------------------------------
# BinExport text dumps and function-level diffs
# ---------------------------------------------------------------------------


_HEADER_RE = re.compile(r"^([0-9A-Fa-f]{16})\s+;\s+(.*)$")
_INSN_RE = re.compile(r"^([0-9A-Fa-f]{16})\s+(.+)$")
_FUNC_RE = re.compile(r"^([0-9A-Fa-f]{16})\s+(\S+)\s+(.*)$")
_DUMP_CACHE: dict[tuple[str, int, int], dict[str, Any]] = {}


def parse_binexport_dump(text: str) -> dict[str, Any]:
    """Parse the textual output of binexport2dump.exe.

    Returns ``{"functions": {addr: name}, "function_flags": {addr: flag},
    "sections": {addr: {...}}}``.  The flag is BinExport's function type:
    ``n`` normal, ``l`` library, ``i`` imported, ``t`` thunk.  A function
    section contains its instruction list and block-start addresses.
    """
    lines = text.splitlines()
    functions: dict[int, str] = {}
    function_flags: dict[int, str] = {}
    try:
        start = lines.index("Functions:") + 1
    except ValueError:
        start = 0
        for idx, line in enumerate(lines):
            if line.strip() == "Functions:":
                start = idx + 1
                break

    for line in lines[start:]:
        if not line.strip():
            break
        match = _FUNC_RE.match(line.strip())
        if match:
            addr = int(match.group(1), 16)
            functions[addr] = match.group(3).strip()
            function_flags[addr] = match.group(2)

    starts = set(functions)
    sections: dict[int, dict[str, Any]] = {}
    current: int | None = None
    for line in lines[start:]:
        stripped = line.rstrip()
        if not stripped:
            continue
        header = _HEADER_RE.match(stripped)
        if header:
            addr = int(header.group(1), 16)
            comment = header.group(2).strip()
            if comment.startswith("---"):
                if current is not None:
                    sections[current]["blocks"].append(addr)
                continue
            if addr in starts and comment:
                current = addr
                sections.setdefault(
                    current, {"name": comment, "instructions": [], "blocks": []}
                )
            continue
        insn = _INSN_RE.match(stripped)
        if insn and current is not None:
            text_value = insn.group(2).strip()
            if text_value and not text_value.startswith(";"):
                sections[current]["instructions"].append(
                    (int(insn.group(1), 16), text_value)
                )
    return {
        "functions": functions,
        "function_flags": function_flags,
        "sections": sections,
    }


def _dump_for(
    binexport: str | Path, tools: dict | None = None
) -> dict[str, Any]:
    path = Path(binexport).resolve()
    if not path.is_file():
        raise BindiffError(f"BinExport not found: {path}")
    stat = path.stat()
    key = (_asan_path(path), stat.st_mtime_ns, stat.st_size)
    cached = _DUMP_CACHE.get(key)
    if cached is not None:
        return cached

    tools = tools or find_tools()
    dump_exe = tools.get("binexport2dump")
    if dump_exe is None:
        raise BindiffError("binexport2dump.exe not found")
    proc = _run([str(dump_exe), _asan_path(path)], timeout=180.0)
    parsed = parse_binexport_dump(proc.stdout)
    _DUMP_CACHE[key] = parsed
    if len(_DUMP_CACHE) > 8:
        _DUMP_CACHE.pop(next(iter(_DUMP_CACHE)))
    return parsed


def _normalize_insn(text: str) -> str:
    # Comments are not an instruction difference; compare the actual operands.
    code = text.split(";", 1)[0]
    return " ".join(code.split())


def _instruction_map(section: dict[str, Any] | None) -> dict[int, str]:
    if not section:
        return {}
    return {addr: text for addr, text in section.get("instructions", [])}


def _slice(items: list[Any], limit: int) -> tuple[list[Any], bool]:
    if limit < 0:
        limit = 0
    if len(items) > limit:
        return items[:limit], True
    return items, False


def _matched_rows(
    cur: sqlite3.Cursor, addr_text: str, side: str
) -> list[sqlite3.Row]:
    value: int | None = None
    try:
        value = int(addr_text, 0)
    except (TypeError, ValueError):
        value = None

    side = side.lower()
    if value is not None:
        if side == "primary":
            return cur.execute(
                "SELECT * FROM function WHERE address1 = ? "
                "ORDER BY similarity DESC LIMIT 50",
                (value,),
            ).fetchall()
        if side == "secondary":
            return cur.execute(
                "SELECT * FROM function WHERE address2 = ? "
                "ORDER BY similarity DESC LIMIT 50",
                (value,),
            ).fetchall()
        return cur.execute(
            "SELECT * FROM function WHERE address1 = ? OR address2 = ? "
            "ORDER BY similarity DESC LIMIT 50",
            (value, value),
        ).fetchall()

    if side == "primary":
        return cur.execute(
            "SELECT * FROM function WHERE name1 = ? "
            "ORDER BY similarity DESC LIMIT 50",
            (addr_text,),
        ).fetchall()
    if side == "secondary":
        return cur.execute(
            "SELECT * FROM function WHERE name2 = ? "
            "ORDER BY similarity DESC LIMIT 50",
            (addr_text,),
        ).fetchall()
    return cur.execute(
        "SELECT * FROM function WHERE name1 = ? OR name2 = ? "
        "ORDER BY similarity DESC LIMIT 50",
        (addr_text, addr_text),
    ).fetchall()


def _function_query(
    cur: sqlite3.Cursor, addr_text: str, side: str
) -> tuple[sqlite3.Row | None, list[sqlite3.Row]]:
    rows = _matched_rows(cur, addr_text, side)
    return (rows[0] if len(rows) == 1 else None), rows


def best_match(
    database: str | Path,
    addr: str,
    *,
    side: str = "auto",
    max_alternatives: int = 10,
) -> dict[str, Any]:
    """Find the highest-similarity matched counterpart for a function.

    The BinDiff database contains matched pairs only.  For a primary or
    secondary address/name this is normally its own match; if a name occurs in
    multiple pairs, all matching rows are ranked by similarity descending and
    the best is returned with the rest as alternatives.
    """
    max_alternatives = max(0, min(50, int(max_alternatives)))
    addr_text = str(addr).strip()
    conn = _connect(database)
    try:
        cur = conn.cursor()
        rows = _matched_rows(cur, addr_text, side)
        if not rows:
            return {
                "database": _asan_path(Path(database)),
                "query": {"addr": addr_text, "side": side},
                "function": None,
                "alternatives": [],
                "error": (
                    "not a matched function in this BinDiff database; "
                    "unmatched functions are intentionally ignored"
                ),
            }
        best = _function_summary(rows[0])
        alternatives = [
            _function_summary(row)
            for row in rows[1 : 1 + max_alternatives]
        ]
        return {
            "database": _asan_path(Path(database)),
            "query": {"addr": addr_text, "side": side},
            "function": best,
            "alternatives": alternatives,
            "matched_count": len(rows),
            "error": None,
        }
    finally:
        conn.close()


def function_diff(
    database: str | Path,
    addr: str,
    *,
    side: str = "auto",
    max_differences: int = 200,
    primary_binexport: str | Path | None = None,
    secondary_binexport: str | Path | None = None,
) -> dict[str, Any]:
    """Return instruction-level differences for one matched function pair."""
    max_differences = max(1, min(2000, int(max_differences)))
    conn = _connect(database)
    try:
        cur = conn.cursor()
        row, matches = _function_query(cur, str(addr).strip(), side)
        if row is None:
            if matches:
                return {
                    "error": f"ambiguous function {addr!r}; use a primary/secondary address",
                    "candidates": [
                        {
                            "id": item["id"],
                            "address1": _hex(item["address1"]),
                            "name1": _name(item["name1"]),
                            "address2": _hex(item["address2"]),
                            "name2": _name(item["name2"]),
                            "similarity": item["similarity"],
                        }
                        for item in matches
                    ],
                }
            return {"error": f"matched function not found: {addr!r}"}

        func_id = row["id"]
        address1 = row["address1"]
        address2 = row["address2"]
        pairs = cur.execute(
            "SELECT i.address1, i.address2 FROM instruction i "
            "JOIN basicblock b ON b.id = i.basicblockid "
            "WHERE b.functionid = ? ORDER BY i.address1, i.address2",
            (func_id,),
        ).fetchall()
        matched_basic_blocks = cur.execute(
            "SELECT COUNT(*) FROM basicblock WHERE functionid = ?", (func_id,)
        ).fetchone()[0]
        algorithm_name = cur.execute(
            "SELECT name FROM functionalgorithm WHERE id = ?", (row["algorithm"],)
        ).fetchone()
    finally:
        conn.close()

    # Prefer the sidecar written by bindiff_diff; explicit arguments win.
    sidecar = read_sidecar(database)
    primary_path = primary_binexport or sidecar.get("primary_binexport")
    secondary_path = secondary_binexport or sidecar.get("secondary_binexport")
    sections1: dict[int, Any] = {}
    sections2: dict[int, Any] = {}
    text_available = bool(primary_path and secondary_path)
    dump_error = None
    if text_available:
        try:
            sections1 = _dump_for(primary_path).get("sections", {})
            sections2 = _dump_for(secondary_path).get("sections", {})
        except Exception as exc:
            text_available = False
            dump_error = str(exc)

    section1 = sections1.get(address1)
    section2 = sections2.get(address2)
    if text_available and (section1 is None or section2 is None):
        text_available = False
        dump_error = "function section not found in BinExport dump"
    instrs1 = _instruction_map(section1)
    instrs2 = _instruction_map(section2)
    primary_addrs = {pair["address1"] for pair in pairs}
    secondary_addrs = {pair["address2"] for pair in pairs}

    changed: list[dict[str, Any]] = []
    if text_available and instrs1 and instrs2:
        for pair in pairs:
            a1, a2 = pair["address1"], pair["address2"]
            t1 = instrs1.get(a1)
            t2 = instrs2.get(a2)
            if t1 is None or t2 is None:
                continue
            if _normalize_insn(t1) != _normalize_insn(t2):
                changed.append(
                    {
                        "addr1": _hex(a1),
                        "addr2": _hex(a2),
                        "disasm1": t1,
                        "disasm2": t2,
                    }
                )

    primary_only = [
        {"addr": _hex(a), "disasm": instrs1[a]}
        for a in sorted(set(instrs1) - primary_addrs)
    ]
    secondary_only = [
        {"addr": _hex(a), "disasm": instrs2[a]}
        for a in sorted(set(instrs2) - secondary_addrs)
    ]
    changed_total = len(changed)
    primary_only_total = len(primary_only)
    secondary_only_total = len(secondary_only)
    changed, changed_truncated = _slice(changed, max_differences)
    primary_only, primary_truncated = _slice(primary_only, max_differences)
    secondary_only, secondary_truncated = _slice(secondary_only, max_differences)

    flow1 = len(instrs1)
    flow2 = len(instrs2)
    blocks1 = len(section1.get("blocks", [])) if section1 else 0
    blocks2 = len(section2.get("blocks", [])) if section2 else 0

    result: dict[str, Any] = {
        "database": _asan_path(Path(database)),
        "function": {
            "id": func_id,
            "primary": {
                "addr": _hex(address1),
                "name": _name(row["name1"]),
            },
            "secondary": {
                "addr": _hex(address2),
                "name": _name(row["name2"]),
            },
            "similarity": row["similarity"],
            "confidence": row["confidence"],
            "flags": row["flags"],
            "algorithm": row["algorithm"],
            "algorithm_name": algorithm_name[0] if algorithm_name else "",
            "evaluate": bool(row["evaluate"]),
            "commentsported": bool(row["commentsported"]),
        },
        "counts": {
            "matched_basic_blocks": matched_basic_blocks,
            "flow_graph_basic_blocks": {"primary": blocks1, "secondary": blocks2},
            "matched_instructions": len(pairs),
            "flow_graph_instructions": {"primary": flow1, "secondary": flow2},
            "changed_matched_instructions": changed_total,
            "primary_only_instructions": primary_only_total,
            "secondary_only_instructions": secondary_only_total,
        },
        "changed_matched_instructions": changed,
        "primary_only_instructions": primary_only,
        "secondary_only_instructions": secondary_only,
        "truncated": {
            "changed_matched_instructions": changed_truncated,
            "primary_only_instructions": primary_truncated,
            "secondary_only_instructions": secondary_truncated,
        },
        "text_available": text_available,
        "note": (
            "primary_only/secondary_only come from BinExport flow-graph "
            "sections; shared function chunks may appear on both sides. "
            "changed_matched_instructions are the strongest fix indicators."
        ),
        "error": dump_error,
    }
    return result


# ---------------------------------------------------------------------------
# Primary-only (new) functions
# ---------------------------------------------------------------------------


_FUNCTION_KINDS = {
    "n": "normal",
    "l": "library",
    "i": "import",
    "t": "thunk",
}


def new_functions(
    database: str | Path,
    *,
    primary_binexport: str | Path | None = None,
    secondary_binexport: str | Path | None = None,
    include_imports: bool = False,
    include_thunks: bool = False,
    include_library: bool = False,
    min_instructions: int = 0,
    name_contains: str = "",
    exclude_name_matches: bool = False,
    offset: int = 0,
    limit: int = 50,
) -> dict[str, Any]:
    """List functions present only in the primary/new BinExport.

    A .BinDiff database only stores matched pairs, so the unmatched functions
    must be recovered by enumerating both BinExport files and subtracting the
    matched addresses.  Import stubs, thunks, and library functions are hidden
    by default because they are rarely the new component code being sought.
    """
    min_instructions = max(0, int(min_instructions))
    offset = max(0, int(offset))
    limit = max(1, min(500, int(limit)))
    needle = name_contains.strip().casefold()

    sidecar = read_sidecar(database)
    primary_path = primary_binexport or sidecar.get("primary_binexport")
    secondary_path = secondary_binexport or sidecar.get("secondary_binexport")
    if not primary_path or not secondary_path:
        raise BindiffError(
            "both BinExport files are required: pass primary_binexport and "
            "secondary_binexport, or use a database created by bindiff_diff()"
        )

    primary_dump = _dump_for(primary_path)
    secondary_dump = _dump_for(secondary_path)
    primary_funcs = primary_dump.get("functions") or {}
    secondary_funcs = secondary_dump.get("functions") or {}
    primary_flags = primary_dump.get("function_flags") or {}
    primary_sections = primary_dump.get("sections") or {}
    secondary_names = {
        _name(name) for name in secondary_funcs.values() if name
    }

    conn = _connect(database)
    try:
        cur = conn.cursor()
        matched_primary = {
            row[0] for row in cur.execute("SELECT address1 FROM function")
        }
        matched_secondary = {
            row[0] for row in cur.execute("SELECT address2 FROM function")
        }
        matched_pairs = cur.execute("SELECT COUNT(*) FROM function").fetchone()[0]
    finally:
        conn.close()

    missing_primary = matched_primary - set(primary_funcs)
    missing_secondary = matched_secondary - set(secondary_funcs)
    if missing_primary or missing_secondary:
        raise BindiffError(
            "BinExport files do not match this BinDiff database: "
            f"{len(missing_primary)} matched primary and "
            f"{len(missing_secondary)} matched secondary addresses are missing "
            "from the dumps; pass the BinExports used to create the database"
        )

    unmatched_primary = sorted(set(primary_funcs) - matched_primary)
    unmatched_secondary = set(secondary_funcs) - matched_secondary

    filtered = {
        "imports": 0,
        "thunks": 0,
        "library": 0,
        "min_instructions": 0,
        "name_contains": 0,
        "name_matches": 0,
    }
    candidates: list[dict[str, Any]] = []
    for addr in unmatched_primary:
        flag = str(primary_flags.get(addr, "")).lower()
        kind = _FUNCTION_KINDS.get(flag, "unknown")
        section = primary_sections.get(addr) or {}
        name = _name(primary_funcs.get(addr) or "")
        item = {
            "addr": _hex(addr),
            "name": name,
            "kind": kind,
            "flag": flag,
            "instructions": len(section.get("instructions", [])),
            "basic_blocks": len(section.get("blocks", [])),
            "name_in_other_version": bool(name and name in secondary_names),
        }

        if kind == "import" and not include_imports:
            filtered["imports"] += 1
            continue
        if kind == "thunk" and not include_thunks:
            filtered["thunks"] += 1
            continue
        if kind == "library" and not include_library:
            filtered["library"] += 1
            continue
        if item["instructions"] < min_instructions:
            filtered["min_instructions"] += 1
            continue
        if needle and needle not in name.casefold():
            filtered["name_contains"] += 1
            continue
        if exclude_name_matches and item["name_in_other_version"]:
            filtered["name_matches"] += 1
            continue
        candidates.append(item)

    total = len(candidates)
    functions = candidates[offset : offset + limit]
    return {
        "database": _asan_path(Path(database)),
        "primary": {
            "binexport": _asan_path(Path(primary_path)),
            "source": sidecar.get("primary_source"),
        },
        "secondary": {
            "binexport": _asan_path(Path(secondary_path)),
            "source": sidecar.get("secondary_source"),
        },
        "summary": {
            "primary_functions": len(primary_funcs),
            "secondary_functions": len(secondary_funcs),
            "matched_pairs": matched_pairs,
            "unmatched": {
                "primary": len(unmatched_primary),
                "secondary": len(unmatched_secondary),
            },
            "selected_side": "primary",
            "filtered": filtered,
        },
        "functions": functions,
        "total": total,
        "offset": offset,
        "limit": limit,
        "note": (
            "The .BinDiff database stores matched pairs only; new functions "
            "are primary BinExport functions absent from every matched pair. "
            "Imports, thunks, and library functions are hidden by default. "
            "name_in_other_version marks a possible move/rename rather than "
            "new code."
        ),
        "error": None,
    }
