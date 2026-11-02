"""Binary survey tool -- complete triage in one call.

Large-database performance
--------------------------
``survey_binary`` must stay useful on multi-hundred-MB databases while never
monopolizing IDA's main thread for minutes.  The original implementation did
several unbounded things:

* rebuilt IDA's string list via ``idautils.Strings()`` (16.7s on a 60MB input),
* materialized every xref for 10k functions,
* walked every instruction of 10k functions for the call-graph estimate,
* read and hashed the entire input file in Python.

This version keeps the same result shape and triage value, but:

* reads IDA's already-built string list directly (0.2s for 37k strings),
* uses IDA's stored input-file MD5/SHA256,
* samples functions evenly for xref ranking and call-graph estimates,
* caps per-function work and returns a ``_note`` when results are sampled,
* enforces a cooperative time budget (standard 8s / minimal 3s by default,
  override with IDA_MCP_SURVEY_BUDGET_SEC / IDA_MCP_SURVEY_MINIMAL_BUDGET_SEC)
  and returns partial results instead of blocking.
"""

from __future__ import annotations

import hashlib
import os
import re
import time
from itertools import islice
from typing import Annotated, TypedDict

from .rpc import tool
from .sync import idasync, tool_timeout
from . import compat
from .api_core import _get_strings_cache
from .utils import get_image_size


class SurveyMetadata(TypedDict):
    path: str
    module: str
    arch: str
    base_address: str
    image_size: str
    md5: str
    sha256: str


class SurveySegmentInfo(TypedDict):
    name: str
    start: str
    end: str
    size: str
    permissions: str


class SurveyEntrypoint(TypedDict):
    addr: str
    name: str
    ordinal: int


class SurveyStatistics(TypedDict):
    total_functions: int
    named_functions: int
    library_functions: int
    unnamed_functions: int
    total_strings: int
    total_segments: int


class SurveyInterestingString(TypedDict):
    addr: str
    string: str
    xref_count: int


class SurveyInterestingFunction(TypedDict):
    addr: str
    name: str
    size: int
    xref_count: int
    callee_count: int
    type: str


class SurveyImportEntry(TypedDict):
    addr: str
    name: str
    module: str


class SurveyImportsByCategory(TypedDict):
    crypto: list[SurveyImportEntry]
    network: list[SurveyImportEntry]
    file_io: list[SurveyImportEntry]
    process: list[SurveyImportEntry]
    registry: list[SurveyImportEntry]
    other: list[SurveyImportEntry]


class SurveyCallGraphSummary(TypedDict):
    total_edges: int
    max_depth_estimate: None
    root_functions: list[str]
    leaf_functions_count: int


class SurveyBinaryResult(TypedDict, total=False):
    metadata: SurveyMetadata
    statistics: SurveyStatistics
    segments: list[SurveySegmentInfo]
    entrypoints: list[SurveyEntrypoint]
    interesting_strings: list[SurveyInterestingString]
    interesting_functions: list[SurveyInterestingFunction]
    imports_by_category: SurveyImportsByCategory
    call_graph_summary: SurveyCallGraphSummary
    _note: str


# ---------------------------------------------------------------------------
# Performance / sampling limits
# ---------------------------------------------------------------------------

# Function counts below this are processed exactly; above it statistics are
# estimated from an evenly spaced sample.
_STATS_EXACT_LIMIT = 200_000
_STATS_SAMPLE = 20_000

# Xref ranking sample sizes.  Small binaries are processed completely.
_INTERESTING_ALL_LIMIT = 10_000
_INTERESTING_SAMPLE = 5_000
_INTERESTING_LARGE_SAMPLE = 2_000

# Call-graph summary is inherently approximate (max_depth_estimate is None),
# so a smaller sample is sufficient.  Under auto-analysis contention even a
# few hundred functions can consume several seconds.
_CALLGRAPH_SAMPLE = 400

# Per-function caps: prevent one pathological function from dominating.
_MAX_XREFS_PER_FUNC = 20_000
_MAX_INSTRUCTIONS_PER_FUNC = 5_000
_MAX_INSTRUCTIONS_PER_CALLGRAPH_FUNC = 500

# String limits.
_MAX_STRING_ITER = 5_000
_MAX_XREFS_PER_STRING = 200

# Import output is an overview, not a complete listing.
_MAX_IMPORTS_PER_CATEGORY = 200

# "Large" heuristics: use sampling even if the function count is moderate
# (a 60MB DLL with 61k functions still benefits from shorter samples).
_LARGE_FUNC_COUNT = 20_000
_LARGE_INPUT_BYTES = 20 * 1024 * 1024

# Cooperative budgets (seconds).  The hard @tool_timeout below is a safety net.
_SURVEY_BUDGET_STANDARD = float(os.getenv("IDA_MCP_SURVEY_BUDGET_SEC", "6"))
_SURVEY_BUDGET_MINIMAL = float(os.getenv("IDA_MCP_SURVEY_MINIMAL_BUDGET_SEC", "3"))


# Import category rules: keyword -> category name.
# Order matters: first match wins.
_IMPORT_CATEGORIES: list[tuple[str, re.Pattern[str]]] = [
    ("crypto", re.compile(r"crypt|aes|sha[^r]|md5|hash|rsa|\bssl\b|\btls\b|\bcert", re.IGNORECASE)),
    ("network", re.compile(r"socket|connect|send|recv|http|url|internet|ws2|winsock", re.IGNORECASE)),
    ("process", re.compile(r"process|thread|terminate|execute|shell|pipe|virtual", re.IGNORECASE)),
    ("registry", re.compile(r"reg|registry|hkey", re.IGNORECASE)),
    ("file_io", re.compile(r"file|path|directory|fopen|fclose|fread|fwrite|readfile|writefile|deletefile|createfile", re.IGNORECASE)),
]


class _SurveyBudget:
    """Cooperative deadline shared by all survey stages."""

    def __init__(self, seconds: float):
        self.deadline = time.monotonic() + max(0.25, float(seconds))
        self.notes: list[str] = []
        self.expired = False

    def check(self) -> bool:
        if time.monotonic() >= self.deadline:
            self.expired = True
            return True
        return False

    def note(self, message: str) -> None:
        if message and message not in self.notes:
            self.notes.append(message)


def _classify_import(name: str) -> str:
    for category, pattern in _IMPORT_CATEGORIES:
        if pattern.search(name):
            return category
    return "other"


def _even_sample(items, limit: int):
    """Return (sample, sampled) selecting at most *limit* evenly spaced items."""
    count = len(items)
    if limit <= 0 or count <= limit:
        return list(items), False
    step = count / float(limit)
    return [items[int(i * step)] for i in range(limit)], True


def _sample_function_eas(total: int, limit: int) -> tuple[list[int], bool]:
    """Return up to *limit* evenly spaced function entry addresses.

    Uses ida_funcs.getn_func so sampling does not require iterating the whole
    function list.  For small databases the complete list is returned so
    normal-size binaries keep their exact previous behavior.
    """
    import ida_funcs
    import idautils

    if total <= 0:
        return [], False
    if total <= limit:
        return list(idautils.Functions()), False

    step = total / float(limit)
    eas: list[int] = []
    seen: set[int] = set()
    for index in range(limit):
        position = int(index * step)
        if position >= total:
            break
        func = ida_funcs.getn_func(position)
        if func is None:
            continue
        ea = func.start_ea
        if ea not in seen:
            seen.add(ea)
            eas.append(ea)
    return eas, True


def _interesting_function_limit(total: int) -> int:
    if total <= _INTERESTING_ALL_LIMIT:
        return total
    if total <= 100_000:
        return _INTERESTING_SAMPLE
    return _INTERESTING_LARGE_SAMPLE


def _callgraph_sample_limit(total: int) -> int:
    """Keep call-graph summaries complete for normal binaries, sample huge ones."""
    if total <= 2_000:
        return total
    if total <= 20_000:
        return 1_000
    return _CALLGRAPH_SAMPLE


def _get_strings_for_survey(large: bool, budget: _SurveyBudget) -> list[tuple[int, str]]:
    """Fetch strings without triggering an expensive rebuild on huge files."""
    try:
        strings = _get_strings_cache(build_if_needed=not large)
    except Exception as e:
        budget.note(f"string list unavailable: {e}")
        return []

    if not strings and large:
        try:
            import ida_strlist

            if ida_strlist.get_strlist_qty() <= 0:
                budget.note(
                    "IDA string list is not built; string scan skipped for this "
                    "large binary (run server_warmup to build it if needed)"
                )
        except Exception:
            pass
    return strings


def _build_metadata() -> dict:
    import idaapi
    import idc
    import ida_nalt

    path = idc.get_idb_path()
    module = ida_nalt.get_root_filename()
    base = hex(idaapi.get_imagebase())
    size = hex(get_image_size())
    is_64 = compat.inf_is_64bit()

    input_path = ida_nalt.get_input_file_path()

    md5 = ""
    sha256 = ""

    # IDA already computed the input-file hashes while loading the database.
    # Avoid reading + hashing a potentially huge input file in Python.
    try:
        value = ida_nalt.retrieve_input_file_md5()
        if isinstance(value, (bytes, bytearray)):
            md5 = bytes(value).hex()
        elif isinstance(value, str):
            md5 = value
    except Exception:
        pass
    try:
        value = ida_nalt.retrieve_input_file_sha256()
        if isinstance(value, (bytes, bytearray)):
            sha256 = bytes(value).hex()
        elif isinstance(value, str):
            sha256 = value
    except Exception:
        pass

    if not md5 or not sha256:
        # Fallback for older IDA / unusual inputs.  Only read small files;
        # blocking on a multi-hundred-MB file would defeat the purpose.
        try:
            file_size = os.path.getsize(input_path)
        except OSError:
            file_size = 0
        if 0 < file_size <= 64 * 1024 * 1024:
            try:
                with open(input_path, "rb") as f:
                    data = f.read()
                if not md5:
                    md5 = hashlib.md5(data).hexdigest()
                if not sha256:
                    sha256 = hashlib.sha256(data).hexdigest()
            except Exception:
                pass

    return {
        "path": path,
        "module": module,
        "arch": "64" if is_64 else "32",
        "base_address": base,
        "image_size": size,
        "md5": md5 or "unavailable",
        "sha256": sha256 or "unavailable",
    }


def _build_segments() -> list[dict]:
    import idaapi
    import idautils
    import ida_segment

    segments = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if not seg:
            continue
        perms = []
        if seg.perm & idaapi.SEGPERM_READ:
            perms.append("r")
        if seg.perm & idaapi.SEGPERM_WRITE:
            perms.append("w")
        if seg.perm & idaapi.SEGPERM_EXEC:
            perms.append("x")
        segments.append({
            "name": ida_segment.get_segm_name(seg),
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": hex(seg.size()),
            "permissions": "".join(perms) or "---",
        })
    return segments


def _build_entrypoints() -> list[dict]:
    entrypoints = []
    entry_count = compat.get_entry_qty()
    for i in range(entry_count):
        ordinal = compat.get_entry_ordinal(i)
        ea = compat.get_entry(ordinal)
        name = compat.get_entry_name(ordinal)
        entrypoints.append({"addr": hex(ea), "name": name, "ordinal": ordinal})
    return entrypoints


def _build_statistics(
    total_functions: int,
    string_count: int,
    segment_count: int,
    budget: _SurveyBudget,
) -> dict:
    import idaapi
    import ida_funcs
    import idautils
    import idc

    if total_functions <= 0:
        total_functions = ida_funcs.get_func_qty()

    if total_functions <= _STATS_EXACT_LIMIT:
        func_eas = list(idautils.Functions())
    else:
        func_eas, _sampled = _sample_function_eas(total_functions, _STATS_SAMPLE)

    named = 0
    library = 0
    unnamed = 0
    processed = 0

    for i, ea in enumerate(func_eas):
        if i % 2048 == 0 and budget.check():
            budget.note(
                f"function statistics interrupted after {processed}/{total_functions}"
            )
            break

        name = idc.get_name(ea, 0) or ""
        func = idaapi.get_func(ea)
        flags = func.flags if func else 0

        if name.startswith("sub_"):
            unnamed += 1
        elif flags & idaapi.FUNC_LIB:
            library += 1
        else:
            named += 1
        processed += 1

    if total_functions > 0 and processed == 0:
        budget.note("function statistics skipped due to time budget")
    elif processed and processed < total_functions:
        # Scale the sampled counts to the exact total.  Adjust rounding so the
        # three buckets still add up to total_functions.
        scale = total_functions / float(processed)
        named = int(round(named * scale))
        library = int(round(library * scale))
        unnamed = int(round(unnamed * scale))
        diff = total_functions - (named + library + unnamed)
        if diff:
            named = max(0, named + diff)
        budget.note(
            f"function name/library counts estimated from {processed}/{total_functions} functions"
        )

    return {
        "total_functions": total_functions,
        "named_functions": named,
        "library_functions": library,
        "unnamed_functions": unnamed,
        "total_strings": string_count,
        "total_segments": segment_count,
    }


def _build_interesting_strings(
    strings: list[tuple[int, str]],
    budget: _SurveyBudget,
) -> list[dict]:
    import idautils

    if not strings:
        return []

    selected, sampled = _even_sample(strings, _MAX_STRING_ITER)
    if sampled:
        budget.note(
            f"string xref ranking sampled {len(selected)}/{len(strings)} strings"
        )

    scored: list[tuple[int, int, str]] = []
    for i, (ea, s) in enumerate(selected):
        if i % 128 == 0 and budget.check():
            budget.note(
                f"string xref ranking interrupted after {i}/{len(selected)} strings"
            )
            break
        # Count xrefs without materializing an unbounded list.
        count = sum(1 for _ in islice(idautils.XrefsTo(ea, 0), _MAX_XREFS_PER_STRING))
        if count == 0:
            continue
        scored.append((count, ea, s))

    scored.sort(key=lambda t: t[0], reverse=True)
    return [
        {"addr": hex(ea), "string": s, "xref_count": xref_count}
        for xref_count, ea, s in scored[:15]
    ]


def _is_library_func(ea: int, name: str, flags: int) -> bool:
    """A function is 'library' if it has a FLIRT signature."""
    import idaapi

    return bool(flags & idaapi.FUNC_LIB)


def _classify_func(ea: int, func, name: str, callee_count: int) -> str:
    """Classify function as thunk/wrapper/leaf/dispatcher/complex."""
    import idaapi

    flags = func.flags
    size = func.end_ea - func.start_ea
    if flags & idaapi.FUNC_THUNK or size <= 8:
        return "thunk"
    if callee_count == 1 and size < 100:
        return "wrapper"
    if callee_count == 0:
        return "leaf"
    if callee_count > 10:
        return "dispatcher"
    return "complex"


def _build_interesting_functions(
    func_eas: list[int],
    budget: _SurveyBudget,
) -> list[dict]:
    import idaapi
    import idautils
    import idc

    candidates: list[tuple[int, int, str, int]] = []

    for i, ea in enumerate(func_eas):
        if i % 128 == 0 and budget.check():
            budget.note(
                f"function xref ranking interrupted after {i}/{len(func_eas)} functions"
            )
            break

        func = idaapi.get_func(ea)
        if not func:
            continue
        name = idc.get_name(ea, 0) or ""

        if _is_library_func(ea, name, func.flags):
            continue

        # Count xrefs without materializing every xref list.
        xref_count = sum(
            1 for _ in islice(idautils.XrefsTo(ea, 0), _MAX_XREFS_PER_FUNC)
        )
        candidates.append((xref_count, ea, name, func.size()))

    candidates.sort(key=lambda t: t[0], reverse=True)
    top = candidates[:15]

    result = []
    for xref_count, ea, name, size in top:
        func = idaapi.get_func(ea)
        if not func:
            continue
        callee_count = 0
        instructions = 0
        truncated = False
        for item_ea in idautils.FuncItems(ea):
            instructions += 1
            if instructions > _MAX_INSTRUCTIONS_PER_FUNC:
                truncated = True
                break
            if instructions % 256 == 0 and budget.check():
                truncated = True
                break
            for xref in idautils.XrefsFrom(item_ea, 0):
                if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                    callee_count += 1
        if truncated:
            budget.note(
                "callee counts truncated/interrupted for very large functions"
            )

        classification = _classify_func(ea, func, name, callee_count)
        result.append({
            "addr": hex(ea),
            "name": name,
            "size": size,
            "xref_count": xref_count,
            "callee_count": callee_count,
            "type": classification,
        })
    return result


def _build_imports_by_category(budget: _SurveyBudget) -> dict[str, list[dict]]:
    import ida_nalt

    categories: dict[str, list[dict]] = {
        "crypto": [],
        "network": [],
        "file_io": [],
        "process": [],
        "registry": [],
        "other": [],
    }
    truncated = False

    nimps = ida_nalt.get_import_module_qty()
    for i in range(nimps):
        if budget.check():
            budget.note("imports_by_category interrupted by time budget")
            break

        module_name = ida_nalt.get_import_module_name(i) or "<unnamed>"

        def imp_cb(ea: int, symbol_name: str | None, ordinal: int) -> bool:
            nonlocal truncated
            name = symbol_name if symbol_name else f"#{ordinal}"
            cat = _classify_import(name)
            bucket = categories[cat]
            if len(bucket) < _MAX_IMPORTS_PER_CATEGORY:
                bucket.append({
                    "addr": hex(ea),
                    "name": name,
                    "module": module_name,
                })
            else:
                truncated = True
            return True

        ida_nalt.enum_import_names(i, imp_cb)

    if truncated:
        budget.note(
            f"imports_by_category capped at {_MAX_IMPORTS_PER_CATEGORY} entries per category"
        )
    return categories


def _build_call_graph_summary(
    func_eas: list[int],
    budget: _SurveyBudget,
) -> dict:
    import idaapi
    import idautils

    total_edges = 0
    root_functions: list[str] = []
    leaf_count = 0
    truncated = False

    for i, ea in enumerate(func_eas):
        if i % 64 == 0 and budget.check():
            budget.note(
                f"call graph summary interrupted after {i}/{len(func_eas)} functions"
            )
            break

        has_callers = False
        has_callees = False

        # Incoming call xrefs.  We only need existence, so stop at the first;
        # cap the scan so data-heavy functions cannot stall the sample.
        for xref in islice(idautils.XrefsTo(ea, 0), _MAX_XREFS_PER_FUNC):
            if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                has_callers = True
                break

        # Outgoing call xrefs, capped per function.
        instructions = 0
        for item_ea in idautils.FuncItems(ea):
            instructions += 1
            if instructions > _MAX_INSTRUCTIONS_PER_CALLGRAPH_FUNC:
                truncated = True
                break
            if instructions % 512 == 0 and budget.check():
                truncated = True
                budget.note("call graph summary interrupted by time budget")
                break
            for xref in idautils.XrefsFrom(item_ea, 0):
                if xref.type in (idaapi.fl_CF, idaapi.fl_CN):
                    total_edges += 1
                    has_callees = True

        if not has_callers:
            root_functions.append(idaapi.get_name(ea) or hex(ea))
        if not has_callees:
            leaf_count += 1

    if truncated:
        budget.note(
            "call graph summary capped at "
            f"{_MAX_INSTRUCTIONS_PER_CALLGRAPH_FUNC} instructions per function"
        )

    return {
        "total_edges": total_edges,
        "max_depth_estimate": None,
        "root_functions": root_functions[:100],
        "leaf_functions_count": leaf_count,
    }


@tool
@idasync
@tool_timeout(30.0)
def survey_binary(
    detail_level: Annotated[str, "Detail level: 'standard' or 'minimal'"] = "standard",
) -> SurveyBinaryResult:
    """Get a compact overview of the binary in one call. Returns file metadata,
    segment layout, entry points, statistics, top 15 strings and functions ranked
    by xref count (functions include classification: thunk/wrapper/leaf/dispatcher/
    complex), imports by category, and call graph summary. Use this as your FIRST
    tool call when starting analysis. Do not call list_funcs, imports, or find_regex
    separately for triage — this returns all of that. Use detail_level='minimal'
    for binaries with >10k functions.

    Large databases are sampled and time-bounded (standard 8s / minimal 3s by
    default); the _note field explains what was sampled or skipped."""
    import ida_auto
    import ida_funcs
    import ida_nalt

    minimal = detail_level == "minimal"
    budget = _SurveyBudget(
        _SURVEY_BUDGET_MINIMAL if minimal else _SURVEY_BUDGET_STANDARD
    )

    total_functions = ida_funcs.get_func_qty()
    try:
        input_size = ida_nalt.retrieve_input_file_size()
    except Exception:
        input_size = 0
    large = (
        total_functions > _LARGE_FUNC_COUNT
        or input_size > _LARGE_INPUT_BYTES
    )

    try:
        if not ida_auto.auto_is_ok():
            budget.note(
                "auto-analysis queue is not empty; results may be incomplete "
                "until analysis finishes"
            )
    except Exception:
        pass

    strings = _get_strings_for_survey(large, budget)
    segments = _build_segments()

    result: dict = {
        "metadata": _build_metadata(),
        "statistics": _build_statistics(
            total_functions, len(strings), len(segments), budget
        ),
        "segments": segments,
        "entrypoints": _build_entrypoints(),
    }

    if not minimal:
        result["interesting_strings"] = _build_interesting_strings(strings, budget)

        func_limit = _interesting_function_limit(total_functions)
        func_eas, sampled = _sample_function_eas(total_functions, func_limit)
        if sampled:
            budget.note(
                f"function xref ranking sampled {len(func_eas)}/{total_functions} functions"
            )
        result["interesting_functions"] = _build_interesting_functions(
            func_eas, budget
        )

        result["imports_by_category"] = _build_imports_by_category(budget)

        cg_eas, cg_sampled = _sample_function_eas(
            total_functions, _callgraph_sample_limit(total_functions)
        )
        if cg_sampled:
            budget.note(
                f"call graph summary sampled {len(cg_eas)}/{total_functions} functions"
            )
        result["call_graph_summary"] = _build_call_graph_summary(cg_eas, budget)

    if budget.notes:
        result["_note"] = "; ".join(budget.notes)
    elif large:
        result["_note"] = (
            f"Large binary ({total_functions} functions); results may be sampled "
            "for responsiveness."
        )

    return result
