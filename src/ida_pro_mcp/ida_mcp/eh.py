"""x86_64 exception-handling extraction and rendering helpers.

IDA's ``eh_parse`` plugin already turns the PE ``.pdata``/``.xdata`` tables
into ``ida_tryblks`` metadata.  We deliberately reuse that data instead of
re-implementing the unwind parser:

* user ``__try`` blocks and their guarded ranges;
* ``__except`` filter routines and handler blocks;
* ``__finally`` out-of-line handler routines;
* the function-level ``__C_specific_handler`` table.

The helpers below turn that metadata plus the function CFG into a structured
flow (nodes/edges), short human-readable text, and annotations for the
disassembly/decompiler output.  No IDB bytes are modified.
"""

from __future__ import annotations

import re
from typing import Any

import ida_ida
import idaapi
import idc

try:  # IDA 9.x; older builds simply expose no exception metadata.
    import ida_tryblks
except ImportError:  # pragma: no cover - depends on the IDA build
    ida_tryblks = None  # type: ignore[assignment]

from .utils import demangle_ea_name

BADADDR = idaapi.BADADDR
_ADDR_RE = re.compile(r"/\*0x([0-9a-fA-F]+)\*/")


def _arch_label() -> str:
    try:
        return "x64" if ida_ida.inf_is_64bit() else "x86"
    except Exception:
        return "x64" if idaapi.get_inf_structure().is_64bit() else "x86"


def _hex(ea: int | None) -> str | None:
    if ea is None or ea == BADADDR:
        return None
    return hex(ea)


def _name_at(ea: int) -> str:
    if ea == BADADDR:
        return ""
    try:
        return demangle_ea_name(ea) or idaapi.get_name(ea) or ""
    except Exception:
        return ""


def _chunk_bounds(ea: int) -> tuple[int, int]:
    """Return the function-chunk (entry or tail) bounds containing *ea*."""
    try:
        start = idc.get_fchunk_attr(ea, idc.FUNCATTR_START)
        end = idc.get_fchunk_attr(ea, idc.FUNCATTR_END)
    except Exception:
        start = end = BADADDR
    if start == BADADDR:
        start = ea
    if end == BADADDR:
        func = idaapi.get_func(ea)
        end = func.end_ea if func else BADADDR
    return start, end


def _range_end(r: Any) -> int:
    end = r.end_ea
    if end == BADADDR:
        _, end = _chunk_bounds(r.start_ea)
    return end


def _ranges_dict(ranges: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in ranges:
        end = _range_end(r)
        out.append(
            {
                "start": hex(r.start_ea),
                "end": _hex(end),
                "size": (end - r.start_ea) if end != BADADDR else None,
            }
        )
    return out


def _cfg_blocks(func: Any) -> list[tuple[int, int]]:
    try:
        return [
            (block.start_ea, block.end_ea)
            for block in idaapi.FlowChart(func)
            if block.end_ea > block.start_ea
        ]
    except Exception:
        return []


def _block_at(blocks: list[tuple[int, int]], ea: int) -> tuple[int, int] | None:
    for start, end in blocks:
        if start <= ea < end:
            return start, end
    return None


def _filter_starts(blocks: list[Any]) -> list[int]:
    starts: set[int] = set()
    for block in blocks:
        if not _is_seh(block):
            continue
        try:
            seh = block.seh()
            for r in seh.filter:
                starts.add(r.start_ea)
        except Exception:
            continue
    return sorted(starts)


def _is_seh(block: Any) -> bool:
    try:
        return bool(block.is_seh())
    except Exception:
        return False


def _is_cpp(block: Any) -> bool:
    """Reserved for future C++ EH rendering; MSVC SEH is the current target."""
    try:
        return bool(block.is_cpp())
    except Exception:
        return False


def _function_ref(start: int, starts: list[int]) -> dict[str, Any] | None:
    """Describe the out-of-line filter/finally routine beginning at *start*."""
    if start == BADADDR:
        return None
    _, chunk_end = _chunk_bounds(start)
    if chunk_end == BADADDR:
        return None
    later = [s for s in starts if start < s < chunk_end]
    end = min(later) if later else chunk_end
    if end <= start:
        return None
    return {
        "addr": hex(start),
        "end": hex(end),
        "size": end - start,
        "name": _name_at(start) or None,
    }


def _seh_code_text(code: int) -> str:
    if code == BADADDR:
        return "EXCEPTION_CONTINUE_EXECUTION"
    if code == 0:
        return "EXCEPTION_CONTINUE_SEARCH"
    if code == 1:
        return "EXCEPTION_EXECUTE_HANDLER"
    return hex(code)


def _classify_kind(
    filter_name: str | None, seh_code: int, has_filter: bool
) -> str:
    """Classify an x64 SEH clause as ``except`` or ``finally``.

    MSVC names the out-of-line routines with ``$filt$N`` and ``$fin$N``.
    The fallback uses the filter/seh_code semantics when symbols are renamed
    or stripped.
    """
    name = (filter_name or "").lower()
    if "$fin$" in name or "fin$" in name:
        return "finally"
    if "$filt$" in name or "filt$" in name:
        return "except"
    if seh_code == 1:
        return "except"
    if has_filter:
        return "except"
    if seh_code == BADADDR:
        return "except"
    return "unknown"


def _kind_label(kind: str) -> str:
    return {
        "except": "__except",
        "finally": "__finally",
        "cpp": "C++ try",
        "unknown": "EH clause",
    }.get(kind, "EH clause")


def _display_name(name: str | None, fallback: str) -> str:
    if not name:
        return fallback
    if name.startswith(("$LN", "loc_", "sub_", "nullsub_", "unknown_libname_")):
        return fallback
    return name


def _is_function_level(block: Any, func: Any) -> bool:
    """True for the level-0 ``__C_specific_handler`` function table entry."""
    if not _is_seh(block) or getattr(block, "level", 0) != 0:
        return False
    try:
        seh = block.seh()
    except Exception:
        return False
    if len(seh.filter) != 0:
        return False
    ranges = list(block)
    if not ranges:
        return False
    try:
        start = min(r.start_ea for r in ranges)
        end = max(_range_end(r) for r in ranges)
    except Exception:
        return False
    if end == BADADDR:
        return False
    # A real user block can cover the whole function; require a code
    # address as the level-0 handler to avoid misclassifying it.
    return (
        start <= func.start_ea
        and end >= func.end_ea
        and seh.seh_code not in (0, 1, BADADDR)
    )


def _contains(outer: list[tuple[int, int]], inner: list[tuple[int, int]]) -> bool:
    def covered(inner_range: tuple[int, int]) -> bool:
        start, end = inner_range
        return any(
            outer_start <= start and end <= outer_end
            for outer_start, outer_end in outer
        )

    return all(covered(r) for r in inner)


def _parent_id(items: list[dict[str, Any]], index: int) -> int | None:
    current = items[index]
    current_level = current["_level"]
    current_ranges = current["_ranges"]
    candidates: list[tuple[int, int]] = []
    for j, other in enumerate(items):
        if j == index or other["_level"] >= current_level:
            continue
        if _contains(other["_ranges"], current_ranges):
            candidates.append((other["_level"], j))
    if not candidates:
        return None
    _, parent_index = max(candidates)
    return items[parent_index]["id"]


def _summary_lines(info: dict[str, Any], limit: int = 16) -> list[str]:
    """Compact ``// EH:`` summary used at the top of pseudocode."""
    lines: list[str] = []
    fh = info.get("function_handler")
    if fh:
        lines.append(
            f"  // EH: function table {fh.get('name') or '?'} @ {fh['addr']}"
        )
    for block in info.get("try_blocks", []):
        indent = "  " * max(0, block["level"] - 1)
        line = (
            f"  // EH: {indent}#{block['id']} level={block['level']} "
            f"{_kind_label(block['kind'])} try {block['try_start']}-{block['try_end']}"
        )
        filt = block.get("filter")
        handler = block.get("handler")
        if filt:
            line += f"; filter {_display_name(filt.get('name'), 'filter')} @ {filt['addr']}"
        if handler:
            line += (
                f"; handler {_display_name(handler.get('name'), 'entry block')}"
                f" @ {handler['addr']}"
            )
            if block.get("handler_shared"):
                line += " (shared/empty)"
        lines.append(line)
    if len(lines) > limit:
        kept = lines[:limit]
        kept.append(f"  // EH: ... {len(lines) - limit} more")
        return kept
    return lines


def _format_text(info: dict[str, Any]) -> str:
    """Human-readable SEH flow summary."""
    func = info.get("function") or {}
    lines = [
        f"{func.get('name') or '?'} @ {func.get('addr')} - {info.get('mechanism') or 'no exception metadata'}"
    ]
    fh = info.get("function_handler")
    if fh:
        lines.append(
            f"  function table: {fh.get('name') or '?'} @ {fh['addr']}"
        )
    blocks = info.get("try_blocks", [])
    if not blocks:
        lines.append("  no user __try blocks")
        return "\n".join(lines)

    for block in blocks:
        indent = "  " * max(0, block["level"] - 1)
        lines.append(
            f"  {indent}#{block['id']} level={block['level']} "
            f"{_kind_label(block['kind'])}"
        )
        lines.append(f"  {indent}  try: {block['try_start']}-{block['try_end']}")
        filt = block.get("filter")
        handler = block.get("handler")
        if filt:
            lines.append(
                f"  {indent}  filter: {_display_name(filt.get('name'), 'filter')}"
                f" @ {filt['addr']}-{filt['end']}"
            )
        if handler:
            extra = " (shared/empty entry)" if block.get("handler_shared") else ""
            lines.append(
                f"  {indent}  handler: {_display_name(handler.get('name'), 'entry block')}"
                f" @ {handler['addr']}-{handler['end']}{extra}"
            )
        if block.get("normal_continuation"):
            lines.append(
                f"  {indent}  normal continuation: {block['normal_continuation']}"
            )
        if block.get("parent_id") is not None:
            lines.append(f"  {indent}  parent: #{block['parent_id']}")

        if block["kind"] == "except" and filt:
            flow = (
                f"try --exception--> filter"
                f" --EXCEPTION_EXECUTE_HANDLER--> handler"
            )
            if block.get("normal_continuation"):
                flow += "; filter --EXCEPTION_CONTINUE_SEARCH--> continuation"
        elif block["kind"] == "finally" and handler:
            flow = "try --unwind--> __finally handler"
            if block.get("normal_continuation"):
                flow += "; try --normal--> continuation"
        else:
            flow = "try --exception--> handler"
        lines.append(f"  {indent}  flow: {flow}")
    return "\n".join(lines)


def _build_graph(info: dict[str, Any]) -> tuple[list[dict], list[dict]]:
    nodes: list[dict] = []
    edges: list[dict] = []
    for block in info.get("try_blocks", []):
        bid = block["id"]
        try_id = f"try:{bid}"
        cont_id = f"cont:{bid}"
        nodes.append(
            {
                "id": try_id,
                "type": "try",
                "label": f"__try #{bid}",
                "block_id": bid,
                "level": block["level"],
                "kind": block["kind"],
                "ranges": block.get("try_ranges", []),
            }
        )
        if block.get("normal_continuation"):
            nodes.append(
                {
                    "id": cont_id,
                    "type": "continuation",
                    "label": f"continuation #{bid}",
                    "addr": block["normal_continuation"],
                }
            )
            edges.append(
                {
                    "from": try_id,
                    "to": cont_id,
                    "type": "eh.normal",
                    "label": "normal",
                }
            )
        filt = block.get("filter")
        handler = block.get("handler")
        if filt:
            filter_id = f"filter:{bid}"
            nodes.append(
                {
                    "id": filter_id,
                    "type": "filter",
                    "label": f"filter #{bid}",
                    "addr": filt["addr"],
                    "end": filt.get("end"),
                    "name": filt.get("name"),
                }
            )
            edges.append(
                {
                    "from": try_id,
                    "to": filter_id,
                    "type": "eh.exception",
                    "label": "exception",
                }
            )
            if handler:
                handler_id = f"handler:{bid}"
                nodes.append(
                    {
                        "id": handler_id,
                        "type": "handler",
                        "label": f"handler #{bid}",
                        "addr": handler["addr"],
                        "end": handler.get("end"),
                        "name": handler.get("name"),
                        "shared": block.get("handler_shared", False),
                    }
                )
                edges.append(
                    {
                        "from": filter_id,
                        "to": handler_id,
                        "type": "eh.handler",
                        "label": "EXCEPTION_EXECUTE_HANDLER (filter)",
                    }
                )
                if block.get("normal_continuation"):
                    edges.append(
                        {
                            "from": filter_id,
                            "to": cont_id,
                            "type": "eh.search",
                            "label": "EXCEPTION_CONTINUE_SEARCH",
                        }
                    )
        elif handler:
            handler_id = f"handler:{bid}"
            nodes.append(
                {
                    "id": handler_id,
                    "type": "handler",
                    "label": f"handler #{bid}",
                    "addr": handler["addr"],
                    "end": handler.get("end"),
                    "name": handler.get("name"),
                    "shared": block.get("handler_shared", False),
                }
            )
            edges.append(
                {
                    "from": try_id,
                    "to": handler_id,
                    "type": "eh.finally" if block["kind"] == "finally" else "eh.handler",
                    "label": "unwind" if block["kind"] == "finally" else "exception",
                }
            )
        if block.get("parent_id") is not None:
            edges.append(
                {
                    "from": f"try:{block['parent_id']}",
                    "to": try_id,
                    "type": "eh.parent",
                    "label": "nested",
                }
            )
    return nodes, edges


def get_eh_info(ea: int) -> dict[str, Any]:
    """Return structured exception metadata and annotations for a function.

    ``ea`` may be any address in the function (including a handler tail).
    The returned ``annotations`` mapping is keyed by integer EA for direct use
    by disassembly/decompiler rendering; it is intentionally separate from the
    JSON-facing ``try_blocks``/``nodes``/``edges`` fields.
    """
    func = idaapi.get_func(ea)
    if func is None:
        return {
            "function": None,
            "arch": _arch_label(),
            "mechanism": None,
            "function_handler": None,
            "try_blocks": [],
            "nodes": [],
            "edges": [],
            "annotations": {},
            "text": "No function at address",
        }
    func = idaapi.get_func(func.start_ea) or func
    arch = _arch_label()
    mechanism = (
        "MSVC x64 SEH (__try/__except/__finally, IDA tryblks)"
        if arch == "x64"
        else "MSVC x86 SEH (__try/__except/__finally, IDA tryblks)"
    )

    raw_blocks: list[Any] = []
    if ida_tryblks is not None:
        try:
            tbv = idaapi.tryblks_t()
            ida_tryblks.get_tryblks(
                tbv, idaapi.range_t(func.start_ea, func.end_ea)
            )
            raw_blocks = list(tbv)
        except Exception:
            raw_blocks = []

    starts = _filter_starts(raw_blocks)
    cfg: list[tuple[int, int]] | None = None
    fh_dict: dict[str, Any] | None = None
    items: list[dict[str, Any]] = []

    for raw in raw_blocks:
        if not _is_seh(raw):
            continue
        try:
            seh = raw.seh()
        except Exception:
            continue
        ranges = list(raw)
        if not ranges:
            continue
        try:
            has_filter = len(seh.filter) != 0
        except Exception:
            has_filter = False
        # Some loaders emit a placeholder tryblk covering the function with
        # no filter and SEH_SEARCH as the code (e.g. plain ELF functions).
        if not has_filter and seh.seh_code in (0, BADADDR):
            continue
        if _is_function_level(raw, func):
            if fh_dict is None:
                handler_name = _name_at(seh.seh_code)
                fh_dict = {
                    "addr": hex(seh.seh_code),
                    "name": handler_name or None,
                    "seh_code": _seh_code_text(seh.seh_code),
                    "ranges": _ranges_dict(ranges),
                }
            continue

        filter_range = None
        try:
            filter_range = next(iter(seh.filter), None)
        except Exception:
            filter_range = None
        filter_ref = (
            _function_ref(filter_range.start_ea, starts)
            if filter_range is not None
            else None
        )
        kind = _classify_kind(
            (filter_ref or {}).get("name"),
            seh.seh_code,
            filter_range is not None,
        )
        try:
            try_end = max(_range_end(r) for r in ranges)
        except Exception:
            try_end = BADADDR

        handler_ref: dict[str, Any] | None = None
        if kind == "except" and try_end != BADADDR:
            if cfg is None:
                cfg = _cfg_blocks(func)
            block = _block_at(cfg, try_end)
            if block is not None:
                block_start, block_end = block
                handler_ref = {
                    "addr": hex(block_start),
                    "end": hex(block_end),
                    "size": block_end - block_start,
                    "name": _name_at(block_start) or None,
                    "entry_block": True,
                }
        elif kind == "finally":
            handler_ref = filter_ref

        item: dict[str, Any] = {
            "id": len(items) + 1,
            "level": raw.level,
            "kind": kind,
            "scope": "user",
            "try_ranges": _ranges_dict(ranges),
            "try_start": hex(ranges[0].start_ea),
            "try_end": _hex(try_end),
            "filter": filter_ref if kind != "finally" else None,
            "handler": handler_ref,
            "handler_shared": False,
            "seh_code": _seh_code_text(seh.seh_code),
            "normal_continuation": _hex(
                int(handler_ref["end"], 16)
                if handler_ref and kind == "except"
                else try_end
            ),
            "parent_id": None,
            "_ranges": [(r.start_ea, _range_end(r)) for r in ranges],
            "_level": raw.level,
            "_filter_addr": filter_range.start_ea if filter_range is not None else None,
            "_handler_addr": (
                int(handler_ref["addr"], 16) if handler_ref is not None else None
            ),
        }
        items.append(item)

    # Shared-handler detection: an empty __except body often has its entry at
    # the next EH boundary (e.g. the normal path of an enclosing __finally).
    all_boundaries: dict[int, set[int]] = {}
    for item in items:
        boundaries: set[int] = set()
        for start, end in item["_ranges"]:
            boundaries.add(start)
            boundaries.add(end)
        if item["_filter_addr"] is not None:
            boundaries.add(item["_filter_addr"])
        all_boundaries[item["id"]] = boundaries
    for item in items:
        addr = item["_handler_addr"]
        if addr is None or item["kind"] != "except":
            continue
        item["handler_shared"] = any(
            addr in boundaries
            for other_id, boundaries in all_boundaries.items()
            if other_id != item["id"]
        )

    for i, item in enumerate(items):
        item["parent_id"] = _parent_id(items, i)

    # Build address-keyed annotations for disasm/decompile rendering.
    annotations: dict[int, list[dict[str, Any]]] = {}
    func_name = _name_at(func.start_ea) or hex(func.start_ea)

    def add(addr: int, role: str, text: str, item: dict[str, Any] | None = None) -> None:
        if addr == BADADDR:
            return
        annotations.setdefault(addr, []).append(
            {
                "role": role,
                "text": text,
                "block_id": item["id"] if item else None,
                "level": item["level"] if item else None,
                "kind": item["kind"] if item else "seh_table",
            }
        )

    if fh_dict:
        add(
            int(fh_dict["addr"], 16),
            "seh_table",
            f"function EH table: {fh_dict.get('name') or '?'} @ {fh_dict['addr']}",
        )

    for item in items:
        bid = item["id"]
        kind_label = _kind_label(item["kind"])
        filt = item.get("filter")
        handler = item.get("handler")
        for idx, (start, end) in enumerate(item["_ranges"]):
            suffix = f" (range {idx + 1}/{len(item['_ranges'])})" if len(item["_ranges"]) > 1 else ""
            begin = f"__try #{bid} (level {item['level']}, {kind_label}) begin{suffix}"
            if filt:
                begin += f"; filter {filt.get('name') or '?'} @ {filt['addr']}"
            if item["kind"] == "finally" and handler:
                begin += f"; __finally handler {handler.get('name') or '?'} @ {handler['addr']}"
            add(start, "try_start", begin, item)

            finish = f"__try #{bid} end{suffix}"
            if item["kind"] == "except" and handler:
                finish += f"; __except handler @ {handler['addr']}"
                if item["handler_shared"]:
                    finish += " (shared/empty entry)"
            elif item["kind"] == "finally" and handler:
                finish += f"; __finally handler {handler.get('name') or '?'} @ {handler['addr']}"
            add(end, "try_end", finish, item)

        if filt:
            add(
                int(filt["addr"], 16),
                "except_filter",
                f"__except filter for {func_name} #{bid}: {filt.get('name') or '?'}",
                item,
            )
        if item["kind"] == "finally" and handler:
            add(
                int(handler["addr"], 16),
                "finally_handler",
                f"__finally handler for {func_name} #{bid}: {handler.get('name') or '?'}",
                item,
            )
        if item["kind"] == "except" and handler and not item["handler_shared"]:
            add(
                int(handler["addr"], 16),
                "except_handler",
                f"__except handler for {func_name} #{bid}",
                item,
            )

    for ann_list in annotations.values():
        ann_list.sort(
            key=lambda a: (
                a.get("block_id") is None,
                a.get("block_id") or 0,
                {"try_start": 0, "try_end": 1, "except_filter": 2, "finally_handler": 3, "except_handler": 4}.get(a["role"], 9),
            )
        )

    public_items = []
    for item in items:
        public_items.append({k: v for k, v in item.items() if not k.startswith("_")})

    info: dict[str, Any] = {
        "function": {
            "addr": hex(func.start_ea),
            "end": hex(func.end_ea),
            "name": _name_at(func.start_ea) or None,
        },
        "arch": arch,
        "mechanism": mechanism if (public_items or fh_dict) else None,
        "function_handler": fh_dict,
        "try_blocks": public_items,
        "nodes": [],
        "edges": [],
        "annotations": annotations,
    }
    info["nodes"], info["edges"] = _build_graph(info)
    info["text"] = _format_text(info)
    return info


def annotate_disasm_entry(entry: dict[str, Any], ea: int, info: dict[str, Any]) -> None:
    """Attach EH roles/comments to one disasm line entry."""
    ann_list = (info.get("annotations") or {}).get(ea)
    if not ann_list:
        return
    entry["eh"] = ann_list
    comments = entry.setdefault("comments", [])
    for ann in ann_list:
        text = f"EH: {ann['text']}"
        if text not in comments:
            comments.append(text)


def _find_insert_index(lines: list[str], addr: int) -> int:
    for i, line in enumerate(lines):
        match = _ADDR_RE.search(line)
        if match and int(match.group(1), 16) >= addr:
            return i
    for i in range(len(lines) - 1, -1, -1):
        if lines[i].strip() == "}":
            return i
    return len(lines)


def annotate_decompile_code(code: str, info: dict[str, Any]) -> tuple[str, int]:
    """Insert ``// EH:`` comments into Hex-Rays pseudocode.

    The function signature is left untouched; a compact summary is inserted
    after the opening brace and boundary comments are inserted before the
    first pseudocode line at/after each EH address marker.
    """
    if not code or not info:
        return code, 0
    lines = code.splitlines()
    if not lines:
        return code, 0

    insertions: dict[int, list[str]] = {}
    summary = _summary_lines(info)
    if summary:
        brace_index = next(
            (i for i, line in enumerate(lines) if line.strip() == "{"),
            None,
        )
        if brace_index is not None:
            insertions.setdefault(brace_index + 1, []).extend(summary)

    has_addresses = any(_ADDR_RE.search(line) for line in lines)
    annotations = info.get("annotations") or {}
    if has_addresses and annotations:
        function = info.get("function") or {}
        func_start = int(function.get("addr") or "0", 16)
        func_end = int(function.get("end") or "0", 16)
        for addr in sorted(annotations):
            # Filter/finally routines live in function tails and are not part
            # of the entry function's pseudocode.  They are listed in the
            # summary above; only annotate addresses in the decompiled entry.
            if func_start and func_end and not (func_start <= addr < func_end):
                continue
            index = _find_insert_index(lines, addr)
            for ann in annotations[addr]:
                insertions.setdefault(index, []).append(
                    f"  // EH: {ann['text']}"
                )

    if not insertions:
        return code, 0

    inserted = 0
    for index in sorted(insertions, reverse=True):
        comments: list[str] = []
        seen: set[str] = set()
        for comment in insertions[index]:
            if comment not in seen:
                seen.add(comment)
                comments.append(comment)
        lines[index:index] = comments
        inserted += len(comments)
    return "\n".join(lines), inserted
