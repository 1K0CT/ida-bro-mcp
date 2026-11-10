"""Agent-facing x86_64 exception-handling flow tool."""

from __future__ import annotations

from typing import Annotated, NotRequired, TypedDict

import idaapi

from . import eh
from .rpc import tool
from .sync import idasync, tool_timeout
from .utils import normalize_dict_list, parse_address


class ExceptionQuery(TypedDict):
    addr: Annotated[str, "Function address or name"]


class ExceptionFlowResult(TypedDict, total=False):
    query: str
    function: dict
    arch: str
    mechanism: str | None
    function_handler: dict | None
    try_blocks: list[dict]
    nodes: list[dict]
    edges: list[dict]
    text: str
    error: NotRequired[str | None]


@tool
@idasync
@tool_timeout(60.0)
def exception_flow(
    queries: Annotated[
        list[ExceptionQuery] | ExceptionQuery,
        "Function address(es)/name(s) whose exception handling should be described",
    ],
) -> list[ExceptionFlowResult]:
    """Describe x86_64 ``__try``/``__except``/``__finally`` flow for functions.

    Uses IDA's parsed ``.pdata``/``.xdata`` try-block metadata (the same data
    the GUI graph uses) plus the function CFG.  Returns nested try blocks with
    guarded ranges, filter routines, handler blocks, out-of-line ``$fin$``
    handlers, the function-level ``__C_specific_handler`` table, a node/edge
    graph, and a compact text rendering.  ``disasm`` and ``decompile`` use the
    same metadata to add ``EH:`` comments automatically.
    """
    queries = normalize_dict_list(queries)
    results: list[ExceptionFlowResult] = []

    for query in queries:
        addr_text = str(query.get("addr", "") or "").strip()
        if not addr_text:
            results.append(
                {
                    "query": addr_text,
                    "function": {},
                    "arch": eh._arch_label(),
                    "mechanism": None,
                    "function_handler": None,
                    "try_blocks": [],
                    "nodes": [],
                    "edges": [],
                    "text": "addr is required",
                    "error": "addr is required",
                }
            )
            continue
        try:
            ea = parse_address(addr_text)
            func = idaapi.get_func(ea)
            if func is None:
                results.append(
                    {
                        "query": addr_text,
                        "function": {},
                        "arch": eh._arch_label(),
                        "mechanism": None,
                        "function_handler": None,
                        "try_blocks": [],
                        "nodes": [],
                        "edges": [],
                        "text": f"Not a function: {addr_text}",
                        "error": f"Not a function: {addr_text}",
                    }
                )
                continue
            info = eh.get_eh_info(func.start_ea)
            # annotations are an internal int-keyed map used by disasm/decompile
            info.pop("annotations", None)
            results.append({"query": addr_text, "error": None, **info})
        except Exception as exc:
            results.append(
                {
                    "query": addr_text,
                    "function": {},
                    "arch": eh._arch_label(),
                    "mechanism": None,
                    "function_handler": None,
                    "try_blocks": [],
                    "nodes": [],
                    "edges": [],
                    "text": str(exc),
                    "error": str(exc),
                }
            )

    return results
