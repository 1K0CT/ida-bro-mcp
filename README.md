# ida-bro-mcp

> [!IMPORTANT]
> **For general use, prefer the [Official Hex-Rays IDA MCP Server](https://github.com/HexRaysSA/ida-mcp).**
>
> See the [announcement blog post](https://hex-rays.com/blog/hex-rays-ida-mcp-server)
> for more information. This fork is maintained for the GUI-agent workflows
> described below; it is not a replacement for the official server.

`ida-bro-mcp` is a fork of [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp).
It keeps the upstream MCP server, GUI plugin, idalib entry point, and core tool
set. This README documents only the features added or changed by this fork; use
the upstream project for the complete core tool reference and general usage.

## Fork features

### Zero-instance GUI supervisor

`ida-pro-mcp-supervisor` keeps an MCP endpoint alive on
`http://127.0.0.1:13337/mcp` even when no GUI IDA instance is running.

```sh
uv run ida-pro-mcp-supervisor --ida-exe "C:\Program Files\IDA Professional 9.3\ida.exe"
```

- With no instances, only the local management tools `open_file`,
  `list_instances`, and `select_instance` are exposed. Analysis tools return a
  message telling the agent to call `open_file` first.
- `open_file` launches the first GUI IDA instance. The endpoint remains up as
  instances appear or disappear; clients that honor `tools/list_changed`
  refresh their tool catalogue automatically.
- Startup uses a temporary `-A` so loader/CPU-selection/PDB dialogs cannot block
  plugin registration. After the instance registers, the supervisor calls
  `enable_interactive_mode` to restore normal dialogs such as Jump (`g`) and
  Cross-references (`x`).
- `autonomous=true` keeps the instance dialog-free for batch jobs, but is
  refused unless `allow_autonomous=true` is also passed.
- See [docs/gui-supervisor.md](docs/gui-supervisor.md) for startup, control
  (`--status`/`--stop`), and limitation details.

### Multi-agent and shared-instance routing

Each MCP session has its own selected instance. Sub-agents sharing one transport
session can use stable agent slots through `?agent=NAME`; an absolute instance
pin is available through `?instance=PORT` or `X-IDA-MCP-Instance`.

- `open_file` and `select_instance` affect only the caller's routing slot.
- An instance launched by one agent is claimed by that agent and is not silently
  auto-selected by others. If no unassigned instance is available, analysis
  tools return an "assigned to other sessions/agents" error; `select_instance`
  explicitly shares an instance.
- `open_file` attaches to an existing reachable instance for the same target by
  default: same IDB path, or the same binary name in the same directory. This
  avoids launching a second IDA against a live database. Set
  `reuse_existing=false` to force a new process.
- Launch matching uses PID first, then target path. The pre-launch snapshot also
  records start time/IDB/binary identity, so closing an existing instance during
  launch and reusing its port no longer causes `open_file` to wait until timeout.
- Separate Claude Code sessions get separate `Mcp-Session-Id` values
  automatically. For sub-agents in one session, configure one MCP server entry
  per agent:

```json
{
  "mcpServers": {
    "ida-alice": {
      "type": "http",
      "url": "http://127.0.0.1:13337/mcp?agent=alice"
    },
    "ida-bob": {
      "type": "http",
      "url": "http://127.0.0.1:13337/mcp?agent=bob"
    }
  }
}
```

### Large-database `survey_binary`

`survey_binary` is tuned for multi-hundred-MB IDBs without monopolizing IDA's
main thread:

- reads IDA's existing string list instead of rebuilding it;
- uses IDA-stored input-file MD5/SHA256 hashes;
- samples functions for xref ranking and call-graph estimates;
- caps per-function work and reports sampled data in `_note`;
- enforces a cooperative time budget and returns partial results instead of
  blocking. The budget is configurable with
  `IDA_MCP_SURVEY_BUDGET_SEC` and `IDA_MCP_SURVEY_MINIMAL_BUDGET_SEC`.

The result shape is unchanged, so existing consumers keep working.

### Demangled C++ symbols

Agent-facing output uses IDA's short demangled names
(`ParsingSession::~ParsingSession(void)`) instead of raw MSVC
(`??1ParsingSession@@...`) or Itanium spellings. This applies to function
lists, xrefs, callgraph nodes, disassembly labels/operands, decompiler refs,
globals/vftables, survey output, sigmaker, resources, and rename output.

`addr`/name arguments accept either the stored mangled name or the demangled
form shown in tool results. Hex-Rays pseudocode and user-authored comments are
left untouched.

### x86_64 exception-handling flow

- `exception_flow(queries)` describes MSVC `__try`/`__except`/`__finally`
  flow for one or more functions: nested try ranges, `__except` filter
  routines, handler entry blocks, out-of-line `$fin$` handlers, the
  function-level `__C_specific_handler` table, a node/edge graph, and a compact
  textual summary.
- `disasm(..., include_eh=true)` and `decompile(..., include_eh=true)` add
  `EH:` comments at try boundaries, filters, and handlers. Pass
  `include_eh=false` for the previous output.

The implementation reuses IDA's parsed `.pdata`/`.xdata` try-block metadata
(`ida_tryblks`) and the function CFG. No additional native plugin, IDB
mutation, or reopen is required.

### BinDiff vulnerability-fix diffing

Aimed at vulnerability-fix analysis of frequently updated components. The
similarity tools focus on matched pairs with low similarity; use
`bindiff_new_functions` to inspect primary-only functions that a `.BinDiff`
database does not store as rows.

- `bindiff_diff(secondary, primary="", ...)`: Export the current/new IDB with
  BinExport, export the closed older IDB with the BinDiff CLI, run
  `bindiff.exe`, and return low-similarity matched pairs. Results are written as
  a `.BinDiff` SQLite database plus a sidecar JSON.
- `bindiff_low_similarity(database, max_similarity=0.99, ...)`: Re-query or page
  through low-similarity matches without rerunning the comparison.
- `bindiff_best_match(database, addr)`: Resolve a primary/secondary address or
  name to its highest-similarity matched counterpart. Duplicate-name matches are
  ranked by similarity and returned with alternatives.
- `bindiff_new_functions(database, ...)`: Enumerate both BinExport files,
  subtract the matched addresses, and list functions present only in the
  primary/new version. Import stubs, thunks, and library functions are hidden
  by default; hidden counts are reported. Functions whose exact name also
  exists in the older version are marked as possible moves/renames.
- `bindiff_function_diff(database, addr)`: Show changed matched instructions and
  primary-only/secondary-only instructions for one matched function pair.

Requirements: BinDiff installed with `bindiff.exe` and
`binexport2dump.exe` available. The current IDB is exported in-process via the
BinExport IDC extension; the older IDB must be closed or supplied as a
`.BinExport` file. Tool discovery can be overridden with
`IDA_MCP_BINDIFF_EXE` or `IDA_MCP_BINDIFF_DIR`.

```text
bindiff_diff(secondary="old.dll.i64", max_similarity=0.95, limit=20)
  -> database: .../primary_vs_secondary.BinDiff
  -> functions: matched pairs sorted by lowest similarity

bindiff_new_functions(database=".../primary_vs_secondary.BinDiff")
  -> functions: primary-only addresses/names (normal functions by default)

bindiff_function_diff(database=".../primary_vs_secondary.BinDiff",
                      addr="0x1800172e0")
  -> changed_matched_instructions / primary_only / secondary_only
```

`bindiff_new_functions` needs both BinExport files because the `.BinDiff`
database stores matched pairs only. It reads them from the sidecar written by
`bindiff_diff`, or accepts explicit `primary_binexport`/`secondary_binexport`
paths for databases produced elsewhere.

### Correctness fixes

- Wide-string references in `decompile`/`disasm` are decoded as UTF-8.
  `get_strlit_contents` already returns UTF-8 bytes for both narrow and wide
  string types, so decoding again by `strtype` produced CJK mojibake for UTF-16
  strings.
- `open_file` launch waiting distinguishes a new IDA from a pre-existing one by
  PID/start time/IDB/binary identity, not merely by `host:port`. See the
  multi-agent section above.
