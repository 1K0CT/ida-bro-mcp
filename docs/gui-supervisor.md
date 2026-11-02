# GUI supervisor: zero-instance bootstrap, multi-agent routing, interactive startup

`ida-pro-mcp-supervisor` is an optional companion to `ida-pro-mcp` / `idalib-mcp`.
It keeps an MCP endpoint alive on `127.0.0.1:13337` even when no GUI IDA
instance is running, so the client can call `open_file` to launch the first
instance instead of failing with `ECONNREFUSED`.

It is aimed at workflows where multiple agents analyze different samples in
GUI IDA instances, and where the user still wants IDA's normal interactive
dialogs (`g`, `x`, ...).

## Quick start

```sh
# From a checkout (set IDA_MCP_IDA_EXE if IDA is not auto-detected):
uv run ida-pro-mcp-supervisor --ida-exe "C:\Program Files\IDA Professional 9.3\ida.exe"

# Or run with IDA's bundled Python:
python -m ida_pro_mcp.gui_supervisor --ida-exe "C:\Program Files\IDA Professional 9.3\ida.exe"
```

Configure the MCP client with:

```json
{ "type": "http", "url": "http://127.0.0.1:13337/mcp" }
```

Control:

```sh
uv run ida-pro-mcp-supervisor --status
uv run ida-pro-mcp-supervisor --stop
uv run ida-pro-mcp-supervisor --verbose
```

The supervisor may also be started by a login script / Windows Task Scheduler /
systemd user unit. The repository does not ship machine-specific autostart
scripts.

## Startup behavior (interactive dialogs)

A fresh database opened with `ida.exe -c <file>` can stop at IDA's
**"Load a new file"** dialog (loader/CPU selection) or a **PDB** prompt before
the MCP plugin registers. The supervisor therefore launches GUI IDA with:

```text
ida.exe -A [-c] <target>
```

`-A` suppresses those startup dialogs. Once the new plugin instance registers,
the supervisor calls the plugin tool `enable_interactive_mode`, which schedules
`idc.batch(0)` on the Qt event loop after the MCP call's transient batch window.
The result is an instance that started without dialogs but has working
interactive dialogs afterwards.

- Default `autonomous=false`: temporary `-A`, then interactive restoration.
- `autonomous=true` + `allow_autonomous=true`: stays in autonomous mode (no
  `g`/`x` dialogs); intended for batch jobs.
- `autonomous=true` without `allow_autonomous`: refused by the agent-facing
  supervisor tool.

Startup PDB prompts are skipped by `-A`; load PDB manually in IDA if needed.
For unusual formats that require a manual loader choice, `-A` uses IDA's
default choice; open such files manually if the default is wrong.

## Zero-instance behavior

- With no instances, `tools/list` contains the local management tools
  (`open_file`, `list_instances`, `select_instance`).
- IDA analysis tools are gated with a message telling the agent to call
  `open_file` first.
- The first live instance populates the tool catalogue cache (under the IDA
  user directory's `mcp/supervisor` folder), and a
  `notifications/tools/list_changed` notification lets clients refresh.

## Multi-agent routing

Routing key priority:

1. `?instance=PORT` / `X-IDA-MCP-Instance: PORT` — absolute pin to one instance;
2. `?agent=NAME` / `X-IDA-MCP-Agent: NAME` — stable agent slot, independent of
   the MCP transport session;
3. `Mcp-Session-Id` — per MCP session (default; strict);
4. `anonymous` — legacy shared bucket, disabled by default.

Behavior:

- Each session/agent slot has its own selected instance. `select_instance` and
  `open_file` affect only the caller's routing key.
- An instance launched by a session is claimed by it; other sessions do not
  silently auto-select it. When every reachable instance is claimed, analysis
  tools return an "assigned to other sessions/agents" error. Use
  `select_instance(port=...)` to explicitly share, or `open_file` to create a
  new instance.
- `open_file` matches the new registration by launched PID first, then by
  target binary/IDB directory. Unrelated instances that appear concurrently are
  ignored.
- Supervisor restart clears selections/claims; claims otherwise expire after
  inactivity (24h).

### Independent agents

Separate Claude Code/SDK sessions get separate `Mcp-Session-Id`s
automatically. Each agent can call `open_file` / `select_instance` without
affecting the others.

### Sub-agents in one Claude Code session

Sub-agents share the parent's MCP transport session. Give each agent its own
MCP server entry with a stable agent slot:

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

Tell each sub-agent to use only its own namespace (`mcp__ida-alice__*` /
`mcp__ida-bob__*`). `alice` and `bob` bind their own instances via
`open_file` / `select_instance`; the URLs stay stable as instance ports change.

### Fixed instance pins

```json
{ "type": "http", "url": "http://127.0.0.1:13337/mcp?instance=13338" }
```

Pinned endpoints are read-only: `open_file` and `select_instance` are refused
there. Use the unpinned `/mcp` or `?agent=` entry to launch/switch instances.

## Legacy/stateless clients

Strict `Mcp-Session-Id` is the default. Clients that cannot send it can set:

```sh
IDA_MCP_ALLOW_ANONYMOUS=1
```

All such clients then share one `anonymous` routing bucket (legacy behavior).
Alternatively, set a stable session id with `X-IDA-MCP-Session: NAME`.

## Scope and limitations

- The supervisor manages **GUI** IDA instances. Instances registered with
  `backend="worker"` (idalib workers) are ignored; use `idalib-mcp` for
  headless worker sessions.
- IDA GUI concurrency is licensed/environment-dependent. If a new instance
  stops at a startup dialog or the limit is reached, `open_file` times out with
  a diagnostic rather than claiming an unrelated instance.
- GUI dialogs are restored by a Qt timer; this targets IDA's GUI (`ida.exe`).
  Text-mode/idALib have no interactive dialogs to restore.
- The supervisor's launch path handles Windows `RUNASADMIN` by falling back to
  a UAC (`ShellExecuteW runas`) launch. On macOS/Linux, provide
  `--ida-exe`/`IDADIR` as needed.

## Related files

- `src/ida_pro_mcp/gui_supervisor.py` — supervisor implementation and entry point.
- `src/ida_pro_mcp/ida_mcp/api_core.py` — `enable_interactive_mode` and the
  direct `ida_strlist` string cache used by `survey_binary`.
- `src/ida_pro_mcp/ida_mcp/discovery.py` — `launch_gui_instance` PID/target
  matching and temporary `-A` startup.
