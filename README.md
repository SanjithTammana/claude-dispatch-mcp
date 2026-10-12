# claude-dispatch-mcp

A stdio MCP server for [Codex](https://learn.chatgpt.com/docs) that hands one task to
[Claude Code](https://code.claude.com/docs) and returns the result. Each call runs exactly one
locked-down Claude Code CLI turn (`claude -p`) in a repository you have listed as trusted, audits
what changed against Git, and confirms that every process it started is gone.

One tool, `dispatch_claude`:

| Argument | Meaning |
|---|---|
| `packet_text` (required) | The task, as Markdown. Passed to Claude on stdin, never on the command line. |
| `cd` (required) | Absolute path of a trusted repository root, or of a linked worktree of one. |
| `mode` | `read-only` (default) or `workspace-write`. |
| `allow` | Relative paths Claude may change. Required in `workspace-write`, forbidden in `read-only`. |
| `model` | `sonnet` (default), `opus` or `haiku`. |
| `effort` | `low`, `medium`, `high` or `xhigh`. |
| `timeout_seconds` | 1 to 3600 (default 900). |
| `max_budget_usd` | 0.01 to 5 (default 1). |

**Status:** v0.1, Windows only. On macOS and Linux it refuses to run (see
[Why Windows only](#why-windows-only)).

## Why this exists

Codex Desktop on Windows runs shell commands as whole PowerShell strings, so a Codex `prefix_rule`
cannot allow a command whose arguments vary, and its JavaScript tool runs inside the command
sandbox. Codex does launch stdio MCP servers as children of the app, outside the command sandbox. An
MCP server is therefore the sanctioned path from a Codex session to a local Claude Code install.
[`docs/FINDINGS.md`](docs/FINDINGS.md) has the details and what was ruled out.

## What a call can and cannot do

Claude runs with:

- `--restricted --strict-mcp-config`: user, project and local settings files are ignored, no MCP
  servers are loaded, code-running tools are removed, and file tools are confined to `cd`.
- `--tools Read Grep Glob`, plus `Edit Write` in `workspace-write`. Bash, PowerShell, web, notebook,
  agent and MCP tools are explicitly disallowed.
- `--permission-mode dontAsk` (read-only) or `acceptEdits` (workspace-write).
- Generated `--settings` with `disableAllHooks` and deny rules for secret-shaped paths (`.env*`,
  `*.pem`, `*.key`, SSH keys, `.npmrc`, `.netrc`, `.git/**`), plus any `extra_deny` you configure.
- An environment with every `ANTHROPIC_*` and `CLAUDE_*` variable removed, so it uses your own
  Claude Code login and never inherits a parent session.
- A Windows Job Object (`JobRun`) with kill-on-close: on exit or timeout, the whole process tree is
  torn down, and the result is a failure unless teardown is confirmed. MCP cancellation requests are
  not supported; a call runs until it finishes or times out.
- No dispatcher-launched Node process inherits `NODE_OPTIONS` or `NODE_PATH`.

After confirmed teardown, the dispatcher compares raw filesystem snapshots before and after. It
records the size, timestamps and file ID of every tracked and non-ignored untracked file, which any
write through Claude's tools changes, even if Git would hide its change through
`ident` or line-ending normalization. In `read-only`, a change in this inventory is a `VIOLATION`
(existing ignored trees are only listed). In `workspace-write`, the index must match HEAD, with no
unmerged, untracked, ignored, hidden or linked entries, and every changed path must be inside
`allow`. Existing tracked byte differences, including checkout conversions, become the starting
baseline. **The allowlist is checked after the fact; it does not prevent a write.** A
violation is reported (exit 3), not undone.

Read [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) before you trust a repository. In short:
- These are Claude Code CLI controls, not an OS filesystem sandbox.
- Dispatcher Git calls disable system/global config, refuse local includes, and neutralize filters.
- Managed (enterprise) Claude Code hooks still run.

## Install

Requirements:
- Windows 10 or 11.
- Node.js 24.2 or later (the entry points use `import.meta.main`).
- Git.
- Claude Code, signed in with `claude` then `/login`.
- The .NET Framework 4 C# compiler, which ships with Windows at
  `%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe`. JobRun is compiled from
  `src/containment/JobRun.cs` on first use, so you run what you can read.

Clone the repository somewhere that is **not** inside a repository you will list as trusted:

```
git clone <this repository's URL> claude-dispatch-mcp
cd claude-dispatch-mcp
npm test
```

There are no npm dependencies.

## Configure

State lives in `%LOCALAPPDATA%\claude-dispatch-mcp\` (override with the `CLAUDE_DISPATCH_HOME`
environment variable, an absolute path). Create `config.json` there:

```json
{
  "trusted_roots": ["D:\\src\\my-repo", "D:\\src\\other-repo"],
  "claude_binary": "D:\\tools\\claude\\claude.exe",
  "extra_deny": ["**/secrets/**"]
}
```

- `trusted_roots` (required): Git toplevels Claude may work in. Their linked worktrees are accepted
  too, and nested or unrelated repositories are not. A root must not overlap the state directory or
  this package.
- `claude_binary` (optional): an absolute path to `claude.exe`. Without it, the dispatcher uses
  `%USERPROFILE%\.local\bin\claude.exe`, then the WinGet package path. The binary must not be inside
  any trusted root.
- `extra_deny` (optional): extra deny patterns, applied to Read, plus Edit and Write in
  `workspace-write`.

All paths must be local drive-letter paths on a volume that reports file IDs. NTFS is tested; FAT
and exFAT are rejected; other filesystems are untested. UNC and `\\?\` paths are rejected. The state
directory must not be inside any Git repository. Unknown keys are rejected.

Some repositories are refused:
- Any call into a repository whose tracked or untracked files include a hard link, or that has a
  populated submodule or a nested repository inside it.
- Either mode into a repository with `include.path` or `includeIf` configuration.
- `workspace-write` into a repository with submodules or an index differing from HEAD, unmerged
  entries, hidden index flags, untracked files or ignored entries. Converted checkouts, including
  `autocrlf`, `eol`, `ident` and filter-produced bytes, are accepted as raw starting baselines.

Each snapshot is bounded: at most 20,000 index + untracked + ignored listing entries combined,
and at most 20,000 inspected filesystem entries during expansion, and 120 seconds of filesystem
inspection. File contents are not read: each file is compared by size, timestamps and file ID. Each Git call has a 120-second
timeout and an 8 MiB output buffer. Exceeding a limit refuses the baseline or returns scope
`UNKNOWN` after the turn, with an explanatory error. Git for Windows' multi-link executables are
accepted only after every hard-link name is enumerated and proven outside the writable roots;
incomplete enumeration refuses the call.

Captured worker stdout and stderr are each limited to 32 Mi characters. Past that the turn is
stopped and the run fails, and the saved `stdout.json` and `stderr.txt` evidence holds only the
output captured before the stop. The MCP response carries the first 200,000 characters of the dispatcher's
output; the RESULT block comes first, and any truncation is reported.

Then check the setup:

```
npm run doctor
```

## Register with Codex

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.claude-dispatch]
command = 'C:\Program Files\nodejs\node.exe'
args = ['D:\path\to\claude-dispatch-mcp\src\mcp_server.mjs']
startup_timeout_sec = 20
tool_timeout_sec = 3700
default_tools_approval_mode = "prompt"
```

Keep `default_tools_approval_mode = "prompt"`. The server does not ask for approval itself;
the prompt Codex shows is the only point where you see the arguments before a call runs. After
registering, start a thread, ask Codex to use `dispatch_claude` for a small read-only question, and
confirm that the approval prompt appears.

## Results

Each call returns the dispatcher's `RESULT` block: `status`, `scope_check` (`PASS`, `VIOLATION` or
`UNKNOWN`), `cleanup_confirmed`, the paths whose raw records changed, cost and usage, the evidence directory, and
Claude's last message. Evidence for every run is kept in `<state>\runs\<id>\`: the packet, stdout,
stderr, the JobRun report and `result.json`.

| Exit | Meaning |
|---|---|
| 0 | Completed, scope `PASS`, cleanup confirmed |
| 2 | Rejected before Claude started (arguments, paths, configuration) |
| 3 | Scope `VIOLATION` or `UNKNOWN`, or `workspace-write` on a dirty worktree |
| 5 | Process teardown not confirmed |
| 6 | Timed out (teardown confirmed) |
| 7 | Claude failed, including an expired login |

The result is a draft. The calling agent should check the work itself.

## Using the dispatcher without MCP

`src/claude_dispatch.mjs` is also a CLI:

```
node src/claude_dispatch.mjs run --packet <state>\packets\task.md --cd D:\src\my-repo --mode read-only
node src/claude_dispatch.mjs doctor
```

Packets must be `.md` files directly inside `<state>\packets\`.

## Why Windows only

Containment relies on a Windows Job Object, which kills every descendant when its last handle
closes and reports how many processes were still active. Without an equivalent, the dispatcher
cannot confirm that a timed-out or cancelled turn left nothing running, so it refuses to start
instead of running uncontained. Equivalents for Linux (cgroups) and macOS are possible future work.

## Terms of use

Use this with your own Claude Code login, for your own work. Anthropic permits signing in to the
unmodified Claude Code binary with your own subscription. Do not use this to give other people
access through your account.

## License

Apache-2.0. See [LICENSE](LICENSE).
