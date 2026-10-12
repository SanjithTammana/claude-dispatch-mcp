# Findings: calling Claude Code from Codex on Windows

Notes from building this bridge in October 2026, against Codex CLI 0.162 and Codex Desktop (Windows
11), and Claude Code 2.1.214 and 2.1.296. Both products change quickly, so recheck anything you rely
on. Each item says how it was established: **docs** (vendor documentation), **source** (vendor
source code), or **observed** (run locally).

## The Codex side

**Windows sandbox backends.** Codex has three Windows sandbox backends:
- `mxc`, built on Microsoft Execution Containers, recommended where supported.
- `elevated`, the legacy backend with dedicated lower-privilege sandbox users.
- `unelevated`, a restricted token.

([docs](https://learn.chatgpt.com/docs/windows/windows-sandbox))

Under MXC, commands run as the interactive user. The MXC crate never creates sandbox users or edits
host ACLs ([source](https://github.com/openai/codex/blob/main/codex-rs/mxc-sandbox/README.md)), and
`whoami` inside the sandbox returned the logged-in user (observed). Network is off by default in
`workspace-write` (docs, observed).

**Stdio MCP servers run outside the command sandbox.** Codex starts a configured stdio MCP server
"as a child of the orchestrator process", with no sandbox wrapper
([source](https://github.com/openai/codex/blob/main/codex-rs/rmcp-client/src/stdio_server_launcher.rs)).
The command network proxy does not filter MCP server connections
([docs](https://learn.chatgpt.com/docs/agent-approvals-security)). An MCP server therefore has the
user's full rights and network. That makes it the sanctioned bridge, and it is also why the server
has to narrow itself: allowlisted arguments, a fixed tool set, path checks and containment.

**Prefix rules do not help Codex Desktop.** A `prefix_rule` with `decision = "allow"` runs a
matching command outside the sandbox
([docs](https://learn.chatgpt.com/docs/agent-configuration/rules)). Codex Desktop on Windows issues
commands as whole PowerShell strings, and `codex execpolicy check` found no match for three
PowerShell forms of a command an argv rule matched (observed). Rules remain useful for callers that
pass a direct argv, such as `codex exec`.

**The Codex JavaScript tool is sandboxed.** Running the dispatcher through Codex's built-in
JavaScript execution failed with `EPERM` from `realpath` (observed). It runs inside the same
sandbox as commands.

**Approval is configured per server.** `default_tools_approval_mode = "prompt"` on an MCP server
makes Codex Desktop show each call's arguments and wait for approval. A call through this server
from a Desktop thread showed that prompt (observed).

## The Claude Code side

**`claude mcp serve` is not a narrow bridge.** It exposes Claude Code's own tools to the MCP
client: Bash, PowerShell, Edit, Write, WebFetch, an Agent tool, and more (observed, 2.1.214). The
documentation says the client "is responsible for implementing user confirmation"
([docs](https://code.claude.com/docs/en/mcp)). Using it from Codex hands Codex a general-purpose
shell with the user's rights.

**`--permission-mode plan` changes the model.** A `claude -p --model haiku --permission-mode plan`
run answered with Sonnet instead (observed, 2.1.296). This project uses `dontAsk` with a read-only
tool list for read-only work.

**A parent Claude Code session leaks into child runs.** A Claude Code session exports variables
such as its session id, a messaging token and `ANTHROPIC_BASE_URL`. A `claude -p` started with them
behaved as a sub-session and ignored `--model` (observed). The dispatcher removes every
`ANTHROPIC_*`, `CLAUDE_*` and `CLAUDECODE` variable, which also keeps the token out of the child.

**`--restricted` is the main lock.** In 2.1.296, `--restricted`:
- ignores user, project and local settings files, while `--settings` and managed settings still
  apply;
- removes code-running tools and WebFetch unless `--tools` names them;
- confines file tools to the working directories;
- refuses `bypassPermissions`.

With `--strict-mcp-config` and no `--mcp-config`, no MCP servers load. These are CLI controls, not
an OS sandbox (`claude --help`, observed).

**Hooks.** `disableAllHooks` in `--settings` disables user, project and local hooks. Managed hooks
are exempt ([docs](https://code.claude.com/docs/en/hooks#disable-or-remove-hooks)).

**Deny rules.** Read deny rules use gitignore-style paths and cover Grep and Glob on a best-effort
basis ([docs](https://code.claude.com/docs/en/permissions)).

**Subscription use.** Signing in to the unmodified Claude Code binary with your own subscription is
permitted. Routing other people's requests through your plan credentials is not
([docs](https://code.claude.com/docs/en/legal-and-compliance)). As of October 2026, `claude -p`
draws on subscription limits
([docs](https://support.claude.com/en/articles/15036540-use-the-claude-agent-sdk-with-your-claude-plan)).
Billing rules changed several times in 2026, so recheck them.

## Design consequences

- **Containment needs a Job Object.** A Claude turn can start descendants (for example through a
  tool), and a detached process can outlive its parent. The MCP server runs outside MXC, so nothing
  else tears those processes down. JobRun puts the turn in a kill-on-close Job Object, and the
  dispatcher treats teardown as unconfirmed unless the job report shows zero active processes.
- **The audit has to stay bounded.** A real working checkout can hold over 100,000 ignored entries
  (dependency folders, build output), and hashing all of them on every read-only call was
  impractical (observed). Read-only runs therefore list ignored paths without hashing them. That is
  supported by read-only turns having no write tools, with the existing ignored-tree limitation
  stated in the threat model. Write runs require clean index metadata and no untracked/ignored
  entries. Raw snapshots record every tracked and non-ignored file by size, timestamps and file
  ID, independent of Git's change classification, with explicit entry and time limits. An earlier
  version hashed contents, which took about a minute and exceeded a 256 MiB cap on a real
  13,600-file checkout.
- **Cleanup comes before the audit.** If the audit ran while descendants were alive, they could
  edit files after the snapshot. The order is: stop, confirm teardown, then audit.

## Approaches considered and not used

| Approach | Why not, here |
|---|---|
| `claude mcp serve` registered in Codex | Exposes a shell and write tools with no gate of its own. |
| A `prefix_rule` allowing the dispatcher | Cannot match Codex Desktop's PowerShell strings. It works for `codex exec`. |
| Running the dispatcher from Codex's JS tool | Sandboxed (`EPERM`). |
| Claude Channels or a localhost relay between the two apps | Opens a listener and a second control path, where a child process over stdio needs neither. |
| Opening the network for the whole Codex sandbox | Gives every model-issued command network access and lets it read the Claude credential file. |

Community projects in the same space, as of October 2026:
- [sendbird/cc-plugin-codex](https://github.com/sendbird/cc-plugin-codex): a Codex plugin that spawns `claude`.
- [xiaolai/claude-octopus](https://github.com/xiaolai/claude-octopus): an MCP server over the Claude Agent SDK.
- [Liii8888/codex-claude-subagent](https://github.com/Liii8888/codex-claude-subagent): read and write modes over the official CLI, macOS only.

Their defaults and scope differ from this project, so compare before choosing.
