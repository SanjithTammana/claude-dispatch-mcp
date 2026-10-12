# Threat model

This document covers what `claude-dispatch-mcp` defends against, how, and where it stops. Read the
limits before you add a repository to `trusted_roots`.

## What is protected

1. Files outside the paths a call is allowed to change, in the repository the call targets.
2. Everything outside that repository: your other files, credentials and the rest of the machine.
3. The dispatcher's own state: `config.json` (the trust list and binary choice), the packets
   directory, run evidence, the compiled JobRun launcher and this package's code. If a dispatched
   turn could write any of these, it could widen the next dispatch.
4. Your Claude account: cost per call, and the login itself.

## Who might act against it

- **The calling agent (Codex).** It chooses every argument and writes the packet. It may be
  following instructions injected into its own context. Treat each call as a request from a
  semi-trusted party.
- **The dispatched Claude turn.** It reads repository content that may contain injected
  instructions, and may try to act outside its scope.
- **Repository content.** Files, and Git configuration in `.git/config`.

Out of scope: other software running as your Windows user. It can already change anything the
dispatcher can, including the state directory. A malicious Claude Code binary, Node.js runtime, or
Git install is also out of scope.

## Controls

| Threat | Control |
|---|---|
| Caller passes extra CLI options (for example `--dangerously-skip-permissions`, `--settings`, `--add-dir`) | The MCP schema allows only typed, enumerated arguments, with no extra properties. Values starting with `-` or containing newlines are rejected. The dispatcher rejects forbidden flag names anywhere in argv and unknown flags. Every call is one direct argv spawn with no shell. |
| Caller points the packet at an arbitrary file | Packets must be regular, single-link `.md` files directly inside `<state>\packets\`. MCP validates arguments and completes the shared preflight before exclusive inbox creation. The dispatcher repeats preflight and validates the actual packet before copying its bytes to evidence and passing them on stdin. The inbox is deleted after success or failure. Rejected calls write no packet; loading configuration may still create the empty state layout. |
| Caller targets an arbitrary directory | `cd` must be exactly the Git toplevel of a trusted root, or of a linked worktree registered to one, verified through the reciprocal `gitdir` link. Nested and unrelated repositories are rejected before `git status` runs. |
| The turn runs commands, browses, or loads tools | `--restricted`, `--tools` limited to `Read Grep Glob` (plus `Edit Write` in `workspace-write`), and `--disallowedTools` for Bash, PowerShell, WebFetch, WebSearch, NotebookEdit, Agent and `mcp__*`. `--strict-mcp-config` with no MCP config. |
| The turn reads secrets inside the repository | Deny rules for `.env*`, `*.env`, `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `id_ed25519*`, `.npmrc`, `.netrc` and `.git/**`, plus `extra_deny`. See the limits below. |
| A workspace file aliases something outside the repository (a hard link to run evidence, a credential, or code) | In both modes, every file Git tracks or reports as untracked must have exactly one name, or the call is refused before Claude starts. An innocuously named alias can therefore not expose a file under a name no deny rule matches, nor let an allowed in-place edit rewrite it. Populated submodules and nested repositories, whose files this non-recursive listing cannot see, are refused in both modes. The check runs before any `git status`, which would otherwise enter them using their own configuration. Ignored trees are not walked (limit 4). |
| Project hooks or settings change behaviour | `--restricted` ignores user, project and local settings files, and the generated settings set `disableAllHooks`. |
| A parent Claude session leaks into the child | Every `ANTHROPIC_*`, `CLAUDE_*` and `CLAUDECODE` variable is removed from the child environment. |
| The turn edits files it was not allowed to | Raw before/after records for every indexed and non-ignored untracked path: size, last-write, change and creation times (100 ns), file ID, link count, type, mode and link status. File contents are not read; every write the turn's Edit and Write tools can make changes these. Write mode also expands ignored entries. Git supplies path names, index object IDs, HEAD and hidden flags; no status or diff classifies scope. Deletions, additions and both endpoints of renames change raw records. Write mode requires index == HEAD, no unmerged/untracked/ignored/hidden entries, and regular single-link tracked files; checkout conversions and existing tracked byte differences are raw baselines. Any raw change outside `allow` gives `VIOLATION`; unreadable or over-limit inventory gives `UNKNOWN`. Both fail. Any submodule is refused in write mode. |
| The turn hides edits | Moving HEAD, `assume-unchanged` and `skip-worktree` flags are violations. Bounded walks make a huge changed tree `UNKNOWN`, never an unbounded hash. |
| Processes outlive the turn and edit files after the audit | The turn runs inside a kill-on-close Job Object. Order is fixed: wait, stop JobRun, confirm teardown from its report (root PID matches, exit codes agree, zero active processes), and only then audit. Without confirmed teardown the audit does not run and scope stays `UNKNOWN`. A missing or forged report means failure. |
| The turn rewrites the dispatcher's state or launcher | `--restricted` confines file tools to `cd`. State, package, Claude, Git and Node must be disjoint from trusted roots and the actual worktree, including linked worktrees outside their main roots. Checks use paths and filesystem identities; missing IDs fail closed. UNC/device paths are refused, including discovered executables. Every protected source/executable hard-link name is enumerated when necessary, verified by identity and count, and checked against writable roots. Third-party executable hard links outside those roots are allowed; workspace files still require one link. Package source links/junctions are refused. State-in-repository checks use filesystem ancestry (`.git` markers and bare-repository layout), with no Git probe. Both entry points finish the same preflight before launcher selection. State config and cached executable/sidecar require single-link files, cache directories must be plain, and canonical cache placement must match. |
| A planted executable runs instead of the real one | Git is resolved to an absolute path from absolute local `PATH` entries, never the current directory. Before Git first runs, its location is checked against every trusted root, the state directory and the requested workspace, using a configuration parsed without Git. Claude, Node, JobRun and `fsutil` are spawned by absolute path. |
| The audit runs code the turn just rewrote | System/global Git config is disabled, inherited `GIT_*` variables are dropped, and local `include.path`/`includeIf` are refused without following them. A phase reads configuration once for each root and supplies filter overrides through separate indexed keys/values, preserving `=` in driver names. After confirmed teardown, a fresh phase reads the frozen configuration again. Fsmonitor, hooks and external attributes are disabled. Dispatcher scope uses metadata/path commands only; no status/diff/content normalization executes workspace filter implementations. |
| Runaway cost or time | `--max-budget-usd` (at most 5, default 1), turn timeout (at most 3600 s, default 900), a 120 s timeout on every Git call, and at most two concurrent calls per server. The MCP server runs the dispatcher inside its own JobRun, which holds every descendant, including the turn's nested job. When the dispatcher exits, anything left in that job is terminated. Ten minutes after the turn timeout, a watchdog asks JobRun to terminate the job, and the server answers within a fixed bound whether or not every pipe closes. Stopping always goes through JobRun's control pipe, never a PID lookup, so a reused PID is never targeted. The dispatcher's last-resort stop for the turn's JobRun uses the process handle Node holds for it, and only while that process has not exited. If the server answers on a drain deadline instead of closed pipes, it says so, and it never reports success without a RESULT block. |

## Limits

1. **These are Claude Code CLI controls, not an OS sandbox.** The turn runs as your Windows user. If
   a Claude Code release mishandles `--restricted`, `--tools` or deny rules, nothing here would stop
   a bypass. The flags were verified against Claude Code 2.1.296. Re-run the tests and `doctor`
   after upgrading.
2. **Deny rules are best-effort for Grep and Glob.** Anthropic documents Read deny rules as covering
   Grep and Glob on a best-effort basis. Do not keep high-value secrets in a trusted repository and
   rely on deny rules alone.
3. **The allowlist is an audit, not a write barrier.** A violating edit is made, detected and
   reported, but not reverted. Run `workspace-write` calls in a clean worktree you can discard.
4. **Read-only mode does not walk ignored trees.** Large checkouts can hold over 100,000 ignored
   entries, so read-only runs list ignored paths without hashing them or checking them for hard
   links. Read-only turns have no write tools. A new top-level ignored listing entry is detected,
   but an addition or edit inside an ignored directory that is already listed is not (for example
   a file a managed hook creates there). A pre-existing hard link inside an ignored directory could
   expose its target to a read. Such links can only come from other software on the machine (Git
   does not store hard links), but package managers that hard-link into `node_modules` exist.
   Keep secrets out of ignored trees of repositories you dispatch into.
5. **Git remains a bounded metadata dependency.** Discovery, configuration, index/path listings,
   HEAD/object-format reads and HEAD-tree listing still use the installed Git. Local repository
   configuration and administrative metadata are read; the dispatcher does not parse all of Git
   itself. System/global scopes are disabled, includes are refused in both modes, filters are
   neutralized, and fsmonitor/hooks/external attributes are disabled. `safe.directory` is supplied
   explicitly and `core.longpaths=true` is pinned, so neither depends on installed config. System
   or global `core.autocrlf`, `core.eol`, `core.attributesFile` and ignore rules do not define raw
   scope: the audit performs no checkout or content conversion. Removing global ignore rules can
   make additional files untracked and refuse write mode. Unknown or unreadable metadata fails
   closed. CLI preflight runs outside a Job Object; MCP's repeated child preflight and final audit
   run in the outer job. Each Git call times out after 120 s with an 8 MiB output ceiling.
6. **Managed settings and hooks still apply.** Enterprise-managed Claude Code settings and hooks
   take precedence by design. If your organization installs hooks, they run in dispatched turns.
7. **Approval is the host's job.** The server does not prompt. Per-call approval exists only if
   Codex is configured with `default_tools_approval_mode = "prompt"` and you read the prompt.
8. **The JobRun checksum detects corruption, not tampering.** A process that can write the cache
   directory can replace both the executable and its sidecar. The cache is protected by being
   outside every workspace a turn can write, and by the link checks.
9. **Packet contents leave the machine.** The packet and anything Claude reads are sent to
   Anthropic as model input. Packets and run evidence (stdout, stderr, results) are kept in the
   state directory until you delete them. Captured worker stdout and stderr are each limited to 32 Mi
   characters. Past that the turn is stopped, the run fails, and the evidence holds only what was
   captured. The MCP response carries at most the first 200,000 characters of the dispatcher's
   output, so a long final message is cut from the end and the truncation is reported. The RESULT
   block comes first and is kept.
10. **The settings file is written to `%TEMP%`.** It holds no secrets and is deleted after a
    confirmed cleanup.
11. **Windows only.** On other platforms the dispatcher refuses to run, because there is no
    confirmed-teardown containment there.
12. **MCP cancellation is not supported.** The server ignores `notifications/cancelled`; a call
    runs until it finishes, its timeout, or the watchdog. Stopping the MCP server itself ends every
    call it started: JobRun's control pipe closes and the job is terminated.
13. **The server's own launch environment is the operator's.** Node processes the dispatcher starts
    do not inherit `NODE_OPTIONS` or `NODE_PATH`, because the relay runs with the repository as its
    working directory and a relative preload would resolve to repository content. The MCP server
    process itself runs with whatever environment and working directory Codex gives it.
14. **Whole-inventory audit limits.** Each snapshot allows at most 20,000 index + untracked +
    ignored listing entries combined (including duplicate index stages), and separately at most
    20,000 inspected filesystem entries including directories/missing paths. No file content is
    read: each file is recorded by size, last-write and change times (100 ns), creation time and
    file ID, which every write through Claude's Edit and Write tools changes. Neither tool can set
    timestamps. Filesystem inspection has a 120-second deadline, checked before and after each
    filesystem operation, during directory enumeration and before a snapshot is accepted. A single
    synchronous call that blocks (for example on an unresponsive volume) is bounded only by the MCP
    watchdog, which terminates the dispatcher's job. Read-only ignored entries consume listing
    capacity but their contents are not read. Over-limit baselines refuse with code 3; over-limit
    final snapshots return `UNKNOWN` with a clear error. These bounds apply to the whole tracked
    inventory, not only files Git calls modified. Run in a smaller repository if needed.

## Reporting

See [SECURITY.md](../SECURITY.md).
