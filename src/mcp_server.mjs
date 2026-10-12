#!/usr/bin/env node
/**
 * claude-dispatch-mcp: stdio MCP server (JSON-RPC 2.0, Node stdlib only) with one tool,
 * dispatch_claude.
 *
 * Why: Codex Desktop on Windows runs shell commands as whole PowerShell strings, so a Codex
 * prefix_rule cannot allow a dispatcher call whose arguments vary, and its JavaScript tool runs
 * inside the command sandbox. Codex launches stdio MCP servers as children of the app, outside the
 * command sandbox, so an MCP server is the sanctioned way for a Codex session to reach Claude Code.
 * This server adds no capability of its own: every call becomes one direct argv invocation (no
 * shell) of claude_dispatch.mjs, which remains the security boundary. Arguments are allowlisted and
 * typed here as a second layer.
 *
 * Register it in Codex with default_tools_approval_mode = "prompt" so every call's arguments are
 * shown for approval before it runs (README "Register with Codex").
 */
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { preflight } from "./preflight.mjs";
import { parseArgs, withoutNodePreloads } from "./claude_dispatch.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE = resolve(HERE, "..");
const DISPATCHERS = { dispatch_claude: join(HERE, "claude_dispatch.mjs") };
const OUTPUT_CAP = 200_000;
const SERVER = { name: "claude-dispatch-mcp", version: "0.1.0" };

const str = (description, extra = {}) => ({ type: "string", description, ...extra });
const TOOLS = [
  {
    name: "dispatch_claude",
    description: "Delegate one task packet to a restricted Claude Code CLI turn (Read/Grep/Glob, plus " +
      "Edit/Write in workspace-write; no shell, web or MCP; no user or project hooks (organization-managed hooks still run); raw filesystem scope audit; Job Object containment). " +
      "Returns the dispatcher's RESULT block.",
    inputSchema: {
      type: "object", additionalProperties: false, required: ["packet_text", "cd"],
      properties: {
        packet_text: str("The full task packet (Markdown). Written to the state directory's packets/ and passed on stdin."),
        cd: str("Absolute path of a trusted repository or linked-worktree root to work in."),
        mode: str("read-only (default) or workspace-write", { enum: ["read-only", "workspace-write"] }),
        allow: { type: "array", items: { type: "string" }, description: "Relative paths Claude may change (workspace-write only)." },
        model: str("sonnet (default), opus or haiku", { enum: ["sonnet", "opus", "haiku"] }),
        effort: str("Optional effort", { enum: ["low", "medium", "high", "xhigh"] }),
        timeout_seconds: { type: "integer", minimum: 1, maximum: 3600 },
        max_budget_usd: { type: "number", minimum: 0.01, maximum: 5, description: "Two decimal places at most." },
      },
    },
  },
];

function fail(message) { const e = new Error(message); e.userFacing = true; throw e; }
function plainValue(name, value) {
  if (typeof value !== "string" || !value || value.startsWith("-") || /[\0\r\n]/.test(value))
    fail(`${name} must be a non-empty single-line string that does not start with '-'`);
  return value;
}
function checkArgs(tool, args) {
  const schema = TOOLS.find(t => t.name === tool).inputSchema;
  if (!args || typeof args !== "object" || Array.isArray(args)) fail("arguments must be an object");
  // Own properties only: `key in` would accept prototype names such as toString or constructor.
  for (const key of Object.keys(args)) if (!Object.hasOwn(schema.properties, key)) fail(`unknown argument: ${key}`);
  for (const key of schema.required) if (!Object.hasOwn(args, key)) fail(`missing argument: ${key}`);
  for (const [key, spec] of Object.entries(schema.properties)) {
    if (!Object.hasOwn(args, key)) continue;
    const v = args[key];
    // No coercion anywhere: a nested array would otherwise stringify to "a,b". Provided strings
    // must be non-empty.
    if (spec.type === "string" && (typeof v !== "string" || !v.trim())) fail(`${key} must be a non-empty string`);
    if (spec.enum && !spec.enum.includes(v)) fail(`${key} must be one of ${spec.enum.join(", ")}`);
    if (spec.type === "integer" && (!Number.isInteger(v) || v < spec.minimum || v > spec.maximum)) fail(`${key} out of range`);
    if (spec.type === "number" && (typeof v !== "number" || !Number.isFinite(v) || v < spec.minimum || v > spec.maximum || v !== Number(v.toFixed(2)))) fail(`${key} must be between ${spec.minimum} and ${spec.maximum} with at most two decimals`);
    if (spec.type === "boolean" && typeof v !== "boolean") fail(`${key} must be a boolean`);
    if (spec.type === "array") {
      if (!Array.isArray(v) || v.length > 50) fail(`${key} must be an array of at most 50 paths`);
      for (const item of v) if (typeof item !== "string" || item.includes(",")) fail(`${key} items must be single paths (strings without commas)`);
    }
  }
  if (typeof args.packet_text !== "string" || !args.packet_text.trim() || args.packet_text.length > 200_000)
    fail("packet_text must be non-empty and at most 200,000 characters");
}
function buildArgv(tool, a, packet) {
  const argv = [DISPATCHERS[tool], "run", "--packet", packet];
  const push = (flag, value) => argv.push(flag, plainValue(flag, String(value)));
  push("--cd", a.cd);
  if (a.mode) push("--mode", a.mode);
  for (const p of a.allow || []) push("--allow", p);
  if (a.model) push("--model", a.model);
  if (a.effort) push("--effort", a.effort);
  if (a.timeout_seconds) push("--timeout", a.timeout_seconds);
  // Plain decimal text: String(1e-7) would be "1e-7", which claude_dispatch rejects.
  if (a.max_budget_usd) push("--max-budget-usd", a.max_budget_usd.toFixed(2));
  return argv;
}
// The dispatcher bounds the Claude turn and each Git call itself. As a backstop for anything else
// that hangs (for example a repository Git filter), the dispatcher runs inside its own JobRun: a
// kill-on-close Job Object that holds every descendant, including the dispatcher's own JobRun for
// Claude (nested jobs). Stopping it is a write to JobRun's control pipe, never a PID lookup, so a
// reused PID cannot be targeted. When the dispatcher exits, JobRun terminates whatever is left, and
// if this server dies its control pipe closes and JobRun does the same.
const WATCHDOG_GRACE_MS = 600_000;
const DRAIN_MS = 5_000;      // after JobRun exits, how long to wait for its pipes to close
const KILL_SETTLE_MS = 15_000; // after a watchdog kill request, when to answer regardless
// JobRun's own codes (src/containment/JobRun.cs); the dispatcher never exits with these.
const JOBRUN = { KILLED: 125, UNCONFIRMED: 126, LAUNCH_FAILED: 127 };
function runDispatcher(argv, { jobrun, reportPath, watchdogMs = 0 } = {}) {
  return new Promise(done => {
    if (!jobrun || !reportPath) { done({ code: 7, out: "", err: "internal error: no JobRun launcher" }); return; }
    // Direct argv, no shell; the dispatcher owns timeouts, containment and cleanup of the turn.
    // No inherited Node preloads in the dispatcher either (see withoutNodePreloads).
    const child = spawn(jobrun, ["--report", reportPath, "--", process.execPath, ...argv],
      { cwd: PACKAGE, env: withoutNodePreloads(), windowsHide: true, shell: false, stdio: ["pipe", "pipe", "pipe"] });
    let out = "", err = "", settled = false, watchdogFired = false, outTruncated = false;
    const timers = [];
    // stderr keeps its tail (the newest diagnostics). stdout keeps its head: the dispatcher prints the
    // RESULT block first and Claude's last message at the end, so a long message is what gets cut.
    const cap = (s, chunk) => (s + chunk).slice(-OUTPUT_CAP);
    const head = chunk => {
      if (outTruncated) return;
      out += chunk;
      if (out.length > OUTPUT_CAP) { out = out.slice(0, OUTPUT_CAP); outTruncated = true; }
    };
    const settle = (raw, drained = true) => {
      if (settled) return;
      settled = true;
      for (const t of timers) clearTimeout(t);
      let code = raw ?? 7;
      const notes = [];
      // A drain deadline answers without the pipes having closed: say so.
      if (!drained) notes.push("output may be incomplete: the dispatcher's pipes did not close within the drain bound");
      if (outTruncated) notes.push(`stdout truncated after ${OUTPUT_CAP} characters (the run's evidence holds the full output)`);
      // Success is only ever reported together with the dispatcher's RESULT block.
      if (code === 0 && !/^# RESULT /m.test(out)) { code = 7; notes.push("no RESULT block from the dispatcher"); }
      if (code === JOBRUN.UNCONFIRMED) { code = 5; notes.push("dispatcher process tree teardown unconfirmed"); }
      else if (code === JOBRUN.LAUNCH_FAILED) { code = 7; notes.push("dispatcher launch failed"); }
      else if (code === JOBRUN.KILLED || watchdogFired) { code = watchdogFired ? 6 : 5; notes.push("dispatcher was stopped"); }
      try { const report = JSON.parse(readFileSync(reportPath, "utf8"));
        if (report.confirmed !== true) { if (code === 0) code = 5; notes.push(`JobRun did not confirm teardown: ${report.error || "unknown"}`); } }
      catch { if (code === 0) code = 5; notes.push("JobRun report missing"); }
      rmSync(reportPath, { force: true });
      err = err.replace(/^jobrun_root_pid=\d+\r?\n/, "");
      done({ code, out, err: notes.length ? `${err}\n${notes.join("\n")}` : err });
    };
    child.stdin.on("error", () => {});
    if (watchdogMs > 0) timers.push(setTimeout(() => {
      watchdogFired = true;
      err = cap(err, `\nwatchdog: dispatcher exceeded ${watchdogMs} ms; JobRun asked to terminate its job`);
      try { child.stdin.write("kill\n"); } catch { /* JobRun already gone */ }
      timers.push(setTimeout(() => settle(6, false), KILL_SETTLE_MS));
    }, watchdogMs));
    // Stream decoders keep a UTF-8 character that is split across two pipe chunks intact.
    child.stdout.setEncoding("utf8"); child.stderr.setEncoding("utf8");
    child.stdout.on("data", c => { head(c); });
    child.stderr.on("data", c => { err = cap(err, c); });
    child.on("error", e => { err = cap(err, `\nlaunch failed: ${e.message}`); settle(7); });
    // Answer within a bound even if some pipe never closes.
    child.on("exit", code => { timers.push(setTimeout(() => settle(code, false), DRAIN_MS)); });
    child.on("close", code => settle(code));
  });
}
const MAX_ACTIVE = 2;
let active = 0;
async function callTool(name, args) {
  if (typeof name !== "string" || !Object.hasOwn(DISPATCHERS, name)) fail(`unknown tool: ${name}`);
  checkArgs(name, args);
  if (active >= MAX_ACTIVE) fail(`busy: ${MAX_ACTIVE} dispatches already running; retry when one finishes`);
  // Every argument is validated (argv built once with a placeholder) before anything touches disk.
  const request=parseArgs(buildArgv(name,args,"placeholder.md").slice(1));
  // No inbox packet exists yet. The same complete preflight must finish before the outer
  // launcher is selected; the child repeats it without trusting a caller-supplied ticket.
  request.packet=null;
  const {config,jobrun}=preflight(request,{skipBaseline:true});
  const id = `mcp-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomUUID().slice(0, 8)}`;
  const packet = join(config.packets, `${id}.md`);
  const argv = buildArgv(name, args, packet);
  active++;
  let r;
  try {
    writeFileSync(packet, args.packet_text, { encoding: "utf8", flag: "wx" });
    r = await runDispatcher(argv, { jobrun, reportPath: join(config.runs, `${id}.jobrun.json`),
      watchdogMs: (args.timeout_seconds || 900) * 1000 + WATCHDOG_GRACE_MS });
  } finally {
    active--;
    // The dispatcher keeps its own copy in the run's evidence directory; the inbox copy goes.
    rmSync(packet, { force: true });
  }
  const text = `exit_code: ${r.code}\n--- stdout ---\n${r.out || "(none)"}` +
    (r.err.trim() ? `\n--- stderr ---\n${r.err}` : "");
  return { content: [{ type: "text", text }], isError: r.code !== 0 };
}

async function handle(msg) {
  const invalid = () => { const e = new Error("invalid request"); e.rpc = -32600; return e; };
  if (!msg || typeof msg !== "object" || Array.isArray(msg)) throw invalid();
  if (msg.jsonrpc !== "2.0" || typeof msg.method !== "string" || msg.method.length > 128) throw invalid();
  if (Object.hasOwn(msg, "params") && (msg.params === null || typeof msg.params !== "object" || Array.isArray(msg.params))) throw invalid();
  const { id, method, params } = msg;
  if (method === "initialize") {
    // Never echo client data unchecked: only a date-shaped version string is returned as-is.
    const asked = params?.protocolVersion;
    const version = typeof asked === "string" && /^\d{4}-\d{2}-\d{2}$/.test(asked) ? asked : "2025-06-18";
    return { protocolVersion: version, capabilities: { tools: {} }, serverInfo: SERVER };
  }
  if (method === "ping") return {};
  if (method === "tools/list") return { tools: TOOLS };
  if (method === "tools/call") {
    try { return await callTool(params?.name, params?.arguments ?? {}); }
    catch (e) {
      if (e.userFacing || e.code === 2 || e.code === 3) return { content: [{ type: "text", text: `rejected: ${e.message}` }], isError: true };
      return { content: [{ type: "text", text: `internal error: ${e.message}` }], isError: true };
    }
  }
  if (id === undefined) return undefined; // notification (e.g. notifications/initialized)
  const e = new Error(`method not found: ${method}`); e.rpc = -32601; throw e;
}

export { TOOLS, checkArgs, buildArgv, handle, runDispatcher };

if (import.meta.main) {
  let buffer = "";
  // MCP request ids are strings or integers; anything else is never echoed back.
  const validId = v => (typeof v === "string" && v.length <= 256) || Number.isSafeInteger(v);
  // A closed client pipe ends the session; never crash on a stream error.
  process.stdout.on("error", () => { process.stdin.pause(); process.exit(0); });
  const send = obj => {
    let line;
    try { line = JSON.stringify(obj); }
    catch { line = JSON.stringify({ jsonrpc: "2.0", id: validId(obj?.id) ? obj.id : null, error: { code: -32603, message: "unserializable response" } }); }
    // Backpressure: if the client stops reading, stop reading its input until stdout drains,
    // so queued responses cannot grow without bound.
    if (!process.stdout.write(line + "\n")) {
      process.stdin.pause();
      process.stdout.once("drain", () => process.stdin.resume());
    }
  };
  process.stdin.setEncoding("utf8");
  const MAX_FRAME = 1_000_000; // a packet is capped at 200k characters; this bounds unterminated input
  let discarding = false; // dropping the rest of an oversized frame up to its newline
  process.stdin.on("data", chunk => {
    if (discarding) {
      const nl = chunk.indexOf("\n");
      if (nl < 0) return;
      discarding = false; chunk = chunk.slice(nl + 1);
    }
    buffer += chunk;
    if (buffer.indexOf("\n") < 0 && Buffer.byteLength(buffer) > MAX_FRAME) {
      buffer = ""; discarding = true;
      send({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "frame too large" } });
      return;
    }
    let nl;
    while ((nl = buffer.indexOf("\n")) >= 0) {
      const raw = buffer.slice(0, nl); buffer = buffer.slice(nl + 1);
      // Measure the raw frame before trimming, so padding cannot carry an oversized frame in.
      if (Buffer.byteLength(raw) > MAX_FRAME) {
        send({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "frame too large" } });
        continue;
      }
      const line = raw.trim();
      if (!line) continue;
      let msg;
      try { msg = JSON.parse(line); } catch { send({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }); continue; }
      const isObject = msg && typeof msg === "object" && !Array.isArray(msg);
      if (isObject && Object.hasOwn(msg, "id") && !validId(msg.id)) {
        send({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "invalid request id" } });
        continue;
      }
      const id = isObject && Object.hasOwn(msg, "id") ? msg.id : null;
      handle(msg).then(result => {
        if (id !== null && result !== undefined) send({ jsonrpc: "2.0", id, result });
      }).catch(e => {
        send({ jsonrpc: "2.0", id, error: { code: e.rpc || -32603, message: e.message } });
      });
    }
    // The unfinished remainder after the last newline is bounded too.
    if (Buffer.byteLength(buffer) > MAX_FRAME) {
      buffer = ""; discarding = true;
      send({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "frame too large" } });
    }
  });
}
