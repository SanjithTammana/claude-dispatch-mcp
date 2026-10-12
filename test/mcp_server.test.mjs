#!/usr/bin/env node
// Offline tests for mcp_server.mjs: protocol, argument allowlist, argv construction. No model call.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { TOOLS, checkArgs, buildArgv, handle, runDispatcher } from "../src/mcp_server.mjs";
import { jobrunPath } from "../src/containment/build.mjs";
import { pipeHolderExe, markerExe } from "./fixtures.mjs";

const SRC = resolve(import.meta.dirname, "..", "src");
// An isolated state directory; nothing here touches a real installation.
const state = mkdtempSync(join(tmpdir(), "cdm-mcp-state-"));
process.env.CLAUDE_DISPATCH_HOME = state;
const jobrun = jobrunPath(join(state, "bin"));
const supervised = name => ({ jobrun, reportPath: join(state, `${name}.jobrun.json`) });
let passed = 0;
async function test(name, fn) { await fn(); passed++; console.log(`PASS ${name}`); }

try {
  await test("tools/list exposes exactly dispatch_claude", async () => {
    const r = await handle({ jsonrpc: "2.0", id: 1, method: "tools/list" });
    assert.deepEqual(r.tools.map(t => t.name), ["dispatch_claude"]);
  });
  await test("no tool exposes verification commands, shared files, test flags or config", async () => {
    for (const t of TOOLS) for (const key of Object.keys(t.inputSchema.properties))
      assert.ok(!/verify|share|fake|test|run_root|network|binary|config|deny|home|state/i.test(key), `${t.name}.${key}`);
  });
  await test("cd is required by the schema", async () => {
    assert.deepEqual([...TOOLS[0].inputSchema.required].sort(), ["cd", "packet_text"]);
  });
  for (const [label, args] of [
    ["unknown argument", { packet_text: "x", cd: "C:\\x", verify_json: "[\"calc\"]" }],
    ["missing packet", { cd: "C:\\x" }],
    ["missing cd", { packet_text: "x" }],
    ["bad enum", { packet_text: "x", cd: "C:\\x", model: "fable" }],
    ["budget too high", { packet_text: "x", cd: "C:\\x", max_budget_usd: 50 }],
    ["budget with three decimals", { packet_text: "x", cd: "C:\\x", max_budget_usd: 0.123 }],
    ["timeout not integer", { packet_text: "x", cd: "C:\\x", timeout_seconds: 1.5 }],
    ["empty packet", { packet_text: "   ", cd: "C:\\x" }],
    ["oversized packet", { packet_text: "x".repeat(200_001), cd: "C:\\x" }],
    ["nested array item", { packet_text: "x", cd: "C:\\x", allow: [["a.txt", "b.txt"]] }],
    ["comma-joined path", { packet_text: "x", cd: "C:\\x", allow: ["a.txt,b.txt"] }],
    ["non-string cd", { packet_text: "x", cd: ["C:\\x"] }],
    ["prototype key", { packet_text: "x", cd: "C:\\x", toString: "y" }],
    ["non-string packet", { packet_text: ["x"], cd: "C:\\x" }],
    ["empty cd", { packet_text: "x", cd: "" }],
  ]) {
    await test(`rejects ${label}`, async () => assert.throws(() => checkArgs("dispatch_claude", args)));
  }
  await test("values that look like flags are rejected at argv build", async () => {
    assert.throws(() => buildArgv("dispatch_claude", { cd: "C:\\x", allow: ["--dangerously-skip-permissions"] }, "p.md"));
    assert.throws(() => buildArgv("dispatch_claude", { cd: "-C" }, "p.md"));
    assert.throws(() => buildArgv("dispatch_claude", { cd: "C:\\a\nb" }, "p.md"));
  });
  await test("claude argv is the dispatcher plus allowlisted flags only", async () => {
    const argv = buildArgv("dispatch_claude", { cd: "C:\\repo", mode: "workspace-write", allow: ["a.txt"],
      model: "haiku", effort: "low", timeout_seconds: 60, max_budget_usd: 0.2 }, "C:\\state\\packets\\p.md");
    assert.equal(argv[0], join(SRC, "claude_dispatch.mjs"));
    assert.deepEqual(argv.slice(1), ["run", "--packet", "C:\\state\\packets\\p.md", "--cd", "C:\\repo",
      "--mode", "workspace-write", "--allow", "a.txt", "--model", "haiku", "--effort", "low", "--timeout", "60",
      "--max-budget-usd", "0.20"]);
  });
  await test("tools/call with bad arguments returns isError without dispatching", async () => {
    const r = await handle({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "dispatch_claude", arguments: { packet_text: "x", cd: "C:\\x", shell: "cmd" } } });
    assert.equal(r.isError, true); assert.match(r.content[0].text, /rejected: unknown argument/);
  });
  await test("tools/call for an unknown tool is rejected", async () => {
    const r = await handle({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "dispatch_opencode", arguments: {} } });
    assert.equal(r.isError, true); assert.match(r.content[0].text, /unknown tool/);
  });
  await test("tools/call without config.json fails before writing a packet or dispatching", async () => {
    const r = await handle({ jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "dispatch_claude", arguments: { packet_text: "x", cd: "C:\\x" } } });
    assert.equal(r.isError, true); assert.match(r.content[0].text, /no config\.json/);
    assert.ok(!existsSync(join(state, "packets")) || readdirSync(join(state, "packets")).length === 0);
  });
  const outside = mkdtempSync(join(tmpdir(), "cdm-mcp-outside-"));
  writeFileSync(join(state, "config.json"), JSON.stringify({ trusted_roots: [outside] }));
  const packetsLeft = () => existsSync(join(state, "packets")) ? readdirSync(join(state, "packets")) : [];
  await test("an argument rejected at argv build writes no packet", async () => {
    const r = await handle({ jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "dispatch_claude",
      arguments: { packet_text: "x".repeat(100_000), cd: "--invalid" } } });
    assert.equal(r.isError, true); assert.match(r.content[0].text, /rejected/);
    assert.deepEqual(packetsLeft(), []);
  });
  await test("repository refusal writes no inbox packet and runs no outer launcher", async () => {
    // The shared preflight now refuses this before the outer launcher or inbox publication.
    const r = await handle({ jsonrpc: "2.0", id: 7, method: "tools/call", params: { name: "dispatch_claude",
      arguments: { packet_text: "probe", cd: outside } } });
    assert.equal(r.isError, true); assert.match(r.content[0].text, /rejected:.*trusted Git repository/);
    assert.deepEqual(packetsLeft(), []);
  });
  await test("a cd that overlaps the state directory is refused before the launcher runs", async () => {
    const r = await handle({ jsonrpc: "2.0", id: 8, method: "tools/call", params: { name: "dispatch_claude",
      arguments: { packet_text: "probe", cd: state } } });
    assert.equal(r.isError, true); assert.match(r.content[0].text, /rejected:.*overlaps the state directory/);
    assert.deepEqual(packetsLeft(), []);
  });
  await test("the inbox packet is removed after a launched fake Claude failure", async () => {
    // Preserve post-launch inbox cleanup coverage despite moving repository refusals earlier.
    const git=(...args)=>{
      const r=spawnSync('git',['-C',outside,...args],{encoding:'utf8'});
      assert.equal(r.status,0,r.stderr);
    };
    git('init','-q');writeFileSync(join(outside,'tracked.txt'),'base');git('add','.');
    git('-c','user.name=Test','-c','user.email=test@example.com','commit','-qm','base');
    const fake=markerExe(state,'fake-claude');
    writeFileSync(join(state,'config.json'),JSON.stringify({trusted_roots:[outside],claude_binary:fake}));
    const r=await handle({jsonrpc:'2.0',id:9,method:'tools/call',params:{name:'dispatch_claude',
      arguments:{packet_text:'probe',cd:outside}}});
    assert.equal(r.isError,true);assert.match(r.content[0].text,/exit_code: 7/);
    assert.ok(existsSync(fake+'.ran'),'fake executable really launched');assert.deepEqual(packetsLeft(),[]);
  });
  rmSync(outside, { recursive: true, force: true });
  await test("output keeps a UTF-8 character split across pipe chunks", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-utf8-"));
    const script = join(dir, "split.mjs");
    // U+20AC is three bytes (e2 82 ac); write them in two separate chunks.
    writeFileSync(script, "process.stdout.write('# RESULT probe\\n');process.stdout.write(Buffer.from([0xe2]));setTimeout(()=>process.stdout.write(Buffer.from([0x82,0xac])),50);");
    try {
      const r = await runDispatcher([script], supervised("utf8"));
      assert.equal(r.out, "# RESULT probe\n€"); assert.equal(r.code, 0, r.err);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
  const alive = pid => { try { process.kill(pid, 0); return true; } catch { return false; } };
  await test("an exited dispatcher whose descendant holds the output pipe settles promptly, descendant killed", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-held-"));
    const pidFile = join(dir, "grandchild.pid"), script = join(dir, "held.mjs");
    writeFileSync(script, `import {spawn} from 'node:child_process';import {writeFileSync} from 'node:fs';
      const c=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{stdio:'inherit'});
      writeFileSync(${JSON.stringify(pidFile)},String(c.pid));process.stdout.write('# RESULT probe\\n',()=>process.exit(0));`);
    try {
      const started = Date.now();
      const r = await runDispatcher([script], supervised("held"));
      assert.ok(Date.now() - started < 12_000, `took ${Date.now() - started} ms`);
      assert.equal(r.code, 0, r.err);
      assert.equal(alive(Number(readFileSync(pidFile, "utf8"))), false, "descendant must die with the job");
    } finally { rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 }); }
  });
  await test("the watchdog stops a hung dispatcher through JobRun and answers within its bound", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-hung-"));
    const script = join(dir, "hung.mjs");
    writeFileSync(script, "setInterval(()=>{},1000);");
    try {
      const started = Date.now();
      const r = await runDispatcher([script], { ...supervised("hung"), watchdogMs: 1500 });
      assert.ok(Date.now() - started < 20_000, `took ${Date.now() - started} ms`);
      assert.equal(r.code, 6, r.err); assert.match(r.err, /watchdog/);
    } finally { rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 }); }
  });
  await test("the dispatcher's own JobRun for Claude works nested inside the server's JobRun", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-nested-"));
    const script = join(dir, "nested.mjs");
    // Like claude_dispatch.mjs, keep the inner JobRun's control pipe open: EOF on it means "stop".
    writeFileSync(script, `import {spawn} from 'node:child_process';
      const c=spawn(${JSON.stringify(jobrun)},['--report',${JSON.stringify(join(dir, "inner.json"))},'--',process.execPath,'-e','console.log("inner ok")'],{stdio:['pipe','pipe','inherit']});
      let o='';c.stdout.on('data',d=>{o+=d;});c.on('close',code=>{process.stdout.write('# RESULT probe\\n'+o,()=>process.exit(code));});`);
    try {
      const r = await runDispatcher([script], supervised("nested"));
      assert.equal(r.code, 0, r.err); assert.match(r.out, /inner ok/);
      assert.equal(JSON.parse(readFileSync(join(dir, "inner.json"), "utf8")).confirmed, true);
    } finally { rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 }); }
  });
  // Drain deadline: the launcher exits but something still holds its output pipe open.
  for (const [label, stdout, expected] of [
    ["no RESULT block arrived: a failure, never success", "partial", 7],
    ["a RESULT block arrived: its code stands, with the incomplete-output note", "# RESULT probe\nstatus: completed\n", 0],
  ]) {
    await test(`drain deadline, ${label}`, async () => {
      const dir = mkdtempSync(join(tmpdir(), "mcp-drain-"));
      const fake = pipeHolderExe(dir, "holder", stdout);
      const reportPath = join(dir, "report.json");
      let childPid = null;
      try {
        const started = Date.now();
        const r = await runDispatcher(["unused.mjs"], { jobrun: fake, reportPath });
        childPid = Number(readFileSync(reportPath + ".child", "utf8"));
        assert.ok(Date.now() - started < 20_000, `took ${Date.now() - started} ms`);
        assert.equal(r.code, expected, r.err); assert.match(r.err, /output may be incomplete/);
      } finally {
        try { if (childPid) process.kill(childPid); } catch { /* already gone */ }
        rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 300 });
      }
    });
  }
  await test("the server never kills by PID", async () => {
    const source = readFileSync(join(SRC, "mcp_server.mjs"), "utf8");
    assert.ok(!/taskkill|process\.kill|\/PID/.test(source));
  });
  await test("stdio protocol: initialize, initialized notification, tools/list, malformed input", async () => {
    const child = spawn(process.execPath, [join(SRC, "mcp_server.mjs")], { stdio: ["pipe", "pipe", "inherit"] });
    let out = "";
    child.stdout.on("data", c => { out += c; });
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18" } }) + "\n");
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list" }) + "\n");
    child.stdin.write("not json\n");
    for (const bad of ["null", "42", "[1,2]", "\"str\""]) child.stdin.write(bad + "\n");
    // A deeply nested id must be rejected, never echoed (echoing overflowed JSON.stringify).
    child.stdin.write(`{"jsonrpc":"2.0","id":${"[".repeat(10000)}${"]".repeat(10000)},"method":"ping"}\n`);
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: { a: 1 }, method: "ping" }) + "\n");
    child.stdin.write(JSON.stringify({ jsonrpc: "2.0", id: 9, method: "ping" }) + "\n");
    await new Promise(r => setTimeout(r, 800));
    assert.equal(child.exitCode, null, "server must survive malformed requests");
    child.stdin.end(); child.kill();
    const lines = out.trim().split("\n").map(l => JSON.parse(l));
    assert.ok(lines.some(l => l.id === 9 && l.result), "ping after malformed input succeeds");
    assert.ok(lines.filter(l => l.error?.code === -32600).length >= 4);
    assert.equal(lines.find(l => l.id === 1).result.serverInfo.name, "claude-dispatch-mcp");
    assert.equal(lines.find(l => l.id === 2).result.tools.length, 1);
    assert.ok(lines.some(l => l.error?.code === -32700));
    assert.ok(!lines.some(l => l.id === undefined && l.result));
  });
  await test("an oversized unterminated frame is rejected and the server keeps serving", async () => {
    const child = spawn(process.execPath, [join(SRC, "mcp_server.mjs")], { stdio: ["pipe", "pipe", "inherit"] });
    let out = "";
    child.stdout.on("data", c => { out += c; });
    child.stdin.write("x".repeat(1_100_000));
    child.stdin.write("\n" + JSON.stringify({ jsonrpc: "2.0", id: 5, method: "ping" }) + "\n");
    await new Promise(r => setTimeout(r, 800));
    child.stdin.end(); child.kill();
    const lines = out.trim().split("\n").map(l => JSON.parse(l));
    assert.ok(lines.some(l => l.error?.message === "frame too large"));
    assert.ok(lines.some(l => l.id === 5 && l.result));
  });
  await test("the dispatcher is launched without inherited Node preload variables", async () => {
    const dir = mkdtempSync(join(tmpdir(), "mcp-preload-"));
    const script = join(dir, "env.mjs");
    writeFileSync(script, "process.stdout.write('# RESULT probe\\n'+JSON.stringify({o:process.env.NODE_OPTIONS ?? null,p:process.env.NODE_PATH ?? null}));");
    const saved = { o: process.env.NODE_OPTIONS, p: process.env.NODE_PATH };
    // A preload that would fail to resolve: if it were inherited, the child could not even start.
    process.env.NODE_OPTIONS = "--require ./definitely-missing-preload.cjs"; process.env.NODE_PATH = dir;
    try {
      const r = await runDispatcher([script], supervised("preload"));
      assert.equal(r.code, 0, r.err); assert.deepEqual(JSON.parse(r.out.split("\n")[1]), { o: null, p: null });
    } finally {
      if (saved.o === undefined) delete process.env.NODE_OPTIONS; else process.env.NODE_OPTIONS = saved.o;
      if (saved.p === undefined) delete process.env.NODE_PATH; else process.env.NODE_PATH = saved.p;
      rmSync(dir, { recursive: true, force: true });
    }
  });
  // Final review, confirmation round: success always carries the dispatcher's RESULT block.
  for (const [label, body, expected, pattern] of [
    ["a clean exit without a RESULT block is a failure", "process.stdout.write('partial');", 7, /no RESULT block/],
    ["a very long last message is cut from the end, keeping the RESULT block",
      "process.stdout.write('# RESULT probe\\nstatus: completed\\n'+'m'.repeat(300000));", 0, /stdout truncated/],
  ]) {
    await test(label, async () => {
      const dir = mkdtempSync(join(tmpdir(), "mcp-result-"));
      const script = join(dir, "out.mjs");
      writeFileSync(script, body);
      try {
        const r = await runDispatcher([script], supervised("result"));
        assert.equal(r.code, expected, r.err); assert.match(r.err, pattern);
        if (expected === 0) { assert.ok(r.out.startsWith("# RESULT probe\nstatus: completed\n")); assert.equal(r.out.length, 200_000); }
      } finally { rmSync(dir, { recursive: true, force: true }); }
    });
  }
  console.log(`${passed} tests passed`);
} finally {
  rmSync(state, { recursive: true, force: true });
}
