#!/usr/bin/env node
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { copyFileSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";
import { jobrunPath } from "../src/containment/build.mjs";
import { createHash } from "node:crypto";

const dir = mkdtempSync(join(tmpdir(), "jobrun-test-"));
const bin = join(dir, "bin");
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
function alive(pid) { try { process.kill(pid, 0); return true; } catch { return false; } }
let passed = 0;
let grandchild;
try {
  const exe = jobrunPath(bin);
  assert.equal(jobrunPath(bin), exe, "build must be idempotent");
  const originalBinary = readFileSync(exe);
  // A published cache is never repaired automatically (a stale repair could evict a valid
  // publication another caller already returned); a tampered cache must fail closed instead.
  try {
    // The tamper write sits inside the try so a failed or partial write is still restored.
    writeFileSync(exe, Buffer.concat([originalBinary, Buffer.from("tampered cache")]));
    assert.throws(() => jobrunPath(bin), /fails its hash check/, "tampered cache must fail closed");
  } finally {
    writeFileSync(exe, originalBinary);  // restore the shared cache for the other suites
  }
  assert.equal(jobrunPath(bin), exe, "restored cache is valid again");
  const restoredHash = createHash("sha256").update(readFileSync(exe)).digest("hex");
  assert.equal(readFileSync(exe + ".sha256", "utf8").trim(), restoredHash);
  console.log("PASS cached executable hash mismatch fails closed"); passed++;
  // A hard link could alias the cached launcher into a writable workspace.
  const alias = join(dir, "alias.exe");
  linkSync(exe, alias);
  try { assert.throws(() => jobrunPath(bin), /fails its hash check/, "hard-linked cache must fail closed"); }
  finally { unlinkSync(alias); }
  assert.equal(jobrunPath(bin), exe, "unlinked cache is valid again");
  console.log("PASS hard-linked cached executable fails closed"); passed++;
  // A junctioned publication directory with a valid exe/sidecar pair must not be accepted.
  const bin2 = join(dir, "bin2"), elsewhere = join(dir, "elsewhere");
  mkdirSync(bin2); mkdirSync(elsewhere);
  copyFileSync(exe, join(elsewhere, basename(exe))); copyFileSync(exe + ".sha256", join(elsewhere, basename(exe) + ".sha256"));
  symlinkSync(elsewhere, join(bin2, basename(dirname(exe))), "junction");
  assert.throws(() => jobrunPath(bin2), /link or not a directory/, "junctioned cache directory must fail closed");
  console.log("PASS junctioned cache publication directory fails closed"); passed++;
  const plantedPath = join(dir, "planted.json");
  const planted = '{"confirmed":true,"active_after":0,"root_pid":12345}';
  const launchedMarker = join(dir, "must-not-launch");
  writeFileSync(plantedPath, planted);
  assert.equal(spawnSync("attrib", ["+R", plantedPath]).status, 0);
  try {
    const refused = spawnSync(exe, ["--report", plantedPath, "--", process.execPath,
      "-e", `require('fs').writeFileSync(${JSON.stringify(launchedMarker)},'launched')`],
      { encoding: "utf8", input: "", windowsHide: true, timeout: 15000 });
    assert.equal(refused.status, 127, refused.stderr);
    assert.equal(existsSync(launchedMarker), false, "existing report must prevent launch");
    assert.equal(readFileSync(plantedPath, "utf8"), planted);
    console.log("PASS pre-planted read-only report refuses launch"); passed++;
  } finally { spawnSync("attrib", ["-R", plantedPath]); }
  async function run(name, target, args, control) {
    const path = join(dir, `${name}.json`);
    const child = spawn(exe, ["--report", path, "--", target, ...args],
                        { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.stdin.on("error", () => {});
    const ended = new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", code => resolve(code));
    });
    const watchdog = setTimeout(() => child.kill(), 15000);
    try {
      if (control) await control(child);
      const code = await ended;
      assert.ok(existsSync(path), `${name}: report missing; ${stderr}`);
      const report = JSON.parse(readFileSync(path, "utf8"));
      if (report.confirmed) {
        assert.equal(stderr.split(/\r?\n/)[0], `jobrun_root_pid=${report.root_pid}`);
      }
      return { code, report, stdout };
    } finally { clearTimeout(watchdog); child.stdin.destroy(); }
  }
  const pidFile = join(dir, "grandchild.pid");
  const b = join(dir, "grandchild.cjs");
  const a = join(dir, "intermediate.cjs");
  const root = join(dir, "root.cjs");
  writeFileSync(b, `require("fs").writeFileSync(process.argv[2],String(process.pid));setTimeout(()=>{},60000);`);
  writeFileSync(a, `const{spawn}=require("child_process");const{existsSync}=require("fs");
const c=spawn(process.execPath,[${JSON.stringify(b)},process.argv[2]],{detached:true,stdio:"ignore"});c.unref();
const t=setInterval(()=>{if(existsSync(process.argv[2])){clearInterval(t);process.exit(0)}},10);`);
  writeFileSync(root, `const{spawn}=require("child_process");
spawn(process.execPath,[${JSON.stringify(a)},process.argv[2]],{stdio:"ignore"}).on("exit",()=>{
console.log("intermediate exited");setTimeout(()=>process.exit(0),500);});`);
  const orphan = await run("orphan", process.execPath, [root, pidFile], async () => {
    const deadline = Date.now() + 8000;
    while (!existsSync(pidFile) && Date.now() < deadline) await sleep(10);
    assert.ok(existsSync(pidFile), "grandchild did not publish its pid");
    grandchild = Number(readFileSync(pidFile, "utf8"));
    assert.ok(alive(grandchild), "grandchild must be alive before root exits");
  });
  assert.equal(orphan.code, 0);
  assert.equal(orphan.report.confirmed, true);
  assert.equal(orphan.report.killed_by, "root_exit");
  assert.equal(orphan.report.active_after, 0);
  assert.ok(orphan.report.descendants_terminated >= 1);
  assert.equal(alive(grandchild), false);
  console.log("PASS root exit kills detached orphan after intermediate exits"); passed++;

  for (const [name, send] of [["kill", c => c.stdin.write("kill\n")],
                              ["eof", c => c.stdin.end()]]) {
    const r = await run(name, process.execPath, ["-e", "console.log('ready');setTimeout(()=>{},60000)"],
      async c => { await new Promise(resolve => c.stdout.once("data", resolve)); send(c); });
    assert.equal(r.code, 125);
    assert.equal(r.report.confirmed, true);
    assert.equal(r.report.active_after, 0);
    assert.equal(r.report.killed_by, name === "kill" ? "kill_request" : "stdin_eof");
    console.log(`PASS ${name} terminates sleeping root with confirmed report`); passed++;
  }
  const missing = await run("missing", join(dir, "nonexistent.exe"), []);
  assert.equal(missing.code, 127);
  assert.equal(missing.report.confirmed, false);
  assert.ok(missing.report.error.includes("CreateProcess"));
  console.log("PASS launch failure is fail closed"); passed++;

  const args = ["", "a b", 'a"b', "a\\", 'a\\\\"b', "line1\nline2", "Unicode \u03bb", "x".repeat(12000)];
  const quoted = await run("quoting", process.execPath,
    ["-e", "console.log(JSON.stringify(process.argv.slice(1)));process.exit(23)", ...args]);
  assert.equal(quoted.code, 23);
  assert.equal(quoted.report.root_exit_code, 23);
  assert.equal(quoted.report.confirmed, true);
  assert.deepEqual(JSON.parse(quoted.stdout), args);
  console.log("PASS Windows argument quoting and nonzero root exit"); passed++;

  const nul = await run("stdin-nul", process.execPath,
    ["-e", "console.log(JSON.stringify(require('fs').readFileSync(0,'utf8')))"]);
  assert.equal(nul.code, 0);
  assert.equal(JSON.parse(nul.stdout), "");
  assert.equal(nul.report.confirmed, true);
  console.log("PASS worker stdin is NUL while JobRun control stdin remains open"); passed++;

  const hardPidFile = join(dir, "hard-grandchild.pid");
  const hardReport = join(dir, "hard.json");
  const hardRoot = `const{spawn}=require("child_process");spawn(process.execPath,`
    + `[${JSON.stringify(a)},${JSON.stringify(hardPidFile)}],{stdio:"ignore"});setTimeout(()=>{},60000);`;
  const hard = spawn(exe, ["--report", hardReport, "--", process.execPath, "-e", hardRoot],
                     { stdio: ["pipe", "ignore", "ignore"] });
  hard.stdin.on("error", () => {});
  const hardClosed = new Promise((resolve, reject) => {
    hard.once("error", reject); hard.once("close", resolve);
  });
  try {
    const deadline = Date.now() + 8000;
    while (!existsSync(hardPidFile) && Date.now() < deadline) await sleep(10);
    assert.ok(existsSync(hardPidFile), "hard-close grandchild did not start");
    grandchild = Number(readFileSync(hardPidFile, "utf8"));
    assert.ok(alive(grandchild), "hard-close grandchild must start alive");
    hard.kill();
    await hardClosed;
    const drained = Date.now() + 5000;
    while (alive(grandchild) && Date.now() < drained) await sleep(20);
    assert.equal(alive(grandchild), false);
    assert.equal(existsSync(hardReport), false, "forced wrapper death cannot certify its own teardown");
    console.log("PASS forced JobRun death kills descendants without fabricating a report"); passed++;
  } finally { hard.stdin.destroy(); }
  console.log(`${passed} passed, 0 failed`);
} finally {
  // Never kill a bare recorded PID: require a fresh positive liveness observation.
  if (grandchild && alive(grandchild)) {
    process.kill(grandchild);
  }
  rmSync(dir, { recursive: true, force: true });
}
