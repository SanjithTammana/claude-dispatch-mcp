#!/usr/bin/env node
// Offline tests for the JobRun supervision helpers (src/containment/jobrun.mjs). No JobRun launch.
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import vm from "node:vm";
import { jobrunCleanup, stopJobrun } from "../src/containment/jobrun.mjs";

const dir = mkdtempSync(join(tmpdir(), "cdm-containment-"));
// Windows PIDs are multiples of four, so this one can never be alive.
const DEAD = 999999;
let passed = 0;
function test(name, fn) { fn(); passed++; console.log(`PASS ${name}`); }
try {
  const report = join(dir, "jobrun.json");
  const write = value => writeFileSync(report, typeof value === "string" ? value : JSON.stringify(value));
  const ok = { confirmed: true, active_after: 0, root_pid: 12345, root_exit_code: 0, killed_by: "root_exit" };

  test("accepts matching wrapper exit and launched root PID", () => { write(ok); assert.ok(jobrunCleanup(DEAD, true, report, 0, 12345).ok); });
  test("rejects exit-code/report disagreement", () => { write(ok); assert.ok(!jobrunCleanup(DEAD, true, report, 23, 12345).ok); });
  test("rejects a mismatched launched root PID", () => { write(ok); assert.ok(!jobrunCleanup(DEAD, true, report, 0, 54321).ok); });
  for (const code of [126, 127, null])
    test(`rejects unconfirmed/failed/unobserved wrapper exit ${code}`, () => { write(ok); assert.ok(!jobrunCleanup(DEAD, true, report, code, 12345).ok); });
  test("rejects active descendants", () => { write({ ...ok, active_after: 1 }); assert.ok(!jobrunCleanup(DEAD, true, report, 0, 12345).ok); });
  test("accepts a confirmed kill with exit 125", () => { write({ ...ok, killed_by: "kill_request" }); assert.ok(jobrunCleanup(DEAD, true, report, 125, 12345).ok); });
  test("rejects a kill report paired with the root exit instead of 125", () => { write({ ...ok, killed_by: "kill_request" }); assert.ok(!jobrunCleanup(DEAD, true, report, 0, 12345).ok); });
  test("rejects an absent report", () => { rmSync(report, { force: true }); assert.ok(!jobrunCleanup(DEAD, true, report, 0, 12345).ok); });
  test("rejects a malformed report", () => { write("not JSON"); assert.ok(!jobrunCleanup(DEAD, true, report, 0, 12345).ok); });
  for (const bad of [{ ...ok, confirmed: false }, { ...ok, confirmed: "true" }, { ...ok, killed_by: "other" },
                     { ...ok, root_pid: "12345" }, { ...ok, root_exit_code: 2 ** 33 }])
    test(`rejects unconfirmed or malformed accounting ${JSON.stringify(bad)}`, () => { write(bad); assert.ok(!jobrunCleanup(DEAD, true, report, 0, 12345).ok); });
  test("a confirmed report cannot pass before JobRun exits", () => { write(ok); assert.ok(!jobrunCleanup(DEAD, false, report, 0, 12345).ok); });
  test("a signed report exit code matches its unsigned wrapper exit", () => {
    write({ ...ok, root_exit_code: -1073741510 }); assert.ok(jobrunCleanup(DEAD, true, report, 3221225786, 12345).ok);
  });

  // The emergency stop uses only the child-process handle, never a PID: once JobRun has exited,
  // nothing is killed even if its pipes never close.
  const source = readFileSync(resolve(import.meta.dirname, "..", "src", "containment", "jobrun.mjs"), "utf8");
  test("the supervision code never kills by PID", () => assert.ok(!/taskkill|tasklist|\/PID|process\.kill\(pid,\s*['"]?SIG/i.test(source)));
  const fakeChild = () => { const calls = []; return { calls, child: { pid: 999999, stdin: { destroyed: false, write: l => calls.push(["write", l]) }, kill: s => calls.push(["kill", s]) } }; };
  const never = new Promise(() => {});
  {
    const { calls, child } = fakeChild();
    write(ok);
    await stopJobrun({ child, closed: never, exited: true, exitCode: 0, rootPid: 12345, launchError: "" }, report);
    test("after JobRun has exited, a held pipe never leads to a kill", () => assert.deepEqual(calls, []));
  }
  {
    const { calls, child } = fakeChild();
    await stopJobrun({ child, closed: never, exited: false, exitCode: null, rootPid: 12345, launchError: "" }, report);
    test("a live JobRun that ignores the kill request is terminated through its handle", () =>
      assert.deepEqual(calls, [["write", "kill\n"], ["kill", "SIGKILL"]]));
  }
  console.log(`\n${passed} tests passed`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
