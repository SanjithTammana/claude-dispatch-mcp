#!/usr/bin/env node
// v1 contains Claude with a Windows Job Object; elsewhere every command but --help must refuse.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { join, resolve } from "node:path";

const dispatcher = join(resolve(import.meta.dirname, ".."), "src", "claude_dispatch.mjs");
if (process.platform === "win32") {
  console.log("SKIP non-Windows refusal (running on Windows)\n0 tests passed");
} else {
  // Poisoned legacy test variables must not open any path either.
  const env = { ...process.env, CLAUDE_DISPATCH_TEST_MODE: "1", CLAUDE_DISPATCH_TEST_BINARY: "/bin/true" };
  let passed = 0;
  for (const args of [["doctor"], ["run", "--packet", "p.md", "--cd", "/tmp"]]) {
    const r = spawnSync(process.execPath, [dispatcher, ...args], { encoding: "utf8", env });
    assert.equal(r.status, 2, r.stderr + r.stdout);
    assert.match(r.stderr, /only on Windows/);
    passed++; console.log(`PASS ${args[0]} refuses on ${process.platform}`);
  }
  const help = spawnSync(process.execPath, [dispatcher, "--help"], { encoding: "utf8" });
  assert.equal(help.status, 0); passed++; console.log("PASS --help still works");
  console.log(`\n${passed} tests passed`);
}
