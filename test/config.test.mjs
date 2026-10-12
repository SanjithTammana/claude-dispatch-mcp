#!/usr/bin/env node
// Unit tests for the path primitives in src/config.mjs that every placement check relies on.
import assert from "node:assert/strict";
import { linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { hardLinks, localPath, overlaps } from "../src/config.mjs";
import * as paths from 'node:path';
import vm from 'node:vm';

const dir = mkdtempSync(join(tmpdir(), "cdm-config-"));
let passed = 0, skipped = 0;
function test(name, fn) { if(fn() === false) {skipped++;return;} passed++; console.log(`PASS ${name}`); }
try {
  const a = join(dir, "a"), b = join(dir, "b"), inner = join(a, "inner");
  mkdirSync(inner, { recursive: true }); mkdirSync(b);
  test("equal and nested paths overlap; siblings do not", () => {
    assert.ok(overlaps(a, a)); assert.ok(overlaps(a, inner)); assert.ok(overlaps(inner, a)); assert.ok(!overlaps(a, b));
  });
  test("case differences still overlap on Windows", () => assert.ok(overlaps(a.toUpperCase(), inner)));
  test("a path that cannot be examined counts as overlapping (fail closed)", () =>
    assert.ok(overlaps(join(dir, "missing"), b)));
  if (process.platform === "win32") {
    for (const path of ["\\\\server\\share\\tools\\git.exe", "\\\\localhost\\C$\\Program Files\\Git\\cmd\\git.exe",
                        "\\\\?\\C:\\Program Files\\Git\\cmd\\git.exe", "\\\\.\\C:\\x"])
      test(`localPath rejects ${path}`, () => assert.throws(() => localPath(path, "git executable"), /drive-letter/));
    test("localPath accepts a drive-letter path", () => assert.equal(localPath("C:\\x", "p"), "C:\\x"));
  }
  test("hardLinks lists every name of a multiply linked file", () => {
    const file = join(a, "f.txt"), twin = join(b, "twin.txt");
    writeFileSync(file, "x");
    assert.deepEqual(hardLinks(file), [file]);
    try { linkSync(file, twin); }
    catch (error) { if (["EPERM", "EACCES", "ENOTSUP"].includes(error.code)) { console.log("SKIP hard links unavailable ("+error.code+")"); return false; } throw error; }
    const names = hardLinks(file).map(n => n.toLowerCase()).sort();
    assert.deepEqual(names, [file, twin].map(n => n.toLowerCase()).sort());
  });
  // Native link creation can be unavailable in a sandbox. Independently exercise enumeration
  // failure modes with stat/spawn doubles; these do not establish native fsutil compatibility.
  const source=readFileSync(new URL('../src/config.mjs',import.meta.url),'utf8')
    .replace(/^import .*;\r?\n/gm,'').replace(/^export /gm,'');
  function enumeration({stdout='\\tools\\file.exe\r\n\\other place\\file.exe\r\n',status=0,wrongIdentity=false}={}) {
    let spawned=false,validated=false;
    const context={...paths,process:{platform:'win32',env:{}},
      statSync:p=>({dev:1n,ino:wrongIdentity&&p.includes('other place')?2n:1n,nlink:2n}),
      realpathSync:{native:p=>p},spawnSync:(exe,args)=>{
        assert.equal(exe,'C:\\Windows\\System32\\fsutil.exe');assert.equal(args[2],'C:\\tools\\file.exe');
        assert.ok(validated,'helper placement validated before spawn');spawned=true;return{status,stdout,stderr:''};}};
    vm.createContext(context);vm.runInContext(source+'\nthis.hardLinks=hardLinks;',context);
    return{run:()=>context.hardLinks('C:\\tools\\file.exe',()=>{validated=true;}),spawned:()=>spawned};
  }
  test('protected multi-link enumeration preserves absolute names including spaces',()=>
    assert.deepEqual(Array.from(enumeration().run()),['C:\\tools\\file.exe','C:\\other place\\file.exe']));
  test('incomplete protected alias enumeration fails closed',()=>
    assert.throws(enumeration({stdout:'\\tools\\file.exe\r\n'}).run,/cannot list hard links/));
  test('failed fsutil enumeration fails closed',()=>assert.throws(enumeration({status:1}).run,/cannot list hard links/));
  test('an alias with a different file identity fails closed',()=>
    assert.throws(enumeration({wrongIdentity:true}).run,/inconsistent hard-link inventory/));
  test('a duplicated name cannot satisfy the link count',()=>
    assert.throws(enumeration({stdout:'\\tools\\file.exe\r\n\\tools\\file.exe\r\n'}).run,/cannot list hard links/));
  console.log(`\n${passed} tests passed, ${skipped} skipped`);
} finally {
  rmSync(dir, { recursive: true, force: true });
}
