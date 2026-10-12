import { createHash, randomUUID } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, renameSync, rmdirSync, rmSync, writeFileSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const HERE = dirname(fileURLToPath(import.meta.url));
// The actual Windows directory; the preflight validates the compiler's placement before it runs.
const CSC = join(process.env.SystemRoot || process.env.WINDIR || "C:\\Windows",
  "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe");

function binaryHash(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

// The sidecar detects corruption, not an attacker who can write both files; the bin directory's
// protection is that it lies outside every workspace a dispatched turn can write (config.mjs).
// A link could alias the pair into such a workspace, so both must be plain single-link files.
function plainFile(path) {
  const s = lstatSync(path);
  return s.isFile() && !s.isSymbolicLink() && s.nlink === 1;
}
function realDirectory(path) {
  const s = lstatSync(path);
  return s.isDirectory() && !s.isSymbolicLink();
}
// A junctioned publication directory could point the launcher at bytes inside a workspace, so the
// directory chain must be real and the executable's canonical path must be exactly where it belongs.
function validCache(exe, bin) {
  try {
    const dir = dirname(exe);
    return realDirectory(bin) && realDirectory(dir)
      && realpathSync.native(exe) === join(realpathSync.native(bin), basename(dir), basename(exe))
      && plainFile(exe) && plainFile(exe + ".sha256")
      && readFileSync(exe + ".sha256", "utf8").trim() === binaryHash(exe);
  }
  catch { return false; }
}

// Publication is one atomic directory rename: each builder compiles the exe and writes its
// sidecar inside a private temp directory, then renames that directory to the content-addressed
// target. Renaming onto an existing directory fails, so exactly one builder publishes and an exe
// is never paired with another build's sidecar. No lock exists, so none can be stolen or leaked.
export function jobrunPath(bin, {validateCompiler = () => {}} = {}) {
  if (!bin) throw new Error("JobRun build: bin directory required");
  const source = join(HERE, "JobRun.cs");
  const hash = createHash("sha256").update(readFileSync(source)).digest("hex").slice(0, 12);
  const name = `jobrun-${hash}.exe`;  // dispatchers verify the image name matches jobrun-*.exe
  const dir = join(bin, `jobrun-${hash}`);
  const target = join(dir, name);
  if (validCache(target, bin)) return target;
  if (!existsSync(CSC)) throw new Error(`JobRun build: .NET Framework compiler missing: ${CSC}`);
  // The shared preflight validates compiler placement/aliases before any build can execute it.
  validateCompiler(realpathSync.native(CSC));
  mkdirSync(bin, { recursive: true });
  // Never repair a published directory automatically: a builder acting on a stale observation could
  // evict a valid publication another caller already returned. A published
  // directory that fails its hash check only arises from outside tampering, so fail closed.
  if (existsSync(dir)) {
    if (validCache(target, bin)) return target;
    if (!realDirectory(dir))
      throw new Error(`JobRun build: published cache ${dir} is a link or not a directory; remove it to rebuild`);
    // An EMPTY directory is never a publication (a publish renames a populated stage dir) but it
    // blocks every future rename, e.g. after an interrupted delete. Non-recursive rmdir removes it
    // only while empty, so it can never evict a valid publication.
    try { rmdirSync(dir); }
    catch (error) {
      if (validCache(target, bin)) return target;
      throw new Error(`JobRun build: published cache ${dir} fails its hash check; delete that directory to rebuild (${error.code || error.message})`);
    }
  }
  const stage = join(bin, `stage-${hash}-${randomUUID()}`);
  mkdirSync(stage);
  try {
    const staged = join(stage, name);
    const r = spawnSync(CSC, ["/nologo", "/langversion:5", "/platform:x64", "/target:exe",
                             `/out:${staged}`, source], { encoding: "utf8", windowsHide: true, timeout: 120000 });
    if (r.error || r.status !== 0)
      throw new Error(`JobRun build failed: ${r.error?.message || r.stdout || r.stderr || `exit ${r.status}`}`);
    writeFileSync(staged + ".sha256", binaryHash(staged) + "\n", "utf8");
    try { renameSync(stage, dir); }
    catch (error) {
      // Another builder published first; use theirs only if it is a valid pair.
      if (validCache(target, bin)) return target;
      throw new Error(`JobRun build: publish failed and no valid cache present: ${error.message}`);
    }
    if (!validCache(target, bin)) throw new Error(`JobRun build: published binary failed its hash check: ${target}`);
    return target;
  } finally { rmSync(stage, { recursive: true, force: true }); }
}

