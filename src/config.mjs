/**
 * Machine-local configuration. Nothing here comes from an MCP caller or a task packet.
 *
 * State directory: CLAUDE_DISPATCH_HOME when set (absolute), else %LOCALAPPDATA%\claude-dispatch-mcp.
 * It holds config.json, packets/ (the only place a packet may come from), runs/ (evidence) and bin/
 * (the compiled JobRun launcher). It must sit outside every trusted root: --restricted confines
 * Claude's file tools to its working directory, so a disjoint state directory is unreachable from the
 * dispatched turn, and the dispatched turn can never edit its own trust list or launcher.
 *
 * config.json (all keys optional except trusted_roots):
 *   { "trusted_roots": ["C:\\src\\my-repo"],        // Git toplevels Claude may work in (and their
 *                                                    // linked worktrees)
 *     "claude_binary": "C:\\...\\claude.exe",       // else ~/.local/bin, then the WinGet package path
 *     "extra_deny": ["**\/secrets/**"] }             // extra Read/Edit/Write deny patterns
 */
import { spawnSync } from 'node:child_process';
import { existsSync, lstatSync, mkdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { gitExecutable } from './git_audit.mjs';

export class ConfigError extends Error {
  constructor(message) { super(message); this.code = 2; }
}
const bad = message => { throw new ConfigError(message); };

// Case-insensitive on Windows, where the filesystem is.
function inside(path, root) {
  const fold = s => process.platform === 'win32' ? s.toLowerCase() : s;
  const r = relative(fold(root), fold(path));
  return r === '' || (!isAbsolute(r) && r !== '..' && !r.startsWith(`..${sep}`));
}
// A volume that reports no file ID (ino 0, for example FAT/exFAT) cannot prove disjointness.
function identity(path) {
  const s = statSync(path, { bigint: true });
  if (s.ino === 0n) throw new Error(`no file identity available for ${path}`);
  return `${s.dev}:${s.ino}`;
}
// True when `inner` is `outer` or lies below it by filesystem identity (volume serial + file ID),
// which also catches aliases a string comparison misses.
function containsByIdentity(outer, inner) {
  const target = identity(outer);
  for (let p = inner;; p = dirname(p)) {
    if (identity(p) === target) return true;
    if (dirname(p) === p) return false;
  }
}
/**
 * Whether two existing paths overlap (equal, or one inside the other). Fails closed: a stat error or
 * a missing file identity counts as overlap, so such paths cannot be used as roots or protected files.
 */
export function overlaps(a, b) {
  if (inside(a, b) || inside(b, a)) return true;
  try { return containsByIdentity(a, b) || containsByIdentity(b, a); }
  catch { return true; }
}
// UNC (\\server\share, \\localhost\C$) and device (\\?\, \\.\) paths can alias local paths in
// ways neither comparison sees reliably; v1 accepts only drive-letter paths.
export function localPath(path, label) {
  if (process.platform === 'win32' && !/^[A-Za-z]:[\\/]/.test(path))
    bad(`${label} must be a local drive-letter path (UNC and device paths are not supported): ${path}`);
  return path;
}
/**
 * Every name of a file (its hard links), as absolute paths. A single-link file needs no lookup;
 * otherwise the in-box fsutil lists the names, which are volume-relative. Throws if they cannot be listed.
 */
export function hardLinks(path, validateExecutable = () => {}) {
  const file = statSync(path, {bigint:true});
  if (file.nlink === 1n) return [path];
  // The actual Windows directory; validateExecutable checks its placement before it runs.
  const fsutil = realpathSync.native(join(process.env.SystemRoot || process.env.WINDIR || 'C:\\Windows', 'System32', 'fsutil.exe'));
  validateExecutable(fsutil);
  const r = spawnSync(fsutil, ['hardlink', 'list', path], { encoding: 'utf8', windowsHide: true, timeout: 10_000 });
  const drive = path.slice(0, 2);
  const names = (r.stdout || '').split(/\r?\n/).filter(l => l.startsWith('\\') && !l.startsWith('\\\\'));
  if (r.status !== 0 || r.error || new Set(names).size !== Number(file.nlink))
    throw new Error(`cannot list hard links of ${path}: ${r.error?.message || (r.stderr || r.stdout || '').trim()}`);
  return names.map(name => {
    const absolute = localPath(realpathSync.native(drive + name), 'hard-link name');
    const alias = statSync(absolute, {bigint:true});
    if (file.ino === 0n || alias.ino !== file.ino || alias.dev !== file.dev || alias.nlink !== file.nlink)
      throw new Error(`inconsistent hard-link inventory for ${path}`);
    return absolute;
  });
}
function realDirectory(path, label) {
  let s;
  try { s = lstatSync(path); } catch (error) { bad(`${label} unavailable: ${path} (${error.code})`); }
  if (!s.isDirectory() || s.isSymbolicLink()) bad(`${label} must be a real directory without links: ${path}`);
  return localPath(realpathSync.native(path), label);
}

export function stateDirectory(env = process.env) {
  const raw = env.CLAUDE_DISPATCH_HOME || (env.LOCALAPPDATA && join(env.LOCALAPPDATA, 'claude-dispatch-mcp'));
  if (!raw) bad('cannot locate the state directory: set CLAUDE_DISPATCH_HOME or LOCALAPPDATA');
  if (!isAbsolute(raw) || raw.includes('\0')) bad(`state directory must be an absolute path: ${raw}`);
  return localPath(resolve(raw), 'state directory');
}

/**
 * Creates the state layout if needed and returns validated, canonical paths and settings.
 * `workspace` is the directory the current call targets, when known: Git's location is checked
 * against it before Git first runs.
 */
export function loadConfig(home = stateDirectory(), workspace = null) {
  if (!existsSync(home)) mkdirSync(home, { recursive: true });
  const root = realDirectory(home, 'state directory');
  const file = join(root, 'config.json');
  let raw;
  try {
    const s = lstatSync(file);
    if (!s.isFile() || s.isSymbolicLink() || s.nlink !== 1) bad(`config.json must be a regular file without links: ${file}`);
    raw = JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    if (error instanceof ConfigError) throw error;
    if (error.code === 'ENOENT') bad(`no config.json in ${root}; see README "Configure"`);
    bad(`config.json unreadable: ${error.message}`);
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) bad('config.json must be a JSON object');
  for (const key of Object.keys(raw))
    if (!['trusted_roots', 'claude_binary', 'extra_deny'].includes(key)) bad(`config.json: unknown key ${key}`);
  if (!Array.isArray(raw.trusted_roots) || !raw.trusted_roots.length)
    bad('config.json: trusted_roots must be a non-empty array of absolute paths');
  const trustedRoots = [];
  for (const entry of raw.trusted_roots) {
    if (typeof entry !== 'string' || !isAbsolute(entry) || entry.includes('\0'))
      bad(`config.json: trusted root must be an absolute path: ${entry}`);
    // A missing registered checkout does not disable dispatch into the others.
    if (!existsSync(entry)) continue;
    const real = realDirectory(entry, 'trusted root');
    if (overlaps(root, real))
      bad(`trusted root overlaps the state directory: ${real}`);
    trustedRoots.push(real);
  }
  let claudeBinary = null;
  if (raw.claude_binary !== undefined) {
    if (typeof raw.claude_binary !== 'string' || !isAbsolute(raw.claude_binary))
      bad('config.json: claude_binary must be an absolute path');
    claudeBinary = raw.claude_binary;
  }
  const extraDeny = raw.extra_deny ?? [];
  if (!Array.isArray(extraDeny) || extraDeny.some(p => typeof p !== 'string' || !p || /[()\0]/.test(p)))
    bad('config.json: extra_deny must be an array of non-empty patterns without parentheses');
  // This is filesystem-only placement validation, not a Git probe. Its executable must not be one a dispatched turn could have
  // written: outside every trusted root, the state directory, and the workspace this call targets
  // (which may be a linked worktree outside its root).
  const gitBinary = localPath(gitExecutable(), 'git executable');
  const places = [...trustedRoots.map(r => ['trusted root', r]), ['state directory', root]];
  if (workspace) {
    let real = null;
    try { real = realpathSync.native(workspace); } catch { /* the dispatcher reports a missing workspace */ }
    if (real) places.push(['requested workspace', localPath(real, 'workspace')]);
  }
  for (const [label, place] of places)
    if (overlaps(gitBinary, place)) bad(`git executable lies inside the ${label} ${place}: ${gitBinary}`);
  const dirs = {};
  for (const name of ['packets', 'runs', 'bin']) {
    const path = join(root, name);
    if (!existsSync(path)) mkdirSync(path);
    dirs[name] = realDirectory(path, `state ${name}/`);
  }
  return { home: root, ...dirs, trustedRoots, claudeBinary, extraDeny };
}
