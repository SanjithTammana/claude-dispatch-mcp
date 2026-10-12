/** Raw scope inventory. Git supplies names and immutable object IDs, never change classification.
 * Each file is recorded by its raw filesystem metadata (see recordFile); no content is read.
 * No symlink/junction is followed, including ancestors of an indexed path. The walk is bounded;
 * an uninspectable path, oversized tree, ambiguous name or unsupported type makes scope UNKNOWN.
 */
import { lstatSync, opendirSync, readlinkSync } from 'node:fs';
import { isAbsolute, join, resolve, relative, sep } from 'node:path';
import { git, hiddenIndexFlags } from './git_audit.mjs';

export const DEFAULT_LEAF_LIMIT = 20000;
export const SNAPSHOT_MS = 120000;
const problem = message => { throw new Error(message); };

function names(root, args, runner) {
  const r = runner(root, args);
  if (!r.ok) problem(r.err || `git ${args[0]} failed`);
  return r.out.split('\0').filter(Boolean);
}
function safeName(root, raw) {
  const p = raw.replace(/\/+$/, '');
  // Windows aliases, ADS and Git administrative paths must not enter the inventory.
  if (!p || /[\\:\r\n\ufffd]/.test(p) || isAbsolute(p)
    || p.split('/').some(s => !s || s === '.' || s === '..' || /[. ]$/.test(s) || s.toLowerCase() === '.git'))
    problem(`unsupported workspace path: ${JSON.stringify(raw)}`);
  const r = relative(root, resolve(root, p));
  if (isAbsolute(r) || r === '..' || r.startsWith(`..${sep}`)) problem(`path escapes workspace: ${raw}`);
  return p;
}
export function inventory(root, runner = git) {
  const index = names(root, ['ls-files','--stage','-z'], runner).map(row => {
    const m = row.match(/^(\d{6}) ([0-9a-f]{40}|[0-9a-f]{64}) ([0-3])\t([\s\S]+)$/);
    if (!m) problem('unrepresentable Git index entry');
    return {mode:m[1], oid:m[2], stage:m[3], path:safeName(root,m[4])};
  });
  const others = names(root, ['ls-files','-z','--others','--exclude-standard'], runner)
    .map(p => safeName(root,p));
  const ignored = names(root, ['ls-files','-z','--others','--ignored','--exclude-standard','--directory'], runner)
    .map(p => safeName(root,p));
  return {index, others, ignored};
}
function boundedNames(path, budget, overdue = () => false) {
  const h = opendirSync(path), out = [];
  try {
    for (let e; (e = h.readSync()) !== null;) {
      if (out.length >= budget) problem('workspace tree exceeds entry limit');
      if (overdue()) problem('workspace tree exceeds audit limit');
      out.push(e.name);
    }
  } finally { h.closeSync(); }
  if (overdue()) problem('workspace tree exceeds audit limit');
  return out.sort();
}
// A file's record is its raw filesystem metadata, never its bytes. The turn can change files only
// through Claude's Edit and Write tools, and every such write updates the last-write and change
// times (100 ns resolution on NTFS); neither tool can set timestamps, and replacing a file changes
// its file ID. Comparing size, both times, creation time and file ID therefore detects every write
// a turn can make, including ones Git's own normalization hides (ident, eol), without reading any
// content: no byte limits, and large repositories stay auditable. Access time is excluded (reads
// update it).
function recordFile(path) {
  const s = lstatSync(path, {bigint:true});
  if (!s.isFile() || s.isSymbolicLink()) problem(`file changed during raw audit: ${path}`);
  return {type:'file', link:false, nlink:Number(s.nlink), mode:Number(s.mode & 0o777n), size:String(s.size),
    mtime:String(s.mtimeNs), ctime:String(s.ctimeNs), birth:String(s.birthtimeNs), id:`${s.dev}:${s.ino}`};
}

export function snapshot(root, mode = 'workspace-write', limit = DEFAULT_LEAF_LIMIT, runner = git, bounds = {}) {
  const records = new Map();
  try {
    const listed = inventory(root,runner);
    if (listed.index.length + listed.others.length + listed.ignored.length > limit) problem('workspace inventory exceeds entry limit');
    const hidden = hiddenIndexFlags(root,runner);
    if (hidden.error) problem(hidden.error);
    const head = runner(root,['rev-parse','HEAD']);
    if (!head.ok) problem(head.err);
    // Tests can lower bounds; no caller can raise the production ceiling.
    const lower=(n,max)=>Number.isFinite(n)&&n>=0?Math.min(n,max):max;
    const budget = {entries:0,deadline:Date.now()+lower(bounds.ms,SNAPSHOT_MS)};
    // Every filesystem inspection, ancestors included, is charged to the same entry budget and
    // deadline; a plain-directory ancestor is inspected once and then cached. The deadline is checked
    // before and after each operation, during directory enumeration, and before returning. A single
    // synchronous call that blocks is bounded only by the MCP watchdog (THREAT_MODEL limit 14).
    const overdue = () => Date.now() >= budget.deadline;
    const charge = () => {
      if (++budget.entries > limit || overdue()) problem('workspace tree exceeds audit limit');
    };
    const onTime = () => { if (overdue()) problem('workspace tree exceeds audit limit'); };
    const plainDirs = new Set();
    function inspect(p, recurse = false) {
      if (records.has(p)) return;
      charge();
      const parts = p.split('/');
      // Record an obstructing ancestor as well as the blocked child. Never read through a link.
      for (let i = 1; i < parts.length; i++) {
        const parent = parts.slice(0,i).join('/');
        if (plainDirs.has(parent)) continue;
        charge();
        let s;
        try { s = lstatSync(join(root,parent)); }
        catch (e) { if (e.code === 'ENOENT' || e.code === 'ENOTDIR') { records.set(p,{type:'missing',link:false}); return; } throw e; }
        onTime();
        if (s.isSymbolicLink() || !s.isDirectory()) {
          inspect(parent);
          records.set(p,{type:'blocked',link:s.isSymbolicLink()}); return;
        }
        plainDirs.add(parent);
      }
      const path = join(root,p);
      let s;
      try { s = lstatSync(path); }
      catch (e) { if (e.code === 'ENOENT' || e.code === 'ENOTDIR') {records.set(p,{type:'missing',link:false});return;} throw e; }
      onTime();
      if (s.isSymbolicLink()) { records.set(p,{type:'link',link:true,target:readlinkSync(path)}); onTime(); return; }
      if (s.isFile()) {records.set(p,recordFile(path));onTime();return;}
      if (!s.isDirectory()) problem(`unsupported file type: ${p}`);
      records.set(p,{type:'directory',link:false});
      if (recurse) {
        const children = boundedNames(path,limit-budget.entries,overdue);
        for (const child of children) inspect(safeName(root,`${p}/${child}`),true);
      }
    }
    for (const p of [...new Set([...listed.index.map(e=>e.path),...listed.others])].sort()) inspect(p,true);
    for (const p of [...new Set(listed.ignored)].sort()) {
      if (mode === 'read-only') {
        // Do not mask a tracked entry if Git lists a collapsed ignored parent around it.
        if (!records.has(p)) records.set(p,{type:'ignored-listed',link:null});
      } else inspect(p,true);
    }
    onTime();
    return {error:null,...listed,head:head.out.trim(),hidden:hidden.paths,
      records:new Map([...records].sort(([a],[b])=>a.localeCompare(b)))};
  } catch (e) {return {error:`cannot record raw workspace: ${e.message}`, records};}
}

/** Clean metadata baseline: index equals HEAD, no unmerged/hidden/untracked/ignored entries or links.
 * Checkout conversions (autocrlf, eol, ident, filters) need not match the index's blob bytes.
 * Scope is measured against the raw pre-turn bytes, including any existing tracked modifications.
 */
export function requireClean(root, before, runner = git) {
  if (before.error) problem(before.error);
  if (before.hidden.length || before.others.length || before.ignored.length)
    problem('workspace-write requires a clean worktree; pre-existing or hidden paths');
  const tree = names(root,['ls-tree','-r','-z','HEAD'],runner).map(row => {
    const m = row.match(/^(\d{6}) (?:blob|commit) ([0-9a-f]+)\t([\s\S]+)$/);
    if (!m) problem('unsupported HEAD tree entry');
    return `${m[1]} ${m[2]} ${safeName(root,m[3])}`;
  }).sort();
  const index = before.index.map(e=>`${e.mode} ${e.oid} ${e.path}`).sort();
  if (before.index.some(e=>e.stage!=='0') || JSON.stringify(index)!==JSON.stringify(tree))
    problem('workspace-write requires a clean index matching HEAD');
  for (const e of before.index) {
    const r = before.records.get(e.path);
    if (r?.type !== 'file' || r.nlink !== 1)
      problem(`workspace-write requires regular single-link tracked files: ${e.path}`);
  }
}
export function compare(a, before, after) {
  const paths = [...new Set([...before.records.keys(),...after.records.keys()])].sort();
  const changed = paths.filter(p=>JSON.stringify(before.records.get(p))!==JSON.stringify(after.records.get(p)));
  if (before.error || after.error) return {scope_check:'UNKNOWN',files_changed:changed,error_detail:before.error||after.error};
  if (after.hidden.length || after.head!==before.head || JSON.stringify(after.index)!==JSON.stringify(before.index))
    return {scope_check:'VIOLATION',files_changed:changed,error_detail:'worker moved HEAD, changed the index, or hid index paths'};
  const unsafe = [...after.records].filter(([,r])=>r.link===true || (r.type==='file' && r.nlink!==1)).map(([p])=>p);
  const violations = a.mode==='read-only' ? changed : changed.filter(p=>!a.allow.some(v=>p===v||p.startsWith(v+'/')));
  // Parent directories are structural records. Creating an allowed leaf necessarily creates its
  // parents; permit these only when every changed descendant is allowed, and never for a tracked
  // file replaced by a directory. Empty directories remain judged as paths themselves.
  const checked = violations.filter(p=> !(a.mode==='workspace-write' && after.records.get(p)?.type==='directory'
    && !before.index.some(e=>e.path===p) && changed.some(c=>c.startsWith(p+'/'))
    && changed.filter(c=>c.startsWith(p+'/') && after.records.get(c)?.type!=='directory')
      .every(c=>a.allow.some(v=>c===v||c.startsWith(v+'/')))));
  return {scope_check:checked.length||unsafe.length?'VIOLATION':'PASS',files_changed:changed,
    error_detail:checked.length||unsafe.length?`out-of-scope or linked changes: ${[...new Set([...checked,...unsafe])].join(', ')}`:''};
}
