/** Ordered launch preflight shared by CLI and MCP.
 * Invariants:
 * 1. Configuration parsing is filesystem-only. Executable placement and hard-link inventories
 *    precede the FIRST Git execution (including discovery/config reads).
 * 2. Git may inspect config without includes, index metadata and path names before workspace
 *    guards; no Git command reads/normalizes workspace contents. Links, populated submodules
 *    and nested repositories are refused before baseline/content reads or launcher selection.
 * 3. State, package, Node, Git, Claude and launcher are disjoint from the actual worktree and
 *    trusted roots. The outer MCP launcher cannot rely on checks performed by its future child.
 * 4. No audit uses code written by the turn. Both entry points repeat this pipeline; no caller
 *    supplied preflight ticket can skip it. Post-turn scope runs only after confirmed teardown.
 */
import {existsSync,lstatSync,opendirSync,readFileSync,readdirSync,realpathSync,statSync} from 'node:fs';
import {dirname,isAbsolute,join,relative,resolve,sep} from 'node:path';
import {loadConfig,localPath,overlaps,hardLinks} from './config.mjs';
import {gitPhase,gitExecutable,submodules,setGitTimeout} from './git_audit.mjs';
import {inventory,snapshot,requireClean,DEFAULT_LEAF_LIMIT,SNAPSHOT_MS} from './raw_audit.mjs';
import {jobrunPath} from './containment/build.mjs';
// Resolve only inside the ordered pipeline: importing CLI/MCP must not perform native probes.
let PACKAGE;
function fail(message,code=2) {throw Object.assign(new Error(message),{code,userFacing:true});}
function inside(path, root) {
  const r = relative(root, path);
  return !isAbsolute(r) && r !== '..' && !r.startsWith(`..${sep}`);
}
function noTraversal(raw) {
  if (raw.split(/[\\/]/).includes('..') || raw.includes('\0')) fail(`path traversal forbidden: ${raw}`);
}
function realExisting(raw) {
  noTraversal(raw);
  let real;
  try { real = realpathSync.native(resolve(raw)); }
  catch (error) { fail(`path unavailable: ${raw} (${error.code})`); }
  return localPath(real, 'path');
}
function trustedRoots(config) {
  localPath(PACKAGE, 'package directory');
  const gitBinary = localPath(gitExecutable(), 'git executable');
  for (const root of config.trustedRoots) {
    if (overlaps(root, PACKAGE)) fail(`trusted root overlaps this package's own code: ${root}`);
    if (overlaps(root, gitBinary)) fail(`git executable lies inside trusted root ${root}: ${gitBinary}`, 7);
  }
  return config.trustedRoots;
}
function repositoryRoot(cd, roots, git) {
  const top = git(cd,['rev-parse','--show-toplevel']);
  const common = git(cd,['rev-parse','--path-format=absolute','--git-common-dir']);
  if (!top.ok || !common.ok) fail(`--cd must belong to a trusted Git repository (${top.err || common.err})`,2);
  const root = realExisting(top.out.trim()), commonDir = realExisting(common.out.trim());
  // An exact registered root needs no Git call on the other roots.
  if (roots.includes(root)) return root;
  for (const trusted of roots) {
    const trustedTop = git(trusted,['rev-parse','--show-toplevel']);
    const trustedCommon = git(trusted,['rev-parse','--path-format=absolute','--git-common-dir']);
    if (!trustedTop.ok || !trustedCommon.ok || realExisting(trustedTop.out.trim()) !== trusted) continue;
    if (commonDir !== realExisting(trustedCommon.out.trim())) continue;
    // A linked worktree has a .git file and a reciprocal registration in common/worktrees.
    const entry = join(root,'.git');
    const gitDir = git(cd,['rev-parse','--absolute-git-dir']);
    if (!gitDir.ok || !lstatSync(entry).isFile() || lstatSync(entry).isSymbolicLink()) continue;
    const admin = realExisting(gitDir.out.trim());
    if (dirname(admin) === join(commonDir,'worktrees')
      && realExisting(readFileSync(join(admin,'gitdir'),'utf8').trim()) === realExisting(entry)) return root;
  }
  fail('--cd Git toplevel is not this repository, a registered trusted root, or its linked worktree');
}
function validatePaths(a, config, git) {
  const roots = trustedRoots(config);
  a.cd = realExisting(a.cd);
  if (!statSync(a.cd).isDirectory()) fail('--cd must be a directory');
  // Before the first Git call in --cd: the executable that call runs must not live there.
  guardWorkspace(a.cd, [['git executable', gitExecutable()]]);
  // Check the Git identity before any status/diff/ls-files command.
  const root = repositoryRoot(a.cd, roots, git);
  // Permission deny rules are cwd-relative, so a --cd inside a protected subtree would turn a
  // pattern such as `**/secrets/**` into a no-op for that subtree. Only a toplevel is allowed.
  if (a.cd !== root) fail('--cd must be exactly a Git toplevel (repository or linked worktree root)');
  guardWorkspace(root, [['state directory', config.home], ['dispatcher package', PACKAGE]]);
  a.allow = a.allow.map(raw => {
    noTraversal(raw);
    const value = raw.replaceAll('\\', '/').replace(/^\.\//, '').replace(/\/+$/, '');
    if (!value || value === '.' || isAbsolute(raw) || /[:*?\[\]]/.test(value)
      || value.split('/').some(p => !p || /[. ]$/.test(p) || p.toLowerCase() === '.git'))
      fail(`--allow must be a relative path without traversal, aliases, globs or .git: ${raw}`);
    const target = resolve(a.cd, value);
    if (!inside(target, a.cd)) fail(`--allow escapes --cd: ${raw}`);
    let ancestor = target;
    // lstat detects dangling links as well; they cannot be treated as future files.
    for (;;) {
      try { lstatSync(ancestor); break; }
      catch (error) {
        if (error.code !== 'ENOENT') fail(`cannot validate --allow: ${raw}`);
        ancestor = dirname(ancestor);
      }
    }
    const real = realExisting(ancestor);
    if (!inside(real, a.cd)) fail(`--allow symlink escapes --cd: ${raw}`);
    // Windows reports ENOENT (not ENOTDIR) for `file/child`; a path through an existing file would
    // let a worker replace a tracked file with a directory of the same name.
    if (ancestor !== target && !lstatSync(ancestor).isDirectory())
      fail(`--allow passes through an existing file: ${raw}`);
    return value;
  });
  return root;
}
// The resolved binary must not live inside a trusted root: a write run could replace it, and the
// next dispatch would execute the replacement with none of these controls.
function resolveClaude(config, testBinary) {
  const binary = localPath(testBinary ? realExisting(testBinary) : findClaude(config), 'Claude binary');
  for (const root of config.trustedRoots)
    if (overlaps(binary, root)) fail(`Claude binary lies inside trusted root ${root}: ${binary}`, 7);
  return binary;
}
// Executables and state the dispatched turn must never be able to write: checked against the
// actual dispatched toplevel, which for a linked worktree may lie outside its registered root.
function guardWorkspace(root, paths) {
  for (const [label, path] of paths)
    if (overlaps(root, path)) fail(`--cd overlaps the ${label}: ${path}`, 2);
}
// The boundary's own source. A link or junction anywhere in it could point an import at code
// outside this inventory, so the tree must be plain directories and files only.
function packageFiles(dir = join(PACKAGE, 'src')) {
  if (lstatSync(dir).isSymbolicLink()) fail(`package source contains a link: ${dir}`, 2);
  return readdirSync(dir, {withFileTypes:true}).flatMap(e => {
    const path = join(dir, e.name);
    if (e.isSymbolicLink()) fail(`package source contains a link: ${path}`, 2);
    if (e.isDirectory()) return packageFiles(path);
    if (e.isFile()) return [path];
    fail(`package source contains an unsupported entry: ${path}`, 2);
  });
}
// A file with several names shares its contents with every other name: an in-place edit of an
// allowed path could rewrite something outside the repository (evidence, credentials, code), and a
// read could expose it under an innocuous name that no deny pattern matches. Every file Git tracks
// or reports as untracked must therefore have exactly one name. Ignored trees are not walked
// (write mode requires there be none; see THREAT_MODEL.md for read-only).
// The listing is non-recursive and reads only the index and directory entries: it runs no filter.
// A directory in it is a populated submodule or a nested repository. Its files would escape this
// scan, and status would recurse into it with that repository's own (unneutralized) configuration,
// so it is refused in both modes. This check runs before any status or diff.
function guardWorkspaceLinks(root, limit, git) {
  let listed;
  try { listed = inventory(root,git); } catch(e) { fail('cannot establish audit baseline: '+e.message,3); }
  const paths = [...new Set([...listed.index.map(e=>e.path),...listed.others])];
  if (listed.index.length+listed.others.length+listed.ignored.length > limit)
    fail('cannot establish audit baseline: workspace inventory exceeds entry limit',3);
  // Bounded like the raw snapshot: each ancestor directory is inspected once, the total number of
  // inspections is capped, and a deadline applies (this runs before any watchdog exists in MCP).
  const checkedDirs = new Set(), deadline = Date.now() + SNAPSHOT_MS;
  let inspections = 0;
  for (const rel of paths) {
    const parts = rel.split('/');
    for (let i=1;i<=parts.length;i++) {
      const prefix = parts.slice(0,i).join('/');
      if (i<parts.length && checkedDirs.has(prefix)) continue;
      if (++inspections > 2*limit || Date.now() >= deadline)
        fail('cannot establish audit baseline: workspace link scan exceeds its inspection limit',3);
      const path = join(root,...parts.slice(0,i));
      let s;
      try {s=lstatSync(path);} catch(e) {if(e.code==='ENOENT'||e.code==='ENOTDIR') break;fail('cannot inspect workspace file '+rel+': '+e.code);}
      if (i<parts.length && s.isDirectory() && !s.isSymbolicLink()) checkedDirs.add(prefix);
      if(s.isSymbolicLink()) fail('workspace contains a link: '+rel);
      if(s.isFile() && s.nlink!==1) fail('workspace file has '+s.nlink+' hard links (aliases are refused): '+rel);
      if(i===parts.length && s.isDirectory()) {
        const h=opendirSync(path);let first;try {first=h.readSync();}finally {h.closeSync();}
        if(first) fail('populated submodule or nested repository refused: '+rel);
      } else if(!s.isFile()&&!s.isDirectory()) fail('unsupported workspace file: '+rel);
    }
  }
}
// A write turn edits files in place, so a pre-existing hard link from the workspace to boundary
// code or an executable would let an allowed edit rewrite it while Git reports only the allowed
// path. Every name of every protected file must lie outside the workspace.
function guardHardLinks(root, files, names) {
  for (const file of files) {
    const s=lstatSync(file);
    if(!s.isFile() || s.isSymbolicLink()) fail('protected file must be regular: '+file);
    for(const alias of names(file))
      if(overlaps(root,alias)) fail('protected file hard link overlaps workspace: '+alias);
  }
}
function findClaude(config) {
  if (config.claudeBinary) {
    // One native executable: no command string, script wrapper or PATH lookup.
    const binary = realExisting(config.claudeBinary);
    if (!statSync(binary).isFile() || !/\.exe$/i.test(binary))
      fail(`config.json claude_binary must be an existing .exe file: ${binary}`, 7);
    return binary;
  }
  const profile = process.env.USERPROFILE;
  if (!profile) fail('USERPROFILE missing; cannot resolve the Claude binary', 7);
  const local = join(profile, '.local/bin/claude.exe');
  if (existsSync(local) && statSync(local).isFile()) return realpathSync.native(local);
  const packages = join(profile, 'AppData/Local/Microsoft/WinGet/Packages');
  if (existsSync(packages)) {
    const candidates = readdirSync(packages).filter(name => /^Anthropic\.ClaudeCode_/i.test(name)).sort().reverse();
    for (const name of candidates) {
      const dir = join(packages, name);
      for (const candidate of [join(dir, 'claude.exe'), ...readdirSync(dir, {withFileTypes:true})
        .filter(e => e.isDirectory()).map(e => join(dir,e.name,'claude.exe'))]) {
        if (existsSync(candidate) && statSync(candidate).isFile()) return realpathSync.native(candidate);
      }
    }
  }
  fail('claude.exe not found in ~/.local/bin or the WinGet package path; set claude_binary in config.json', 7);
}

function validatePacket(a,config) {
  noTraversal(a.packet);
  const packet = resolve(a.packet);
  if (dirname(packet) !== config.packets || !packet.endsWith('.md'))
    fail(`--packet must be a regular .md file directly inside ${config.packets}`);
  let packetStat;
  try { packetStat = lstatSync(packet); } catch { fail('--packet is unavailable'); }
  if (!packetStat.isFile() || packetStat.isSymbolicLink() || packetStat.nlink !== 1)
    fail('--packet must be a regular .md file without links');
  a.packet = packet;
}
// Filesystem ancestry replaces the Git state-in-repository probe. Includes cannot redirect this
// test; discovery cannot run before placement validation. Bare repositories are refused too.
function guardState(home) {
  for(let p=home;;p=dirname(p)) {
    if(existsSync(join(p,'.git')) || (existsSync(join(p,'HEAD')) && existsSync(join(p,'objects')) && existsSync(join(p,'config'))))
      fail('state directory lies inside a Git repository: '+p);
    if(dirname(p)===p) break;
  }
}
export const PREFLIGHT_ORDER=Object.freeze(['platform','config','placement','state','repository','workspace-links','submodules','baseline','executables','launcher']);
export function preflight(a, options={}) {
  const stage=name=>options.onStage?.(name);
  stage('platform');
  if(process.platform!=='win32') fail('claude-dispatch-mcp v1 runs only on Windows (no containment elsewhere)');
  setGitTimeout(options.gitTimeoutMs);
  stage('config');
  const config=options.config ?? loadConfig(undefined,a.cd);
  stage('placement');
  PACKAGE=localPath(realpathSync.native(resolve(import.meta.dirname,'..')),'package directory');
  const roots=trustedRoots(config);
  const workspace=a.cd ? realExisting(a.cd) : null;
  const node=localPath(realpathSync.native(process.execPath),'node executable');
  const files=packageFiles();
  const protectedFiles=[...files,node,localPath(gitExecutable(),'git executable')];
  const aliases=new Map();
  const names=file=>{
    if(!aliases.has(file)) {
      try { aliases.set(file,hardLinks(file,utility=>{
        localPath(utility,'fsutil executable');
        if(!lstatSync(utility).isFile()) fail('fsutil must be a regular executable');
        for(const place of [...roots,config.home,PACKAGE,...(workspace?[workspace]:[])])
          if(overlaps(utility,place)) fail('fsutil executable overlaps a protected boundary: '+place);
      })); } catch(e) { fail('cannot validate protected hard links: '+e.message); }
    }
    return aliases.get(file);
  };
  // Git for Windows intentionally hard-links its builtins. Enumerate every name, fail closed
  // if enumeration is incomplete, and prove every alias disjoint before executing Git.
  for(const file of protectedFiles) {
    const s=lstatSync(file);
    if(!s.isFile() || s.isSymbolicLink()) fail('protected file must be regular: '+file);
    for(const alias of names(file)) for(const root of roots)
      if(overlaps(alias,root)) fail('protected file hard link lies inside trusted root '+root);
  }
  if(workspace) {
    guardWorkspace(workspace,[['state directory',config.home],['dispatcher package',PACKAGE],['git executable',gitExecutable()],['node executable',node]]);
    guardHardLinks(workspace,protectedFiles,names);
  }
  stage('state');guardState(config.home);
  stage('repository');
  const git=gitPhase();
  let root=null,before=null;
  const limit=options.leafLimit>0?options.leafLimit:DEFAULT_LEAF_LIMIT;
  if(a.command!=='doctor') {
    root=validatePaths(a,config,git);
    if(a.packet) validatePacket(a,config);
  }
  stage('workspace-links');if(root) guardWorkspaceLinks(root,limit,git);
  stage('submodules');
  if(root && a.mode==='workspace-write') {
    const subs=submodules(root,git);
    if(subs.error) fail('cannot list submodules: '+subs.error,3);
    if(subs.paths.length) fail('workspace-write refuses repositories with submodules: '+subs.paths.slice(0,10).join(', '),3);
  }
  stage('baseline');
  // The MCP server runs this preflight only to validate everything before it executes its outer
  // launcher; it never audits, so it skips the snapshot (the dispatcher child takes the real one
  // and enforces write-mode cleanliness). Skipping gates nothing: no later stage reads `before`.
  if(root && options.skipBaseline!==true) {
    before=snapshot(root,a.mode,limit,git);
    if(before.error || before.hidden.length) fail('cannot establish audit baseline: '+(before.error || 'hidden index flags'),3);
    if(a.mode==='workspace-write') try {requireClean(root,before,git);} catch(e) {fail(e.message,3);}
  }
  stage('executables');
  const binary=resolveClaude(config,options.testBinary);
  for(const file of [binary]) for(const trusted of roots)
    if(overlaps(file,trusted)) fail('Claude binary lies inside trusted root '+trusted,7);
  for(const trusted of roots) guardHardLinks(trusted,[binary],names);
  if(root) {guardWorkspace(root,[['Claude binary',binary]]);guardHardLinks(root,[binary],names);}
  stage('launcher');
  const jobrun=jobrunPath(config.bin,{validateCompiler:compiler=>{
    localPath(compiler,'C# compiler');
    for(const trusted of roots) guardHardLinks(trusted,[compiler],names);
    if(root) guardHardLinks(root,[compiler],names);
  }});
  if(root) guardHardLinks(root,[jobrun,jobrun+'.sha256'],names);
  return {config,root,before,binary,node,jobrun,limit};
}
