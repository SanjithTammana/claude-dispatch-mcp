/**
 * Bounded Git metadata/path access. Scope decisions compare raw filesystem bytes, not Git diffs.
 * Every Git call, including discovery before containment,
 * goes through git(): the executable is an absolute path found on PATH (never the current directory,
 * where a planted git.exe would otherwise win on Windows), inherited GIT_* variables are dropped,
 * fsmonitor and hooks are disabled, every configured filter driver is emptied (neutralizeFilters),
 * submodule changes are always reported, every call is bounded by a timeout, and the repository is
 * named explicitly as safe.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';

let GIT = null;
let TIMEOUT_MS = 120_000;
export function setGitTimeout(ms) { TIMEOUT_MS = ms > 0 ? ms : 120_000; }

/** The first git.exe in an absolute PATH entry, canonicalized. Relative entries are skipped. */
export function gitExecutable(env = process.env) {
  if (GIT) return GIT;
  const path = env.PATH ?? env.Path ?? '';
  for (const dir of path.split(process.platform === 'win32' ? ';' : ':')) {
    const entry = dir.trim().replace(/^"(.*)"$/, '$1');
    if (!entry || !isAbsolute(entry) || entry.startsWith('\\\\')) continue;
    for (const name of process.platform === 'win32' ? ['git.exe'] : ['git']) {
      const candidate = join(entry, name);
      try { if (existsSync(candidate) && statSync(candidate).isFile()) return (GIT = realpathSync.native(candidate)); }
      catch { /* unreadable PATH entry */ }
    }
  }
  throw Object.assign(new Error('git executable not found in an absolute local PATH entry'), { code: 7 });
}

function run(cwd, args, overrides = []) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (/^GIT_/i.test(key)) delete env[key];
  // Git 2.45 supports a separate global config path; NUL is an empty file on Windows.
  env.GIT_CONFIG_NOSYSTEM = '1';
  env.GIT_CONFIG_GLOBAL = process.platform === 'win32' ? 'NUL' : '/dev/null';
  // Never reach the network or run a transport command. A partial clone fetches missing objects on
  // demand (for example during ls-tree), and a fetch can run a repository-configured
  // core.sshCommand. GIT_NO_LAZY_FETCH (Git 2.44+) stops on-demand fetches; protocol.allow=never
  // below blocks every transport on any Git version. A missing object then fails the call, closed.
  env.GIT_NO_LAZY_FETCH = '1';
  env.GIT_TERMINAL_PROMPT = '0';
  // Keys and values must travel separately. `-c filter.late=driver.clean=` changes the
  // wrong key. Indexed configuration represents the literal '=' in a subsection name.
  env.GIT_CONFIG_COUNT = String(overrides.length);
  overrides.forEach(([key, value], i) => {
    env[`GIT_CONFIG_KEY_${i}`] = key;
    env[`GIT_CONFIG_VALUE_${i}`] = value;
  });
  const r = spawnSync(gitExecutable(), ['-c',`safe.directory=${cwd.replaceAll('\\','/')}`,
    '-c','core.fsmonitor=false','-c',`core.hooksPath=${process.platform === 'win32' ? 'NUL' : '/dev/null'}`,
    '-c','core.longpaths=true',
    // protocol.<name>.allow in repository config would override protocol.allow, so pin each one.
    '-c','protocol.allow=never',...['file','git','ssh','http','https','ext']
      .flatMap(p => ['-c',`protocol.${p}.allow=never`]),
    '-c','core.attributesFile='+ (process.platform === 'win32' ? 'NUL' : '/dev/null'),
    '-C',cwd,...args], {encoding:'utf8',maxBuffer:8 << 20,env,windowsHide:true,timeout:TIMEOUT_MS});
  // ENOBUFS, timeouts and spawn failures leave stderr empty; never let a failed call look error-free.
  const err = r.error?.code === 'ETIMEDOUT' ? `git ${args[0]} timed out after ${TIMEOUT_MS} ms`
    : (r.stderr || '').trim() || r.error?.message || (r.status !== 0 ? `git exit ${r.status ?? r.signal}` : '');
  return {ok:r.status === 0 && !r.error,status:r.status,out:r.stdout || '',err};
}

// Inspect config WITHOUT following includes. A phase owns its configuration map; it is never
// shared across turns. The post-turn phase is created only after confirmed teardown.
// Worktree config is included by Git itself; system/global files are disabled even for this read.
function configuration(cwd) {
  const r = run(cwd, ['config','--no-includes','--null','--name-only','--list']);
  if (!r.ok) throw Object.assign(new Error(`cannot read Git configuration: ${r.err}`), {code:2});
  const keys = r.out.split('\0').filter(Boolean);
  if (keys.length > 20000) throw Object.assign(new Error('too many Git configuration keys'), {code:2});
  const names = new Set();
  for (const key of keys) {
    if (/[\r\n\ufffd]/.test(key)) throw Object.assign(new Error('unrepresentable Git configuration key'), {code:2});
    if (/^(?:include\.path|includeif\..*\.path)$/i.test(key))
      throw Object.assign(new Error('repository Git configuration includes are refused (include.path/includeIf)'), {code:2});
    const m = key.match(/^filter\.(.+)\.(?:clean|smudge|process|required)$/i);
    if (m) names.add(m[1]);
  }
  const overrides = [...names].flatMap(n => ['clean','smudge','process','required']
    .map(k => [`filter.${n}.${k}`, k === 'required' ? 'false' : '']));
  return {names:[...names], overrides};
}
/** Retained public validation helper; there is no mutable filter state to refresh. */
export function neutralizeFilters(cwd) { return configuration(cwd).names; }

export function git(cwd, args, overrides) {
  try { return run(cwd, args, overrides ?? configuration(cwd).overrides); }
  catch (error) { return {ok:false,status:null,out:'',err:error.message}; }
}

/** One config read per root in this phase; every subsequent call gets explicit overrides. */
export function gitPhase() {
  const roots = new Map();
  return (cwd, args) => {
    try {
      if (!roots.has(cwd)) {
        try { roots.set(cwd, configuration(cwd).overrides); }
        catch (error) { roots.set(cwd,error); }
      }
      if (roots.get(cwd) instanceof Error) throw roots.get(cwd);
      return git(cwd, args, roots.get(cwd));
    } catch (error) { return {ok:false,status:null,out:'',err:error.message}; }
  };
}

/**
 * -z parsing, untracked and ignored files, and BOTH endpoints of a rename or copy.
 * --ignore-submodules=none overrides any `ignore=` setting in .gitmodules or config.
 */
export function changedPaths(cwd, gitRunner = git) {
  const r = gitRunner(cwd, ['status','--porcelain=v1','-z','--untracked-files=all','--ignored=matching',
    '--ignore-submodules=none']);
  if (!r.ok) return {paths:[],error:r.err || 'git status failed'};
  const fields = r.out.split('\0').filter(Boolean);
  const paths = [];
  for (let i = 0; i < fields.length; i++) {
    const e = fields[i];
    if (e.length < 4) continue;
    const xy = e.slice(0, 2);
    paths.push(e.slice(3));
    if (xy.includes('R') || xy.includes('C')) {
      if (fields[i + 1]) paths.push(fields[i + 1]);
      i++;
    }
  }
  return {paths,error:null};
}

/** Lowercase status = assume-unchanged, 'S' = skip-worktree: both hide edits from git status. */
export function hiddenIndexFlags(cwd, gitRunner = git) {
  const r = gitRunner(cwd, ['ls-files','-v','-z']);
  if (!r.ok) return {paths:[],error:r.err || 'git ls-files -v failed'};
  return {paths:r.out.split('\0').filter(l => l && (/[a-z]/.test(l[0]) || l[0] === 'S'))
    .map(l => l.slice(2)),error:null};
}

/** Gitlinks (mode 160000): a submodule's worktree is a separate repository this audit does not walk. */
export function submodules(cwd, gitRunner = git) {
  const r = gitRunner(cwd, ['ls-files','-s','-z']);
  if (!r.ok) return {paths:[],error:r.err || 'git ls-files -s failed'};
  const paths = r.out.split('\0').filter(l => l.startsWith('160000 ')).map(l => l.slice(l.indexOf('\t') + 1));
  if (existsSync(join(cwd, '.gitmodules'))) paths.push('.gitmodules');
  return {paths,error:null};
}
