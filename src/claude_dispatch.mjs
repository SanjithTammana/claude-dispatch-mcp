#!/usr/bin/env node
/**
 * Fixed-command boundary around one Claude Code CLI turn. Node 24 stdlib only; Windows only (v1).
 *
 * Flags verified against Claude Code 2.1.296 `--help` (2026-10-10): -p, --output-format json,
 * --model, --effort low|medium|high|xhigh, --max-budget-usd, --settings,
 * --permission-mode dontAsk|acceptEdits, --allowedTools, --disallowedTools, --tools, --restricted,
 * --strict-mcp-config. `plan` mode is not used: it silently swaps --model for Sonnet.
 * --restricted ignores user/project/local settings (keeps --settings and managed settings), removes
 * code-running tools unless --tools names them, and confines the file tools to the working directory.
 * --strict-mcp-config ignores every MCP configuration not passed with --mcp-config (none is).
 * disableAllHooks: https://code.claude.com/docs/en/hooks#disable-or-remove-hooks (managed hooks are
 * exempt). Deny rules: https://code.claude.com/docs/en/permissions (gitignore path syntax; Read denies
 * cover Grep/Glob on a best-effort basis). These are CLI controls, not an OS filesystem sandbox; see
 * docs/THREAT_MODEL.md.
 */
import { spawn, spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { preflight } from './preflight.mjs';
import { snapshot, compare } from './raw_audit.mjs';
import { gitPhase } from './git_audit.mjs';
import { stopJobrun, waitWithin } from './containment/jobrun.mjs';

// Ceiling on captured worker stdout and stderr (characters each); see run().
const CAPTURE_LIMIT = 32 * 1024 * 1024;
const FORBIDDEN = /--(?:dangerously-skip-permissions|allow-dangerously-skip-permissions|settings|mcp-config|plugin-dir|agents|add-dir|append-system-prompt[^\s]*)/i;
// Secret-shaped paths no mode may read or write. config.json `extra_deny` adds to this list.
const DENY = ['**/.env*','**/*.env','**/*.pem','**/*.key','**/*.p12','**/*.pfx','**/id_rsa*','**/id_ed25519*',
  '**/.npmrc','**/.netrc','**/.git/**'];
const HELP = `Usage: node claude_dispatch.mjs run --packet <file> --cd <dir>
  [--mode read-only|workspace-write] [--allow <relpath>]...
  [--model sonnet|opus|haiku] [--effort low|medium|high|xhigh]
  [--timeout <secs: default 900, max 3600>]
  [--max-budget-usd <n: default 1, max 5>]
  node claude_dispatch.mjs doctor | --help
Packets must sit directly in <state>/packets/. See README "Configure".`;
class Failure extends Error {
  constructor(message, code = 2) { super(message); this.code = code; }
}
function fail(message, code = 2) { throw new Failure(message, code); }
function parseArgs(argv) {
  for (const value of argv) if (FORBIDDEN.test(value)) fail(`forbidden argument: ${value}`);
  if (argv.length === 1 && ['--help', 'doctor'].includes(argv[0])) return { command: argv[0] };
  if (argv[0] !== 'run') fail('expected run, doctor, or --help');
  if (argv.length === 2 && argv[1] === '--help') return { command: '--help' };
  const a = { command: 'run', packet: null, cd: null, mode: 'read-only', allow: [],
    model: 'sonnet', effort: null, timeout: 900, budget: 1 };
  const names = new Map([['--packet','packet'],['--cd','cd'],['--mode','mode'],
    ['--allow','allow'],['--model','model'],['--effort','effort'],
    ['--timeout','timeout'],['--max-budget-usd','budget']]);
  const seen = new Set();
  for (let i = 1; i < argv.length; i++) {
    const flag = argv[i], name = names.get(flag);
    if (!name) fail(`unknown flag or positional argument: ${flag}`);
    if (seen.has(flag) && name !== 'allow') fail(`duplicate flag: ${flag}`);
    seen.add(flag);
    const value = argv[++i];
    if (!value || value.startsWith('-') || value.includes('\0')) fail(`${flag} requires a value`);
    if (name === 'allow') a.allow.push(value); else a[name] = value;
  }
  if (!a.packet) fail('--packet is required; positional prompts are forbidden');
  if (!a.cd) fail('--cd is required');
  if (!['sonnet','opus','haiku'].includes(a.model)) fail('--model must be sonnet|opus|haiku');
  if (a.effort && !['low','medium','high','xhigh'].includes(a.effort)) fail('--effort must be low|medium|high|xhigh');
  if (!['read-only','workspace-write'].includes(a.mode)) fail('--mode must be read-only|workspace-write');
  for (const [key, flag, max] of [['timeout','--timeout',3600],['budget','--max-budget-usd',5]]) {
    if (!/^(?:\d+(?:\.\d+)?|\.\d+)$/.test(String(a[key]))) fail(`${flag} requires a positive decimal number`);
    a[key] = Number(a[key]);
    if (!Number.isFinite(a[key]) || a[key] <= 0 || a[key] > max) fail(`${flag} must be > 0 and <= ${max}`);
  }
  if (a.mode === 'workspace-write' && !a.allow.length) fail('workspace-write requires at least one --allow');
  if (a.mode === 'read-only' && a.allow.length) fail('--allow is forbidden in read-only mode');
  return a;
}
function childEnvironment() {
  // Drop every Anthropic/Claude variable, not just API keys: a parent Claude Code session
  // exports its session id, messaging token and ANTHROPIC_BASE_URL, which made the child act as
  // a sub-session (it ignored --model) and would leak that token. The child uses only its own
  // subscription login from ~/.claude.
  return withoutNodePreloads(env => {
    for (const key of Object.keys(env))
      if (/^(?:ANTHROPIC_|CLAUDE_|CLAUDECODE$)/i.test(key)) delete env[key];
  });
}
// NODE_OPTIONS can carry --require/--import/--loader, and NODE_PATH widens module resolution. The relay
// starts with the repository as its working directory, so a relative preload would resolve to a
// file the repository supplies and run before the fixed relay code. No dispatcher-launched Node
// process inherits either.
export function withoutNodePreloads(edit = () => {}) {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (/^(?:NODE_OPTIONS|NODE_PATH)$/i.test(key)) delete env[key];
  edit(env);
  return env;
}
function claudeArgs(a, settings) {
  const tools = ['Read','Grep','Glob',...(a.mode === 'read-only' ? [] : ['Edit','Write'])];
  return ['-p','--output-format','json','--model',a.model,
    ...(a.effort ? ['--effort',a.effort] : []),'--max-budget-usd',String(a.budget),
    '--settings',settings,'--permission-mode',a.mode === 'read-only' ? 'dontAsk' : 'acceptEdits',
    '--restricted','--strict-mcp-config','--tools',...tools,
    '--allowedTools',...tools,
    '--disallowedTools','Bash','PowerShell',...(a.mode === 'read-only' ? ['Edit','Write'] : []),
    'NotebookEdit','WebFetch','WebSearch','Agent','mcp__*'];
}
function claudeSettings(a, config) {
  const tools = a.mode === 'read-only' ? ['Read'] : ['Read','Edit','Write'];
  const patterns = [...DENY, ...config.extraDeny];
  return {disableAllHooks:true,permissions:{deny:tools.flatMap(tool => patterns.map(p => `${tool}(${p})`))}};
}
// JobRun gives its root NUL stdin and reserves its own stdin for kill/EOF control.
// This constant relay runs INSIDE the job, passes bytes on a child stdin pipe, and
// forwards the worker exit. No prompt, executable source, or shell text comes from argv.
const RELAY = `const{spawn}=require('node:child_process');const{readFileSync}=require('node:fs');
const [exe,args,packet]=process.argv.slice(1);
const child=spawn(exe,JSON.parse(args),{stdio:['pipe','inherit','inherit'],windowsHide:true});
child.stdin.on('error',()=>{});child.on('error',e=>{console.error(e.message);process.exitCode=7});
child.on('close',(code)=>{process.exitCode=code===null?7:code});
child.stdin.end(readFileSync(packet));`;

function audit(a, root, before, limit) {
  const git=gitPhase();
  const top=git(root,['rev-parse','--show-toplevel']);
  if(!top.ok || resolve(top.out.trim()).toLowerCase()!==root.toLowerCase())
    return {scope_check:'UNKNOWN',files_changed:[],error_detail:'Git repository ownership changed or is unavailable: '+top.err};
  return compare(a,before,snapshot(root,a.mode,limit,git));
}
function printResult(result) {
  console.log(`# RESULT ${result.id} (draft - orchestrator must verify)`);
  for (const key of ['status','model','mode','workspace','scope_check','cleanup_confirmed']) console.log(`${key}: ${result[key]}`);
  console.log(`files_changed (raw filesystem audit):\n${result.files_changed.join('\n') || '  (none)'}`);
  for (const key of ['total_cost_usd','cost_usd','usage','modelUsage']) if (result[key] !== undefined) console.log(`${key}: ${JSON.stringify(result[key])}`);
  console.log(`evidence: ${JSON.stringify(result.evidence_paths)}`);
  console.log(`result_json: ${result.evidence_paths.result}`);
  console.log(`failure_evidence_or_alert: ${result.error_detail || 'none'}`);
  console.log(`--- last message ---\n${result.last_message || '(none)'}`);
}
async function run(a, prepared, testBinary) {
  const {config,root,before,binary,node,jobrun,limit}=prepared;
  const id = `${new Date().toISOString().replaceAll(/[:.]/g,'-')}-${randomUUID()}`;
  const runDir = join(config.runs,id);
  mkdirSync(runDir,{recursive:true});
  const paths = {packet:join(runDir,'packet.md'),stdout:join(runDir,'stdout.json'),
    stderr:join(runDir,'stderr.txt'),result:join(runDir,'result.json'),jobrun:join(runDir,'jobrun.json')};
  writeFileSync(paths.packet,readFileSync(a.packet));
  writeFileSync(paths.stdout,'');writeFileSync(paths.stderr,'');
  const temp = mkdtempSync(join(tmpdir(),'claude-dispatch-'));
  const settings = join(temp,'settings.json');
  writeFileSync(settings,JSON.stringify(claudeSettings(a, config)),'utf8');
  const argv = claudeArgs(a,settings);
  // Offline tests inject a Node script as the binary; production never takes this branch.
  const testScript = Boolean(testBinary) && binary.endsWith('.mjs');
  const target = testScript ? process.execPath : binary;
  const targetArgs = testScript ? [binary,...argv] : argv;
  let supervisor, stdout = '', stderr = '', timedOut = false, timer, outputOverflow = null;
  const result = {id,status:'failed',model:a.model,mode:a.mode,workspace:a.cd,
    command:[binary,...argv],scope_check:'UNKNOWN',files_changed:[],cleanup_confirmed:false,
    evidence_paths:paths,last_message:'',error_detail:'',exit_code:7};
  try {
    const child = spawn(jobrun,['--report',paths.jobrun,'--',process.execPath,'-e',RELAY,
      target,JSON.stringify(targetArgs),paths.packet],{
      env:childEnvironment(),cwd:a.cd,stdio:['pipe','pipe','pipe'],detached:true,windowsHide:true,
    });
    supervisor = {child,exited:false,exitCode:null,rootPid:null,launchError:''};
    child.stdin.on('error',()=>{});
    child.once('exit',code => {supervisor.exited=true;supervisor.exitCode=code;});
    child.once('error',error => {supervisor.launchError=error.message;});
    supervisor.closed = new Promise(done => child.once('close',done));
    let firstLine = '';
    // Captured output is bounded: past the ceiling the turn is stopped and the run fails, rather than
    // the dispatcher's memory growing until the timeout.
    const overflow = stream => {
      if (!outputOverflow) { outputOverflow = stream; if (!child.stdin.destroyed) child.stdin.write('kill\n'); }
    };
    // Decode as streams so a UTF-8 character split across two pipe chunks stays intact.
    child.stdout.setEncoding('utf8'); child.stderr.setEncoding('utf8');
    child.stderr.on('data',chunk => {
      if (stderr.length + chunk.length > CAPTURE_LIMIT) return overflow('stderr');
      stderr += chunk;
      if (supervisor.rootPid === null) {
        firstLine += chunk;
        const match = firstLine.match(/^jobrun_root_pid=(\d+)\r?\n/);
        if (match) supervisor.rootPid=Number(match[1]);
      }
    });
    child.stdout.on('data',chunk => {
      if (stdout.length + chunk.length > CAPTURE_LIMIT) return overflow('stdout');
      stdout += chunk;
    });
    const signalStop = () => { if (!child.stdin.destroyed) child.stdin.write('kill\n'); };
    process.once('SIGINT',signalStop);process.once('SIGTERM',signalStop);
    try {
      timer = setTimeout(() => {timedOut=true;signalStop();},a.timeout*1000);
      // Deadline plus the same 8s cleanup grace used by OpenCode; never wait forever.
      await waitWithin(supervisor.closed,a.timeout*1000+8000);
      const cleanup = await stopJobrun(supervisor,paths.jobrun);
      result.cleanup_confirmed=cleanup.ok;result.jobrun=cleanup.report;
      result.worker_exit_code=cleanup.report?.root_exit_code ?? null;
      // A surviving process could still edit after the snapshot, so scope is established only
      // after confirmed teardown; otherwise it stays UNKNOWN.
      if (cleanup.ok) Object.assign(result,audit(a,root,before,limit));
      else Object.assign(result,{scope_check:'UNKNOWN',files_changed:[]});
      let output;
      try {
        const parsed=JSON.parse(stdout);output=Array.isArray(parsed) ? parsed.findLast(v=>v.type==='result') : parsed;
        if (!output || typeof output !== 'object') throw new Error('missing JSON result');
      } catch { output=null; }
      result.last_message = output?.result ?? '';
      for (const field of ['total_cost_usd','cost_usd','usage','modelUsage','duration_ms','duration_api_ms','num_turns'])
        if (output?.[field] !== undefined) result[field]=output[field];
      // Only a failed run can be an auth failure; a successful answer may discuss auth.
      const failedRun = !output || output.is_error || result.worker_exit_code !== 0;
      const auth = failedRun && /OAuth session expired|OAuth.*expired|authentication.*(?:failed|required)|not logged in|invalid.*(?:api key|auth.*token)/i
        .test(stderr+'\n'+(output?.result ?? stdout));
      result.exit_code = !cleanup.ok ? 5 : result.scope_check !== 'PASS' ? 3 : timedOut ? 6
        : outputOverflow || auth || result.worker_exit_code !== 0 || output?.is_error || !output ? 7 : 0;
      if (!cleanup.ok) result.error_detail=cleanup.detail;
      else if (outputOverflow) result.error_detail=`worker ${outputOverflow} exceeded ${CAPTURE_LIMIT} characters; turn stopped`;
      else if (auth) result.error_detail='OAuth session expired. Run `claude`, then `/login`, and retry.';
      else if (timedOut) result.error_detail=`timeout after ${a.timeout}s; process tree teardown confirmed`;
      else if (result.exit_code === 7) result.error_detail=`Claude failed (exit ${result.worker_exit_code}); ${output?.result || supervisor.launchError || stderr.slice(-1000)}`;
      result.status=result.exit_code===0 ? 'completed' : 'failed';
    } finally { clearTimeout(timer);process.removeListener('SIGINT',signalStop);process.removeListener('SIGTERM',signalStop); }
  } catch (error) {
    result.error_detail=error.message;result.exit_code=Number.isInteger(error.code)?error.code:7;
    if (supervisor) {
      const cleanup=await stopJobrun(supervisor,paths.jobrun);
      result.cleanup_confirmed=cleanup.ok;result.jobrun=cleanup.report;
      if (!cleanup.ok) {result.exit_code=5;result.error_detail=cleanup.detail;}
    }
  } finally {
    writeFileSync(paths.stdout,stdout,'utf8');writeFileSync(paths.stderr,stderr,'utf8');
    writeFileSync(paths.result,JSON.stringify(result,null,2)+'\n','utf8');
    if (result.cleanup_confirmed || !supervisor) rmSync(temp,{recursive:true,force:true});
  }
  printResult(result);
  return result.exit_code;
}
// options exist for the offline tests only: { config, testBinary, leafLimit }. The CLI passes none,
// so production always loads config.json from the state directory and resolves the real binary.
export async function main(argv, options = {}) {
  const a=parseArgs(argv);
  if (a.command==='--help') {console.log(HELP);return 0;}
  // The dispatcher always takes its own baseline: skipping it is for the MCP pre-launch check only.
  const prepared=preflight(a,{...options,skipBaseline:false});
  const {config,binary,jobrun}=prepared;
  if (a.command==='doctor') {
    console.log('state: '+config.home);
    console.log('trusted_roots:\n'+config.trustedRoots.map(r=>'  '+r).join('\n'));
    console.log('jobrun: '+jobrun);
    const r=spawnSync(binary,['--version'],{encoding:'utf8',env:childEnvironment(),windowsHide:true,timeout:15000});
    console.log('binary: '+binary+'\nversion: '+((r.stdout || '').trim() || '(unavailable)'));
    if(r.error || r.status!==0) {console.error(r.error?.message || r.stderr);return 7;}
    return 0;
  }
  return run(a,prepared,options.testBinary);
}
export {parseArgs};
// import.meta.main, not a path comparison: Windows paths differ in case (Codex records
// lowercase project paths) and a mismatch would make a direct run a silent exit-0 no-op.
if (import.meta.main) {
  try {process.exitCode=await main(process.argv.slice(2));}
  catch (error) {console.error(error.message);process.exitCode=Number.isInteger(error.code)?error.code:7;}
}
