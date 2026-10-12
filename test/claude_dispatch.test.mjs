#!/usr/bin/env node
// Offline contract tests: the fake executable is a Node script injected through main(), never the CLI.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { changedPaths, gitExecutable, gitPhase } from '../src/git_audit.mjs';
import { PREFLIGHT_ORDER } from '../src/preflight.mjs';
import { markerExe } from './fixtures.mjs';

const repo = resolve(import.meta.dirname, '..');
const dispatcher = join(repo, 'src', 'claude_dispatch.mjs');
const DENY = ['**/.env*','**/*.env','**/*.pem','**/*.key','**/*.p12','**/*.pfx','**/id_rsa*','**/id_ed25519*',
  '**/.npmrc','**/.netrc','**/.git/**'];
let passed = 0;
function test(name, fn) { fn(); passed++; console.log(`PASS ${name}`); }
test('dispatcher exists', () => assert.ok(existsSync(dispatcher), 'missing Claude dispatcher'));
const dir = mkdtempSync(join(tmpdir(), 'cdm-test-'));
// The state directory is disjoint from every fixture repository, as the boundary requires.
const state = mkdtempSync(join(tmpdir(), 'cdm-state-'));
const packets = join(state,'packets');mkdirSync(packets);
const packetFiles = [], roots = [];
const outside = mkdtempSync(join(tmpdir(), 'claude-outside-'));
const fake = join(dir, 'fake.mjs');
writeFileSync(fake, `
import {readFileSync,writeFileSync,rmSync,mkdirSync,readdirSync} from 'node:fs';
import {dirname,join} from 'node:path';
import {spawn,spawnSync} from 'node:child_process';
const text=readFileSync(0,'utf8'); const p=JSON.parse(text);
const argv=process.argv.slice(2);
const settings=JSON.parse(readFileSync(argv[argv.indexOf('--settings')+1],'utf8'));
const keys=['ANTHROPIC_API_KEY','ANTHROPIC_AUTH_TOKEN','CLAUDE_CODE_USE_BEDROCK','CLAUDE_CODE_USE_VERTEX','ANTHROPIC_BASE_URL','CLAUDE_CODE_SESSION_ID','CLAUDE_CODE_MESSAGING_TOKEN','CLAUDECODE'];
if(p.writes) for(const w of p.writes) {mkdirSync(dirname(w.path),{recursive:true});writeFileSync(w.path,w.content);}
if(p.flood) {const block='x'.repeat(1<<20);const pump=()=>{while(process.stdout.write(block));process.stdout.once('drain',pump);};pump();setInterval(()=>{},1000);}
if(p.write) {mkdirSync(dirname(p.write),{recursive:true});writeFileSync(p.write,p.content||'changed');
 for(let i=0;i<(p.extra||0);i++) writeFileSync(join(dirname(p.write),'extra-'+i+'.txt'),'x');}
if(p.removeGit) rmSync('.git',{recursive:true,force:true});
if(p.hide) spawnSync('git',['update-index','--assume-unchanged','tracked.txt'],{stdio:'ignore'});
if(p.commit) spawnSync('git',['-c','user.name=Test','-c','user.email=test@example.com','commit','--allow-empty','-qm','worker moved HEAD'],{stdio:'ignore'});
if(p.plantReport) {
 const latest=readdirSync(p.runRoot).sort().at(-1);
 writeFileSync(join(p.runRoot,latest,'jobrun.json'),JSON.stringify({confirmed:true,active_after:0,root_pid:process.pid,root_exit_code:0,killed_by:'root_exit'}));
}
if(p.auth) {console.error('OAuth session expired');process.exit(1)}
if(p.split) {
 const b=Buffer.from(JSON.stringify({type:'result',result:'EURO:'+String.fromCharCode(0x20ac)}));
 const i=b.indexOf(0xe2);process.stdout.write(b.subarray(0,i+1));
 setTimeout(()=>process.stdout.write(b.subarray(i+1)),60);
} else if(p.sleep) {
 const child=spawn(process.execPath,['-e','setInterval(()=>{},1000)'],{detached:true,stdio:'ignore'});
 writeFileSync(p.pidFile,String(child.pid));child.unref();setInterval(()=>{},1000);
} else console.log(JSON.stringify({type:'result',result:JSON.stringify({text,argv,settings,envKeys:keys.filter(k=>k in process.env)}),total_cost_usd:0.02,usage:{input_tokens:3,output_tokens:4}}));
`, 'utf8');
const env = { ...process.env, CLAUDE_DISPATCH_HOME: state,
  ANTHROPIC_API_KEY: 'test-only', ANTHROPIC_AUTH_TOKEN: 'test-only',
  CLAUDE_CODE_USE_BEDROCK: '1', CLAUDE_CODE_USE_VERTEX: '1', ANTHROPIC_BASE_URL: 'http://127.0.0.1:9', CLAUDE_CODE_SESSION_ID: 'parent', CLAUDE_CODE_MESSAGING_TOKEN: 'test-only', CLAUDECODE: '1' };
function writeConfig(home, value) {
  mkdirSync(home,{recursive:true});writeFileSync(join(home,'config.json'),JSON.stringify(value));
}
function run(args, extra = {}) {
  // Fixture repositories reach the boundary through the real config.json; the fake binary and the
  // leaf limit are injected through the imported API, never through the production CLI.
  if (!extra.keepConfig) writeConfig(state,{trusted_roots:roots.length ? roots : [outside],...(extra.config || {})});
  const runner = `import {main} from ${JSON.stringify(pathToFileURL(dispatcher).href)};
    import cp from 'node:child_process';import fs from 'node:fs';import {syncBuiltinESMExports} from 'node:module';
    if(process.argv[3]) {const original=cp.spawnSync;cp.spawnSync=(exe,args,opts)=>{
      if(/(^|[\\\\/])git(\\.exe)?$/i.test(exe)) fs.appendFileSync(process.argv[3],JSON.stringify([exe,...args])+'\\n');return original(exe,args,opts);
    };syncBuiltinESMExports();}
    const options=JSON.parse(process.argv[2]);
    if(options.stageTraceFile) options.onStage=name=>fs.appendFileSync(options.stageTraceFile,name+'\\n');
    try {process.exitCode=await main(JSON.parse(process.argv[1]),options);}
    catch(e) {console.error(e.message);process.exitCode=e.code || 7;}`;
  const {gitTraceFile = '',stageTraceFile,leafLimit,gitTimeoutMs,config,keepConfig,testBinary = fake,...options}=extra;
  return spawnSync(process.execPath, ['--input-type=module','-e',runner,JSON.stringify(args),JSON.stringify({testBinary,stageTraceFile,leafLimit,gitTimeoutMs}),gitTraceFile], {
    cwd: repo, encoding: 'utf8', env, timeout: 90000, ...options,
  });
}
function git(cwd, ...args) {
  const r = spawnSync('git', ['-c', `safe.directory=${cwd.replaceAll('\\','/')}`,
    '-c','core.fsmonitor=false','-c',`core.hooksPath=${process.platform==='win32'?'NUL':'/dev/null'}`,
    '-C', cwd, ...args], {encoding:'utf8'});
  assert.equal(r.status, 0, r.stderr); return r.stdout;
}
let seq = 0;
function workspace() {
  const cwd = join(dir, `workspace-${++seq}`); mkdirSync(cwd);
  git(cwd,'init','-q'); writeFileSync(join(cwd,'tracked.txt'),'base');
  writeFileSync(join(cwd,'.gitignore'),'ignored/\n');
  git(cwd,'add','.'); git(cwd,'-c','user.name=Test','-c','user.email=test@example.com','commit','-qm','base');
  roots.push(cwd);
  return cwd;
}
function packet(value = {}) {
  const path = join(packets, `${basename(dir)}-packet-${++seq}.md`);
  packetFiles.push(path);writeFileSync(path,JSON.stringify(value));return path;
}
function execute(mode, value = {}, allow = ['tracked.txt'], options = []) {
  const cwd = workspace(); const p = packet(value);
  const args = ['run','--cd',cwd,'--packet',p,'--mode',mode,...options];
  if(mode==='workspace-write') for(const a of allow) args.push('--allow',a);
  const r=run(args); const match=r.stdout.match(/^result_json: (.+)$/m);
  const result=match ? JSON.parse(readFileSync(match[1],'utf8')) : null;
  return {r,result,cwd,p};
}
try {
  for (const flag of ['--dangerously-skip-permissions','--allow-dangerously-skip-permissions',
    '--settings','--mcp-config','--plugin-dir','--agents','--add-dir',
    '--append-system-prompt','--append-system-prompt-file','--unknown']) {
    test(`reject ${flag}`, () => {const r=run(['run',flag,'x']);assert.equal(r.status,2,r.stderr+r.stdout);});
    test(`reject embedded ${flag}`, () => assert.equal(run(['run','--packet',`x ${flag}=x`]).status,2));
  }
  for(const [flag,value] of [['--model','fable'],['--effort','max'],['--mode','bypassPermissions'],
    ['--timeout','0'],['--timeout','3601'],['--timeout','NaN'],['--max-budget-usd','0'],
    ['--max-budget-usd','5.01'],['--max-budget-usd','Infinity']]) {
    test(`reject ${flag} ${value}`,()=>{const r=run(['run','--packet',packet(),'--cd',dir,flag,value]);assert.equal(r.status,2);assert.match(r.stderr,new RegExp(flag));});
  }
  for(const args of [['run','prompt'],['run'],['run','--packet'],['doctor','--model','sonnet'],
    ['run','--packet',packet(),'--packet',packet()],['run','--packet',packet(),'--allow','tracked.txt'],
    ['run','--packet',packet(),'--mode','workspace-write']]) {
    test(`reject malformed ${args.slice(0,3).join(' ')}`,()=>assert.equal(run(args).status,2));
  }
  test('help',()=>assert.equal(run(['--help']).status,0));
  test('run without --cd is rejected',()=>{const r=run(['run','--packet',packet()]);assert.equal(r.status,2);assert.match(r.stderr,/--cd is required/);});
  test('production CLI has no test-binary path (old environment hooks are inert)',()=>{
    // Pin an unavailable production binary: this test must never discover or run real Claude.
    writeConfig(state,{trusted_roots:[outside],claude_binary:join(outside,'unavailable-claude.exe')});
    const r=spawnSync(process.execPath,[dispatcher,'doctor'],{encoding:'utf8',
      env:{...env,CLAUDE_DISPATCH_TEST_MODE:'1',CLAUDE_DISPATCH_TEST_BINARY:fake}});
    assert.notEqual(r.status,0,r.stderr+r.stdout);
    assert.ok(!(r.stdout+r.stderr).includes(fake),r.stdout+r.stderr);
  });
  const cwd=workspace(), p=packet();
  for(const args of [['--cd',dir+'/..'],['--cd',outside],['--packet',join(outside,'p.md')],
    ['--packet',dir+'/../packet.md'],['--allow','../oops'],['--allow',outside],['--allow','tracked.txt:stream']]) {
    writeFileSync(join(outside,'p.md'),'{}');
    const base=args[0]==='--packet' ? ['run','--cd',cwd] : ['run','--packet',p];
    if(args[0]==='--allow') base.push('--cd',cwd,'--mode','workspace-write');
    test(`reject path ${args.join(' ')}`,()=>assert.equal(run([...base,...args]).status,2));
  }
  test('packet in repo outside cd and _local is rejected',()=>assert.equal(run(['run','--cd',cwd,'--packet',dispatcher]).status,2));
  test('packet outside _local/packets is rejected without copying its bytes',()=>{
    const path=join(dir,'credential.env');writeFileSync(path,'secret-test-sentinel');
    const r=run(['run','--cd',cwd,'--packet',path]);
    assert.equal(r.status,2);assert.match(r.stderr,/packets/);assert.ok(!r.stdout.includes('secret-test-sentinel'));
  });
  test('non-md file inside packets is rejected',()=>{
    const path=join(packets,`${basename(dir)}.env`);packetFiles.push(path);writeFileSync(path,'secret-test-sentinel');
    assert.equal(run(['run','--cd',cwd,'--packet',path]).status,2);
  });
  test('packet subdirectory is rejected',()=>{
    const path=join(packets,basename(dir));packetFiles.push(path);mkdirSync(path);writeFileSync(join(path,'p.md'),'{}');
    assert.equal(run(['run','--cd',cwd,'--packet',join(path,'p.md')]).status,2);
  });
  test('directory named md is rejected',()=>{
    const path=join(packets,`${basename(dir)}-directory.md`);packetFiles.push(path);mkdirSync(path);
    assert.equal(run(['run','--cd',cwd,'--packet',path]).status,2);
  });
  try {
    const path=join(packets,`${basename(dir)}-hardlink.md`);packetFiles.push(path);linkSync(p,path);
    test('hard-linked packet is rejected',()=>assert.equal(run(['run','--cd',cwd,'--packet',path]).status,2));rmSync(path);
  } catch(error) { if(!['EPERM','EACCES','ENOTSUP'].includes(error.code)) throw error; console.log('SKIP hard links unavailable'); }
  try {
    const path=join(packets,`${basename(dir)}-symlink.md`);packetFiles.push(path);symlinkSync(p,path,'file');
    test('symlink packet inside packets is rejected',()=>assert.equal(run(['run','--cd',cwd,'--packet',path]).status,2));
  } catch(error) { if(!['EPERM','EACCES','ENOTSUP'].includes(error.code)) throw error; console.log('SKIP file symlink unavailable'); }
  test('unregistered repository under a trusted root is rejected before status; fsmonitor never executes',()=>{
    const nested=join(cwd,'nested');mkdirSync(nested);git(nested,'init','-q');
    writeFileSync(join(nested,'tracked.txt'),'base');git(nested,'add','.');
    git(nested,'-c','user.name=Test','-c','user.email=test@example.com','commit','-qm','base');
    const marker=join(dir,'fsmonitor-marker'), hook=join(dir,'fsmonitor.mjs');
    writeFileSync(hook,`import {writeFileSync} from 'node:fs';writeFileSync(${JSON.stringify(marker)},'executed');process.stdout.write('test-token\\0');`);
    const direct=spawnSync(process.execPath,[hook],{encoding:'utf8'});
    assert.equal(direct.status,0,direct.stderr);assert.ok(existsSync(marker));rmSync(marker);
    git(nested,'config','core.fsmonitor',`"${process.execPath.replaceAll('\\','/')}" "${hook.replaceAll('\\','/')}"`);
    // Positive control: an unprotected status really would execute this config.
    const probe=spawnSync('git',['-C',nested,'status','--porcelain'],{encoding:'utf8',env:{...process.env,GIT_TRACE:'1',GIT_TRACE_FSMONITOR:'1'}});
    assert.equal(probe.status,0,probe.stderr);
    if(existsSync(marker)) rmSync(marker);
    else {
      assert.match(probe.stderr,/fsmonitor process .* returned failure/);
      console.log('SKIP Git fsmonitor positive control: hook execution unavailable; direct marker script verified');
    }
    const trace=join(dir,'nested-git-trace.jsonl');
    const r=run(['run','--cd',nested,'--packet',p,'--mode','workspace-write','--allow','tracked.txt'],{gitTraceFile:trace});
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/Git toplevel/);assert.ok(!existsSync(marker));
    const calls=readFileSync(trace,'utf8').trim().split('\n').map(line=>JSON.parse(line));
    assert.ok(calls.length);assert.ok(calls.every(args=>!args.includes('status')),'status ran before trust rejection');
    for(const args of calls) {
      // Never a bare `git`: Windows would search the current directory before PATH.
      assert.ok(isAbsolute(args[0]),`git spawned by bare name: ${args[0]}`);
      assert.ok(args.includes('core.fsmonitor=false'));
      assert.ok(args.includes(`core.hooksPath=${process.platform==='win32'?'NUL':'/dev/null'}`));
    }
    rmSync(nested,{recursive:true,force:true});
  });
  test('production CLI rejects a repository missing from config.json',()=>{
    const other=mkdtempSync(join(tmpdir(),'cdm-state-other-'));writeConfig(other,{trusted_roots:[outside]});
    const r=spawnSync(process.execPath,[dispatcher,'run','--cd',cwd,'--packet',p],{encoding:'utf8',env:{...env,CLAUDE_DISPATCH_HOME:other}});
    rmSync(other,{recursive:true,force:true});
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/Git toplevel/);
  });
  test('linked worktree of a trusted root outside that root is accepted in both modes',()=>{
    const base=workspace(), linked=join(dir,`linked-${++seq}`);git(base,'worktree','add','--detach',linked,'HEAD');
    for(const mode of ['read-only','workspace-write']) {
      const args=['run','--cd',linked,'--packet',packet(),'--mode',mode];
      if(mode==='workspace-write') args.push('--allow','tracked.txt');
      const r=run(args);assert.equal(r.status,0,r.stderr+r.stdout);assert.match(r.stdout,/scope_check: PASS/);
    }
  });
  try {
    const link=join(dir,'escape');symlinkSync(outside,link,'junction');
    test('reject cd symlink escape',()=>assert.equal(run(['run','--cd',link,'--packet',p]).status,2));
    const inner=join(cwd,'escape');symlinkSync(outside,inner,'junction');
    test('reject allow symlink escape',()=>assert.equal(run(['run','--cd',cwd,'--packet',p,'--mode','workspace-write','--allow','escape/new.txt']).status,2));
    test('reject packet symlink escape',()=>assert.equal(run(['run','--cd',cwd,'--packet',join(inner,'p.md')]).status,2));
  } catch(error) { if(!['EPERM','EACCES','ENOTSUP'].includes(error.code)) throw error; console.log('SKIP symlinks unavailable'); }
  for(const mode of ['read-only','workspace-write']) {
    test(`${mode} exact argv, stdin, hooks, env, usage and containment`,()=>{
      const {r,result,p}=execute(mode,{},undefined,['--model','opus','--effort','xhigh']);
      assert.equal(r.status,0,r.stderr+r.stdout);assert.equal(result.scope_check,'PASS');assert.equal(result.cleanup_confirmed,true);
      const seen=JSON.parse(result.last_message);assert.equal(seen.text,readFileSync(p,'utf8'));
      const settings=seen.argv[seen.argv.indexOf('--settings')+1];
      assert.deepEqual(seen.argv,['-p','--output-format','json','--model','opus','--effort','xhigh',
        '--max-budget-usd','1','--settings',settings,'--permission-mode',mode==='read-only'?'dontAsk':'acceptEdits',
        '--restricted','--strict-mcp-config','--tools','Read','Grep','Glob',...(mode==='read-only'?[]:['Edit','Write']),
        '--allowedTools','Read','Grep','Glob',...(mode==='read-only'?[]:['Edit','Write']),
        '--disallowedTools','Bash','PowerShell',...(mode==='read-only'?['Edit','Write']:[]),'NotebookEdit','WebFetch','WebSearch','Agent','mcp__*']);
      assert.deepEqual(seen.settings,{disableAllHooks:true,permissions:{deny:
        (mode==='read-only'?['Read']:['Read','Edit','Write']).flatMap(tool =>
          DENY.map(path => `${tool}(${path})`))}});
      assert.deepEqual(seen.envKeys,[]);
      assert.equal(result.total_cost_usd,0.02);assert.equal(result.usage.input_tokens,3);
      for(const path of Object.values(result.evidence_paths)) assert.ok(existsSync(path),path);
    });
  }
  for(const [mode,write,allow,code,scope] of [
    ['workspace-write','tracked.txt',['tracked.txt'],0,'PASS'],
    ['workspace-write','outside.txt',['tracked.txt'],3,'VIOLATION'],
    ['workspace-write','ignored/new.txt',['tracked.txt'],3,'VIOLATION'],
    ['workspace-write','ignored/new.txt',['ignored/new.txt'],0,'PASS'],
    ['workspace-write','ignored/deep/new.txt',['ignored/new.txt'],3,'VIOLATION'],
    ['workspace-write','.opencode/node_modules/escape.txt',['tracked.txt'],3,'VIOLATION'],
    ['read-only','.opencode/node_modules/escape.txt',[],3,'VIOLATION'],
    ['read-only','tracked.txt',[],3,'VIOLATION'],['read-only','new.txt',[],3,'VIOLATION']]) {
    test(`${mode} ${write}: ${scope}`,()=>{
      const {r,result}=execute(mode,{write},allow);assert.equal(r.status,code,r.stderr+r.stdout);
      assert.equal(result.scope_check,scope);assert.ok(result.files_changed.length);
    });
  }
  test('--allow through an existing tracked file is rejected (file-to-directory swap)',()=>{
    const cwd=workspace();
    const r=run(['run','--packet',packet(),'--cd',cwd,'--mode','workspace-write','--allow','tracked.txt/allowed.txt']);
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr+r.stdout,/existing file/);
  });
  test('tracked deletion is judged as itself, not hidden by leaves written in its place',()=>{
    const cwd=workspace();rmSync(join(cwd,'tracked.txt'));mkdirSync(join(cwd,'tracked.txt'));
    writeFileSync(join(cwd,'tracked.txt','allowed.txt'),'x');
    const leaves=changedPaths(cwd).paths;
    assert.ok(leaves.includes('tracked.txt'),JSON.stringify(leaves));
  });
  test('a changed tree larger than the entry limit is UNKNOWN, not hashed without bound',()=>{
    const cwd=workspace();
    const r=run(['run','--cd',cwd,'--packet',packet({write:'ignored/a/one.txt',extra:30}),'--mode','workspace-write','--allow','ignored'],
      {leafLimit:10});
    const match=r.stdout.match(/^result_json: (.+)$/m);assert.ok(match,r.stderr+r.stdout);
    const result=JSON.parse(readFileSync(match[1],'utf8'));
    assert.equal(result.scope_check,'UNKNOWN',r.stderr+r.stdout);assert.notEqual(r.status,0);
  });
  test('--cd below the Git toplevel is rejected (deny rules are cwd-relative)',()=>{
    const cwd=workspace();mkdirSync(join(cwd,'sub'));
    const r=run(['run','--packet',packet(),'--cd',join(cwd,'sub')]);
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr+r.stdout,/exactly a Git toplevel/);
  });
  for(const dirty of ['untracked.txt','ignored/new.txt']) {
    test(`refuse pre-existing ${dirty}`,()=>{
      const cwd=workspace();mkdirSync(join(cwd,dirty,'..'),{recursive:true});writeFileSync(join(cwd,dirty),'existing');
      assert.equal(run(['run','--cd',cwd,'--packet',packet(),'--mode','workspace-write','--allow','tracked.txt']).status,3);
    });
  }
  test('a UTF-8 character split across worker output chunks survives decoding',()=>{
    const {r,result}=execute('read-only',{split:true},[]);assert.equal(r.status,0,r.stderr+r.stdout);
    assert.equal(result.last_message,'EURO:'+String.fromCharCode(0x20ac));
  });
  test('read-only lists ignored trees without hashing them (large main checkouts stay auditable)',()=>{
    const cwd=workspace();const big=join(cwd,'ignored','deep');mkdirSync(big,{recursive:true});
    for(let i=0;i<40;i++) writeFileSync(join(big,`f${i}.txt`),'x');
    const r=run(['run','--cd',cwd,'--packet',packet()],{leafLimit:10});
    assert.equal(r.status,0,r.stderr+r.stdout);assert.match(r.stdout,/scope_check: PASS/);
  });
  test('read-only still flags a new ignored path',()=>{
    const cwd=workspace();
    const r=run(['run','--cd',cwd,'--packet',packet({write:'ignored/new.txt'})]);
    assert.equal(r.status,3,r.stderr+r.stdout);assert.match(r.stdout,/scope_check: VIOLATION/);
  });
  // Read-only mode has no write tools; edits inside an already-ignored tree are not hashed there.
  for(const dirty of ['tracked.txt']) {
    test(`read-only detects change to already dirty ${dirty}`,()=>{
      const cwd=workspace();mkdirSync(join(cwd,dirty,'..'),{recursive:true});writeFileSync(join(cwd,dirty),'already dirty');
      const r=run(['run','--cd',cwd,'--packet',packet({write:dirty,content:'new dirty bytes'})]);
      assert.equal(r.status,3,r.stderr+r.stdout);assert.match(r.stdout,/scope_check: VIOLATION/);
    });
  }
  for(const value of [{hide:true},{commit:true}]) {
    test(`Git ownership audit ${JSON.stringify(value)}`,()=>{
      const {r,result}=execute('workspace-write',value);assert.equal(r.status,3,r.stderr+r.stdout);assert.equal(result.scope_check,'VIOLATION');
    });
  }
  test('audit failure is UNKNOWN',()=>{
    const {r,result}=execute('read-only',{removeGit:true});assert.equal(r.status,3,r.stderr+r.stdout);assert.equal(result.scope_check,'UNKNOWN');
  });
  test('OAuth failure has actionable fix and exit 7',()=>{
    const {r,result}=execute('read-only',{auth:true});assert.equal(r.status,7,r.stderr+r.stdout);
    assert.match(result.error_detail,/OAuth session expired.*claude.*\/login/);
  });
  test('forged report cannot certify cleanup; exit 5',()=>{
    const {r,result}=execute('read-only',{plantReport:true,runRoot:join(state,'runs')});
    assert.equal(r.status,5,r.stderr+r.stdout);assert.equal(result.cleanup_confirmed,false);assert.match(result.error_detail,/cleanup unconfirmed/);
    // Without confirmed teardown a survivor could edit after the snapshot: scope is never established.
    assert.equal(result.scope_check,'UNKNOWN');
  });
  test('timeout kills detached tree and confirms teardown',()=>{
    const pidFile=join(dir,'grandchild.pid');const {r,result}=execute('read-only',{sleep:true,pidFile},[],['--timeout','2']);
    assert.equal(r.status,6,r.stderr+r.stdout);assert.equal(result.cleanup_confirmed,true);
    assert.equal(result.jobrun.active_after,0);assert.equal(result.jobrun.killed_by,'kill_request');
    const pid=Number(readFileSync(pidFile,'utf8'));assert.throws(()=>process.kill(pid,0));
  });
  // Configuration and placement: nothing a dispatched turn can write may steer a later dispatch.
  const configFile = join(state,'config.json');
  const withRawConfig = (text, fn) => {
    writeFileSync(configFile,text);
    try { return fn(); } finally { writeConfig(state,{trusted_roots:roots}); }
  };
  test('missing config.json is a configuration error (exit 2)',()=>{
    rmSync(configFile);const r=run(['run','--cd',cwd,'--packet',p],{keepConfig:true});
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/no config\.json/);
  });
  for(const [label,text,pattern] of [['malformed JSON','{',/unreadable/],['an array','[]',/JSON object/],
    ['an unknown key',JSON.stringify({trusted_roots:[cwd],max_budget_usd:50}),/unknown key max_budget_usd/],
    ['empty trusted_roots',JSON.stringify({trusted_roots:[]}),/non-empty array/],
    ['a relative trusted root',JSON.stringify({trusted_roots:['repo']}),/absolute path/],
    ['a relative claude_binary',JSON.stringify({trusted_roots:[cwd],claude_binary:'claude.exe'}),/absolute path/],
    ['an extra_deny pattern with parentheses',JSON.stringify({trusted_roots:[cwd],extra_deny:['Bash(*)']}),/extra_deny/]]) {
    test(`config.json with ${label} is rejected`,()=>withRawConfig(text,()=>{
      const r=run(['run','--cd',cwd,'--packet',p],{keepConfig:true});
      assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,pattern);
    }));
  }
  try {
    const target=join(dir,'config-target.json');writeFileSync(target,JSON.stringify({trusted_roots:[cwd]}));
    rmSync(configFile);linkSync(target,configFile);
    test('hard-linked config.json is rejected (a workspace alias could rewrite it)',()=>{
      const r=run(['run','--cd',cwd,'--packet',p],{keepConfig:true});
      assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/without links/);
    });
    rmSync(configFile);rmSync(target);
  } catch(error) { if(!['EPERM','EACCES','ENOTSUP'].includes(error.code)) throw error; console.log('SKIP hard links unavailable'); }
  test('a trusted root that contains the state directory is rejected',()=>{
    const r=run(['run','--cd',cwd,'--packet',p],{config:{trusted_roots:[tmpdir()]}});
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/overlaps the state directory/);
  });
  test('a trusted root inside the state directory is rejected',()=>{
    const inner=join(state,'repo');mkdirSync(inner,{recursive:true});
    const r=run(['run','--cd',cwd,'--packet',p],{config:{trusted_roots:[inner]}});
    rmSync(inner,{recursive:true,force:true});
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/overlaps the state directory/);
  });
  test('a trusted root that contains the dispatcher package is rejected',()=>{
    const r=run(['run','--cd',cwd,'--packet',p],{config:{trusted_roots:[repo]}});
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/package's own code/);
  });
  test('a linked worktree placed inside the state directory is rejected before Claude starts',()=>{
    const base=workspace(), linked=join(state,`wt-${++seq}`);git(base,'worktree','add','--detach',linked,'HEAD');
    const r=run(['run','--cd',linked,'--packet',packet()]);
    git(base,'worktree','remove','--force',linked);
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/overlaps the state directory/);
  });
  test('a Claude binary inside a trusted root is rejected (a write run could replace it)',()=>{
    const ws=workspace();const planted=join(ws,'claude.mjs');writeFileSync(planted,readFileSync(fake));
    const r=run(['run','--cd',ws,'--packet',packet()],{testBinary:planted});
    assert.equal(r.status,7,r.stderr+r.stdout);assert.match(r.stderr,/inside trusted root/);
  });
  test('config.json claude_binary must be a native .exe',()=>{
    // A fresh workspace: the shared `cwd` fixture holds an `escape` junction from an earlier test,
    // which the preflight now refuses (links are checked before executables are resolved).
    const ws=workspace();
    const r=run(['run','--cd',ws,'--packet',packet()],{config:{claude_binary:fake},testBinary:null});
    assert.equal(r.status,7,r.stderr+r.stdout);assert.match(r.stderr,/\.exe/);
  });
  try {
    const moved=join(state,'packets-real');
    const link=join(state,'packets');
    // Swap packets/ for a junction: the state layout must refuse to follow it.
    const {renameSync}=await import('node:fs');renameSync(link,moved);symlinkSync(join(dir),link,'junction');
    test('a junctioned state packets/ directory is rejected',()=>{
      const r=run(['run','--cd',cwd,'--packet',join(link,'x.md')]);
      assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/without links/);
    });
    rmSync(link);renameSync(moved,link);
  } catch(error) { if(!['EPERM','EACCES','ENOTSUP'].includes(error.code)) throw error; console.log('SKIP junctions unavailable'); }
  test('extra_deny patterns are appended to the built-in deny rules',()=>{
    const ws=workspace();
    const r=run(['run','--cd',ws,'--packet',packet()],{config:{trusted_roots:roots,extra_deny:['**/secrets/**']}});
    assert.equal(r.status,0,r.stderr+r.stdout);
    const result=JSON.parse(readFileSync(r.stdout.match(/^result_json: (.+)$/m)[1],'utf8'));
    const seen=JSON.parse(result.last_message);
    assert.deepEqual(seen.settings.permissions.deny,[...DENY,'**/secrets/**'].map(path => `Read(${path})`));
  });
  // Round-1 boundary review regressions.
  const commit = (cwd, message) => git(cwd,'-c','user.name=Test','-c','user.email=test@example.com','commit','-qm',message);
  // Round-2: a pre-existing hard link from the workspace to protected code or an executable.
  for(const [label,target] of [['the boundary source',join(repo,'src','config.mjs')],['the git executable',gitExecutable()]]) {
    let linked=true;const ws=workspace();const alias=join(ws,'alias.bin');
    try { linkSync(target,alias); }
    catch(error) { if(!['EPERM','EACCES','ENOTSUP','EXDEV'].includes(error.code)) throw error; linked=false; console.log(`SKIP hard link to ${label} unavailable (${error.code})`); }
    if(linked) {
      try {
        git(ws,'add','alias.bin');commit(ws,'alias');
        test(`a workspace hard link to ${label} blocks workspace-write before Claude starts`,()=>{
          const before=readFileSync(target);
          const r=run(['run','--cd',ws,'--packet',packet({write:'alias.bin'}),'--mode','workspace-write','--allow','alias.bin']);
          // Either the protected-file inventory or the workspace scan refuses it, before Claude starts.
          assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/hard link/);
          assert.ok(readFileSync(target).equals(before),`${label} untouched`);
        });
      } finally { rmSync(alias,{force:true}); }
    }
  }
  for(const mode of ['read-only','workspace-write']) test(`${mode} refuses a populated submodule before any status runs`,()=>{
    const inner=workspace(), outer=workspace();
    git(outer,'-c','protocol.file.allow=always','submodule','add','-q',inner,'sub');commit(outer,'add submodule');
    // A filter defined only in the submodule's own configuration, on a modified filtered file there.
    const marker=join(dir,`sub-filter-ran-${seq}`);const script=join(dir,`sub-filter-${seq}.cjs`);
    writeFileSync(script,`require('fs').writeFileSync(${JSON.stringify(marker)},'ran');process.stdin.pipe(process.stdout);`);
    const subDir=join(outer,'sub');
    git(subDir,'config','filter.subonly.clean',`"${process.execPath.replaceAll('\\','/')}" "${script.replaceAll('\\','/')}"`);
    writeFileSync(join(subDir,'.gitattributes'),'tracked.txt filter=subonly\n');
    const later=new Date(Date.now()+5000);writeFileSync(join(subDir,'tracked.txt'),'base');utimesSync(join(subDir,'tracked.txt'),later,later);
    const args=['run','--cd',outer,'--packet',packet()];
    if(mode==='workspace-write') args.push('--mode','workspace-write','--allow','README.md');
    const r=run(args);
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/populated submodule or nested repository/);
    assert.equal(existsSync(marker),false,'the submodule filter ran');
  });
  test('workspace-write refuses even an unpopulated submodule',()=>{
    const inner=workspace(), outer=workspace();
    git(outer,'-c','protocol.file.allow=always','submodule','add','-q',inner,'sub');commit(outer,'add submodule');
    git(outer,'submodule','deinit','-q','-f','sub');
    const r=run(['run','--cd',outer,'--packet',packet(),'--mode','workspace-write','--allow','README.md']);
    assert.equal(r.status,3,r.stderr+r.stdout);assert.match(r.stderr,/refuses repositories with submodules/);
  });
  test('submodule edits stay visible even with ignore=all in .gitmodules',()=>{
    const inner=workspace(), outer=workspace();
    git(outer,'-c','protocol.file.allow=always','submodule','add','-q',inner,'sub');
    git(outer,'config','-f','.gitmodules','submodule.sub.ignore','all');git(outer,'add','.gitmodules');commit(outer,'ignore all');
    writeFileSync(join(outer,'sub','tracked.txt'),'edited inside the submodule');
    assert.ok(changedPaths(outer).paths.some(p => p.replace(/\/$/,'')==='sub'),JSON.stringify(changedPaths(outer)));
  });
  test('a UNC --cd is rejected',()=>{
    const unc='\\\\localhost\\'+cwd[0]+'$'+cwd.slice(2);
    const r=run(['run','--cd',unc,'--packet',p]);assert.equal(r.status,2,r.stderr+r.stdout);
  });
  test('a UNC state directory is rejected',()=>{
    const r=run(['run','--cd',cwd,'--packet',p],{env:{...env,CLAUDE_DISPATCH_HOME:'\\\\localhost\\'+state[0]+'$'+state.slice(2)}});
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/drive-letter/);
  });
  const withPathFirst = binDir => {
    const pathEnv={...env};const original=Object.entries(env).find(([k])=>k.toLowerCase()==='path')?.[1] ?? '';
    for(const k of Object.keys(pathEnv)) if(k.toLowerCase()==='path') delete pathEnv[k];
    pathEnv.PATH=`${binDir};${original}`;return pathEnv;
  };
  test('a planted git.exe in a trusted root never executes, not even for the state probe',()=>{
    const ws=workspace();const binDir=join(ws,'tools');mkdirSync(binDir);
    const planted=markerExe(binDir,'git');
    const r=run(['run','--cd',ws,'--packet',packet()],{env:withPathFirst(binDir)});
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/git executable lies inside the trusted root/);
    assert.equal(existsSync(planted+'.ran'),false,'the planted git ran');
  });
  test('a planted git.exe in the requested linked worktree (outside its root) never executes',()=>{
    const base=workspace(), linked=join(dir,`linked-git-${++seq}`);git(base,'worktree','add','--detach',linked,'HEAD');
    const binDir=join(linked,'tools');mkdirSync(binDir);const planted=markerExe(binDir,'git');
    const r=run(['run','--cd',linked,'--packet',packet()],{env:withPathFirst(binDir)});
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/git executable lies inside the requested workspace/);
    assert.equal(existsSync(planted+'.ran'),false,'the planted git ran');
  });
  test('a tracked Git include is refused before the turn; its filter never executes',()=>{
    const ws=workspace();const marker=join(dir,`late-filter-ran-${seq}`);const script=join(dir,`late-filter-${seq}.cjs`);
    writeFileSync(script,`require('fs').writeFileSync(${JSON.stringify(marker)},'ran');process.stdin.pipe(process.stdout);`);
    writeFileSync(join(ws,'audit.inc'),'# no filters yet\n');git(ws,'add','audit.inc');commit(ws,'include');
    git(ws,'config','include.path','../audit.inc');
    const driver=`[filter "late"]\n\tclean = \\"${process.execPath.replaceAll('\\','/')}\\" \\"${script.replaceAll('\\','/')}\\"\n`;
    const writes=[{path:'audit.inc',content:driver},{path:'.gitattributes',content:'tracked.txt filter=late\n'},
      {path:'tracked.txt',content:'edited by the turn'}];
    const r=run(['run','--cd',ws,'--packet',packet({writes}),'--mode','workspace-write',
      '--allow','audit.inc','--allow','.gitattributes','--allow','tracked.txt']);
    assert.equal(existsSync(marker),false,'the introduced filter ran during the audit');
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/includes are refused/);
    assert.equal(readFileSync(join(ws,'audit.inc'),'utf8'),'# no filters yet\n','turn never started');
    // Positive control: the include really defines a live driver for an unprotected diff.
    for(const w of writes) writeFileSync(join(ws,w.path),w.content);
    spawnSync('git',['-C',ws,'diff','HEAD','--'],{encoding:'utf8'});
    assert.equal(existsSync(marker),true,'positive control: the introduced filter should run without neutralization');
  });
  test('ordered preflight; exactly one config read per pre/post phase; no status/diff audit',()=>{
    const ws=workspace(), trace=join(dir,'phase-git.jsonl'), stages=join(dir,'phase-stages.txt');
    const r=run(['run','--cd',ws,'--packet',packet()],{gitTraceFile:trace,stageTraceFile:stages});
    assert.equal(r.status,0,r.stderr+r.stdout);
    assert.deepEqual(readFileSync(stages,'utf8').trim().split('\n'),[...PREFLIGHT_ORDER]);
    const calls=readFileSync(trace,'utf8').trim().split('\n').map(l=>JSON.parse(l));
    assert.equal(calls.filter(c=>c.includes('--no-includes')).length,2,'one pre-turn and one post-turn config read');
    assert.ok(calls.every(c=>!c.includes('status')&&!c.includes('diff')));
  });
  test('multi-link protected fake binary outside all roots is accepted',()=>{
    const alias=join(outside,'fake-alias.mjs');linkSync(fake,alias);
    try {
      const ws=workspace();const r=run(['run','--cd',ws,'--packet',packet()]);
      assert.equal(r.status,0,r.stderr+r.stdout);
    } finally {rmSync(alias);}
  });
  test('r5 #1: equals-containing driver is neutralized, with native execution-marker control',()=>{
    const ws=workspace(), marker=join(dir,'equals-driver.ran'), script=join(dir,'equals-driver.cjs');
    writeFileSync(script,`require('fs').writeFileSync(${JSON.stringify(marker)},'ran');process.stdin.pipe(process.stdout);`);
    writeFileSync(join(ws,'.gitattributes'),'tracked.txt filter=late=driver\n');
    git(ws,'add','.gitattributes');commit(ws,'equals attributes');
    git(ws,'config','filter.late=driver.clean',`"${process.execPath.replaceAll('\\','/')}" "${script.replaceAll('\\','/')}"`);
    writeFileSync(join(ws,'tracked.txt'),'positive-control');
    git(ws,'diff','HEAD','--');assert.ok(existsSync(marker),'unprotected diff must execute the filter');rmSync(marker);
    const isolated=gitPhase()(ws,['diff','HEAD','--']);assert.ok(isolated.ok,isolated.err);
    assert.equal(existsSync(marker),false,'literal equals key was neutralized');
    const r=run(['run','--cd',ws,'--packet',packet({write:'tracked.txt'}),'--mode','workspace-write','--allow','tracked.txt']);
    assert.equal(r.status,0,r.stderr+r.stdout);assert.equal(existsSync(marker),false);
  });
  for(const kind of ['ident','eol','autocrlf']) test(`r5 #2: ${kind} conversion cannot hide out-of-allow raw edits`,()=>{
    const ws=workspace(), victim=join(ws,'victim.js');
    const original=kind==='ident'?'const value = "$Id$";\n':'const value = 1;\n';
    writeFileSync(victim,original);
    if(kind!=='autocrlf') writeFileSync(join(ws,'.gitattributes'),`victim.js ${kind==='ident'?'ident':'text eol=crlf'}\n`);
    git(ws,'config','core.autocrlf',kind==='autocrlf'?'true':'false');
    git(ws,'add','.');commit(ws,'conversion');
    rmSync(victim);git(ws,'checkout','--','victim.js');
    const checkout=readFileSync(victim,'utf8');
    if(kind!=='ident') assert.ok(checkout.includes('\r\n'),'default autocrlf/eol checkout must use CRLF');
    const unchanged=run(['run','--cd',ws,'--packet',packet(),'--mode','workspace-write','--allow','tracked.txt']);
    assert.equal(unchanged.status,0,unchanged.stderr+unchanged.stdout,'converted checkout accepted');
    const injection=kind==='ident'?'const value = "$Id: "; globalThis.executed = true; // $";\n':checkout.replaceAll('\r\n','\n');
    writeFileSync(victim,injection);
    assert.equal(git(ws,'diff','HEAD','--','victim.js'),'','positive control: Git hides raw change');
    writeFileSync(victim,checkout);
    const r=run(['run','--cd',ws,'--packet',packet({write:'victim.js',content:injection}),'--mode','workspace-write','--allow','tracked.txt']);
    assert.equal(r.status,3,r.stderr+r.stdout);assert.match(r.stdout,/scope_check: VIOLATION/);
    const result=JSON.parse(readFileSync(r.stdout.match(/^result_json: (.+)$/m)[1],'utf8'));
    assert.ok(result.files_changed.includes('victim.js'));
  });
  test('every Git call is bounded by the per-call timeout and a timeout fails closed',()=>{
    const ws=workspace();
    const r=run(['run','--cd',ws,'--packet',packet()],{gitTimeoutMs:1});
    assert.notEqual(r.status,0,r.stderr+r.stdout);assert.match(r.stderr+r.stdout,/timed out after 1 ms/);
  });
  // Round-3 boundary review regressions.
  for(const mode of ['read-only','workspace-write']) test(`${mode}: configured Git filters never execute during the audit`,()=>{
    const ws=workspace();const marker=join(ws,'..',`filter-ran-${seq}`);
    const script=join(ws,'filter.cjs');
    writeFileSync(script,`require('fs').writeFileSync(${JSON.stringify(marker)},'ran');process.stdin.pipe(process.stdout);`);
    const node=process.execPath.replaceAll('\\','/');
    git(ws,'config','filter.probe.clean',`"${node}" "${script.replaceAll('\\','/')}"`);
    git(ws,'config','filter.probe.process',`"${node}" "${script.replaceAll('\\','/')}"`);
    git(ws,'config','filter.probe.required','true');
    writeFileSync(join(ws,'.gitattributes'),'tracked.txt filter=probe\n');
    git(ws,'-c','filter.probe.clean=','-c','filter.probe.process=','-c','filter.probe.required=false','add','.gitattributes','filter.cjs');
    git(ws,'-c','filter.probe.clean=','-c','filter.probe.process=','-c','filter.probe.required=false','-c','user.name=Test','-c','user.email=test@example.com','commit','-qm','filter');
    if(existsSync(marker)) rmSync(marker);
    // The turn rewrites tracked.txt (an allowed path) and would rewrite the filter's implementation.
    const args=['run','--cd',ws,'--packet',packet(mode==='workspace-write'?{write:'tracked.txt',content:'edited'}:{})];
    if(mode==='workspace-write') args.push('--mode','workspace-write','--allow','tracked.txt');
    const r=run(args);
    assert.equal(existsSync(marker),false,'a filter ran during the audit');
    assert.equal(r.status,0,r.stderr+r.stdout);
    if(mode==='workspace-write') {
      // Positive control: an un-neutralized diff of the same worktree really does run the filter.
      spawnSync('git',['-C',ws,'diff','HEAD','--'],{encoding:'utf8'});
      assert.equal(existsSync(marker),true,'positive control: the filter should run without neutralization');
    }
  });
  test('a hard link between workspace files is refused in read-only mode too',()=>{
    const ws=workspace();
    try { linkSync(join(ws,'tracked.txt'),join(ws,'alias.txt')); }
    catch(error) { if(['EPERM','EACCES','ENOTSUP'].includes(error.code)) { console.log('SKIP hard links unavailable'); passed--; return; } throw error; }
    const r=run(['run','--cd',ws,'--packet',packet()]);
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/2 hard links/);
  });
  test('a junction inside the package source blocks workspace-write',()=>{
    const ws=workspace();const target=mkdtempSync(join(tmpdir(),'cdm-elsewhere-'));const link=join(repo,'src','linked-dir');
    try { symlinkSync(target,link,'junction'); }
    catch(error) { rmSync(target,{recursive:true,force:true}); if(['EPERM','EACCES','ENOTSUP'].includes(error.code)) { console.log('SKIP junctions unavailable'); passed--; return; } throw error; }
    try {
      const r=run(['run','--cd',ws,'--packet',packet(),'--mode','workspace-write','--allow','tracked.txt']);
      assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/package source contains a link/);
    } finally { rmSync(link,{force:true,recursive:false});rmSync(target,{recursive:true,force:true}); }
  });
  test('a state directory inside any Git repository is rejected',()=>{
    const other=join(dir,`plain-repo-${++seq}`);mkdirSync(other);git(other,'init','-q');
    const home=join(other,'state');mkdirSync(home);writeFileSync(join(home,'config.json'),JSON.stringify({trusted_roots:[cwd]}));
    const r=run(['run','--cd',cwd,'--packet',p],{keepConfig:true,env:{...env,CLAUDE_DISPATCH_HOME:home}});
    assert.equal(r.status,2,r.stderr+r.stdout);assert.match(r.stderr,/inside a Git repository/);
  });
  // Final review: an inherited relative Node preload must never resolve to repository content.
  test('a relative NODE_OPTIONS preload in the operator environment never runs repository code',()=>{
    const ws=workspace();const marker=join(dir,`preload-ran-${seq}`);
    writeFileSync(join(ws,'bootstrap.cjs'),`require('fs').writeFileSync(${JSON.stringify(marker)},'ran');`);
    // The runner itself starts in a directory whose bootstrap.cjs is harmless.
    const benign=join(dir,`benign-${seq}`);mkdirSync(benign);writeFileSync(join(benign,'bootstrap.cjs'),'');
    const r=run(['run','--cd',ws,'--packet',packet()],{cwd:benign,env:{...env,NODE_OPTIONS:'--require ./bootstrap.cjs'}});
    assert.equal(existsSync(marker),false,'the repository preload ran');
    assert.equal(r.status,0,r.stderr+r.stdout);
    // Positive control: the same preload really runs for a Node process started in the repository.
    spawnSync(process.execPath,['-e','0'],{cwd:ws,env:{...env,NODE_OPTIONS:'--require ./bootstrap.cjs'}});
    assert.equal(existsSync(marker),true,'positive control: the preload should run without the scrub');
  });
  test('the workspace link scan is bounded even for deeply nested paths',()=>{
    const ws=workspace();const deep=join(ws,...Array.from({length:30},(_,i)=>`d${i}`));
    mkdirSync(deep,{recursive:true});writeFileSync(join(deep,'f.txt'),'x');git(ws,'add','.');commit(ws,'deep');
    const r=run(['run','--cd',ws,'--packet',packet()],{leafLimit:10});
    assert.equal(r.status,3,r.stderr+r.stdout);assert.match(r.stderr,/link scan exceeds its inspection limit/);
  });
  // Confirmation round: no network or transport command, even for a partial clone with missing objects.
  test('a partial clone with a missing tree never runs its repository-configured ssh command',()=>{
    const origin=workspace();git(origin,'config','uploadpack.allowFilter','true');
    const partial=join(dir,`partial-${++seq}`);
    const cloned=spawnSync('git',['-c','protocol.file.allow=always','clone','-q','--no-checkout','--filter=tree:0',
      'file:///'+origin.replaceAll('\\','/'),partial],{encoding:'utf8'});
    assert.equal(cloned.status,0,cloned.stderr);
    roots.push(partial);
    const marker=join(dir,`ssh-ran-${seq}`);const ssh=join(dir,`ssh-${seq}.cjs`);
    writeFileSync(ssh,`require('fs').writeFileSync(${JSON.stringify(marker)},'ran');process.exit(1);`);
    git(partial,'remote','set-url','origin','ssh://localhost/never');
    git(partial,'config','core.sshCommand',`"${process.execPath.replaceAll('\\','/')}" "${ssh.replaceAll('\\','/')}"`);
    const r=run(['run','--cd',partial,'--packet',packet(),'--mode','workspace-write','--allow','tracked.txt']);
    assert.equal(existsSync(marker),false,'the repository ssh command ran during preflight');
    assert.equal(r.status,3,r.stderr+r.stdout);
    // Positive control: plain Git really does lazily fetch, and so runs the command.
    spawnSync('git',['-C',partial,'ls-tree','-r','HEAD'],{encoding:'utf8'});
    assert.equal(existsSync(marker),true,'positive control: plain Git should attempt the lazy fetch');
  });
  test('worker output past the capture ceiling stops the turn and fails the run',()=>{
    const {r,result}=execute('read-only',{flood:true},[]);
    assert.equal(r.status,7,r.stderr+r.stdout);assert.match(result.error_detail,/exceeded \d+ characters; turn stopped/);
    assert.equal(result.cleanup_confirmed,true);
  });
  console.log(`\n${passed} tests passed`);
} finally {
  // Targets are absolute mkdtemp results under the known test roots; no shell deletion.
  // Retries: an orphaned filter process from the hang test may still hold its directory briefly.
  for(const path of [dir,outside,state]) {
    try { rmSync(path,{recursive:true,force:true,maxRetries:30,retryDelay:500}); }
    catch(error) { console.log(`WARN could not remove ${path}: ${error.code}`); }
  }
  for(const path of packetFiles) rmSync(path,{recursive:true,force:true});
}
