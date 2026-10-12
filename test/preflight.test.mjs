#!/usr/bin/env node
// Exercise the real orchestration with deterministic filesystem/process doubles.
// This verifies ordering and refusal, not native Windows alias or Job Object behavior.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import * as path from 'node:path';
import vm from 'node:vm';
let passed=0;
function test(name,fn){fn();passed++;console.log('PASS '+name);}
const source=readFileSync(new URL('../src/preflight.mjs',import.meta.url),'utf8')
  .replace(/^import .*;\r?\n/gm,'').replaceAll('import.meta.dirname','HERE').replace(/^export /gm,'');
function fixture({aliasInside=false,workspaceLink=false,baselineError=false,stateInRepo=false,compilerInside=false}={}) {
  const events=[],root='C:\\work',home='C:\\state',packageRoot='C:\\boundary';
  const config={home,packets:path.join(home,'packets'),runs:path.join(home,'runs'),bin:path.join(home,'bin'),trustedRoots:[root],extraDeny:[]};
  const directory=p=>[root,home,packageRoot,path.join(packageRoot,'src')].includes(p);
  const stat=p=>({isFile:()=>!directory(p),isDirectory:()=>directory(p),isSymbolicLink:()=>false,nlink:1});
  const context={...path,HERE:path.join(packageRoot,'src'),process:{platform:'win32',execPath:'C:\\tools\\node.exe'},
    existsSync:p=>stateInRepo&&p===path.join(home,'.git'),lstatSync:stat,statSync:stat,realpathSync:{native:p=>p},readdirSync:()=>[],
    readFileSync:()=>'',opendirSync:()=>({readSync:()=>null,closeSync:()=>{}}),
    loadConfig:()=>{events.push('read-config');return config;},localPath:p=>p,
    overlaps:(a,b)=>a===b||a.startsWith(b+'\\')||b.startsWith(a+'\\'),gitExecutable:()=> 'C:\\tools\\git.exe',
    hardLinks:p=>{events.push('links:'+p);return aliasInside&&p.endsWith('git.exe')?[p,path.join(root,'git-alias.exe')]:[p];},
    setGitTimeout:()=>{},gitPhase:()=>{events.push('new-git-phase');return(_root,args)=>{
      events.push('git:'+args[0]);return{ok:true,out:args.includes('--show-toplevel')?root+'\n':'C:\\admin\n',err:''};};},
    inventory:()=>({index:[],others:workspaceLink?['alias.txt']:[],ignored:[]}),DEFAULT_LEAF_LIMIT:20000,SNAPSHOT_MS:120000,
    submodules:()=>{events.push('submodules');return{paths:[],error:null};},
    snapshot:()=>{events.push('snapshot');return{error:baselineError?'byte limit exceeded':null,hidden:[],records:new Map()};},
    requireClean:()=>events.push('clean'),jobrunPath:(_bin,options)=>{
      events.push('select-launcher');options.validateCompiler(compilerInside?path.join(root,'csc.exe'):'C:\\tools\\csc.exe');
      events.push('compile');return'C:\\state\\bin\\jobrun.exe';}};
  if(workspaceLink) context.lstatSync=p=>p.endsWith('alias.txt')?{...stat(p),nlink:2}:stat(p);
  vm.createContext(context);vm.runInContext(source+'\nthis.preflight=preflight;this.order=PREFLIGHT_ORDER;',context);
  const args={command:'run',cd:root,mode:'workspace-write',allow:['allowed.txt']};
  return{events,context,run:()=>context.preflight(args,{testBinary:'C:\\tools\\fake.mjs',onStage:n=>events.push('stage:'+n)})};
}
test('successful preflight completes the declared order before selecting a launcher',()=>{
  const f=fixture();f.run();
  assert.deepEqual(f.events.filter(e=>e.startsWith('stage:')).map(e=>e.slice(6)),Array.from(f.context.order));
  assert.ok(f.events.indexOf('links:C:\\tools\\git.exe')<f.events.indexOf('git:rev-parse'));
  assert.ok(f.events.indexOf('snapshot')<f.events.indexOf('select-launcher'));
});
test('a protected executable alias inside the workspace refuses before any Git execution',()=>{
  const f=fixture({aliasInside:true});assert.throws(f.run,/hard link/);
  assert.ok(!f.events.some(e=>e.startsWith('git:')));assert.ok(!f.events.includes('select-launcher'));
});
test('workspace hard links refuse before raw reads and launcher selection',()=>{
  const f=fixture({workspaceLink:true});assert.throws(f.run,/hard links/);
  assert.ok(!f.events.includes('snapshot'));assert.ok(!f.events.includes('select-launcher'));
});
test('an oversized or unreadable baseline refuses with code 3 before launcher selection',()=>{
  const f=fixture({baselineError:true});assert.throws(f.run,e=>e.code===3&&/byte limit/.test(e.message));
  assert.ok(!f.events.includes('select-launcher'));
});
test('state-in-repository ancestry refuses without invoking Git',()=>{
  const f=fixture({stateInRepo:true});assert.throws(f.run,/inside a Git repository/);
  assert.ok(!f.events.some(e=>e.startsWith('git:')));assert.ok(!f.events.includes('select-launcher'));
});
test('compiler placement is checked before compilation',()=>{
  const f=fixture({compilerInside:true});assert.throws(f.run,/hard link overlaps workspace/);
  assert.ok(!f.events.includes('compile'));
});
test('CLI and MCP both invoke shared preflight, with no serialized bypass ticket',()=>{
  const cli=readFileSync(new URL('../src/claude_dispatch.mjs',import.meta.url),'utf8');
  const mcp=readFileSync(new URL('../src/mcp_server.mjs',import.meta.url),'utf8');
  // The CLI always takes its own baseline; only the MCP pre-launch check skips it.
  assert.match(cli,/preflight\(a,\{\.\.\.options,skipBaseline:false\}\)/);
  assert.match(mcp,/preflight\(request,\{skipBaseline:true\}\)/);
  assert.ok(mcp.indexOf('preflight(request')<mcp.indexOf('writeFileSync(packet'));
  assert.doesNotMatch(mcp,/jobrunPath\(|loadConfig\(/);
});
console.log(`\n${passed} tests passed`);
