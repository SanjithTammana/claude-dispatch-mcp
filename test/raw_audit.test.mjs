#!/usr/bin/env node
// Raw filesystem tests with a metadata-only Git double. No native Git or containment required.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {mkdirSync,mkdtempSync,readFileSync,rmSync,writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {snapshot,compare,requireClean,DEFAULT_LEAF_LIMIT,SNAPSHOT_MS} from '../src/raw_audit.mjs';

const root=mkdtempSync(join(tmpdir(),'cdm-raw-'));
let passed=0;
function test(name,fn) {fn();passed++;console.log('PASS '+name);}
const oid=content=>createHash('sha1').update(`blob ${Buffer.byteLength(content)}\0`).update(content).digest('hex');
const index=[{path:'victim.js',mode:'100644',stage:'0',oid:oid('const value = "$Id$";\n')}];
let others=[],ignored=[],hidden=[],head='a'.repeat(40),failGit=false;
const commands=[];
function runner(_root,args) {
  commands.push(args);
  if(failGit) return {ok:false,out:'',err:'injected metadata failure'};
  let out='';
  if(args[0]==='ls-files') {
    if(args.includes('--stage')) out=index.map(e=>`${e.mode} ${e.oid} ${e.stage}\t${e.path}\0`).join('');
    else if(args.includes('-v')) out=hidden.map(p=>'h '+p+'\0').join('');
    else out=(args.includes('--ignored')?ignored:others).map(p=>p+'\0').join('');
  } else if(args[0]==='ls-tree') out=index.map(e=>`${e.mode} blob ${e.oid}\t${e.path}\0`).join('');
  else if(args[0]==='rev-parse') out=args.includes('--show-object-format')?'sha1\n':head+'\n';
  else assert.fail('unexpected content-reading Git command: '+args.join(' '));
  return {ok:true,out,err:''};
}
const snap=(mode='workspace-write',limit=DEFAULT_LEAF_LIMIT,bounds={})=>snapshot(root,mode,limit,runner,bounds);
const request={mode:'workspace-write',allow:['allowed.txt']};
const victim=join(root,'victim.js');
try {
  writeFileSync(victim,'const value = "$Id$";\n');
  test('snapshot fingerprints every indexed file by metadata, without a status or diff command',()=>{
    const s=snap();assert.equal(s.error,null);const r=s.records.get('victim.js');
    for(const key of ['size','mtime','ctime','birth','id','nlink']) assert.ok(r[key]!==undefined,key);
    assert.ok(commands.every(a=>!['status','diff','hash-object'].includes(a[0])));
  });
  test('the raw audit reads no file content',()=>{
    const source=readFileSync(new URL('../src/raw_audit.mjs',import.meta.url),'utf8');
    // Directory listings (Dir#readSync) are expected; file-content reads are not.
    assert.ok(!/readFileSync|\bopenSync\b|createReadStream|createHash|readSync\(\s*fd/.test(source));
  });
  test('rewriting identical bytes still counts as a change (timestamps move)',()=>{
    const before=snap('read-only');writeFileSync(victim,readFileSync(victim));
    assert.equal(compare({mode:'read-only',allow:[]},before,snap('read-only')).scope_check,'VIOLATION');
  });
  test('ident injection outside allow is a violation despite unchanged index',()=>{
    const before=snap();writeFileSync(victim,'const value = "$Id: "; globalThis.executed = true; // $";\n');
    const result=compare(request,before,snap());assert.equal(result.scope_check,'VIOLATION');
    assert.deepEqual(result.files_changed,['victim.js']);
  });
  test('converted raw checkout can establish a write baseline without matching index bytes',()=>{
    writeFileSync(victim,'const value = "$Id: expanded $";\r\n');
    const s=snap();assert.doesNotThrow(()=>requireClean(root,s,runner));
  });
  test('CRLF to LF raw change outside allow is detected',()=>{
    const before=snap();writeFileSync(victim,readFileSync(victim,'utf8').replaceAll('\r\n','\n'));
    assert.equal(compare(request,before,snap()).scope_check,'VIOLATION');
  });
  test('an allowed tracked byte edit passes; same edit fails in read-only mode',()=>{
    const before=snap();writeFileSync(victim,'allowed bytes');const after=snap();
    assert.equal(compare({mode:'workspace-write',allow:['victim.js']},before,after).scope_check,'PASS');
    assert.equal(compare({mode:'read-only',allow:[]},before,after).scope_check,'VIOLATION');
  });
  test('tracked deletion remains a changed path',()=>{
    const before=snap();rmSync(victim);const result=compare(request,before,snap());
    assert.equal(result.scope_check,'VIOLATION');assert.deepEqual(result.files_changed,['victim.js']);
    writeFileSync(victim,'restored');
  });
  test('new allowed ignored leaf permits necessary parents but rejects a sibling leaf',()=>{
    const before=snap();mkdirSync(join(root,'ignored','deep'),{recursive:true});
    writeFileSync(join(root,'ignored','deep','ok.txt'),'ok');ignored=['ignored/'];
    const a={mode:'workspace-write',allow:['ignored/deep/ok.txt']};
    assert.equal(compare(a,before,snap()).scope_check,'PASS');
    writeFileSync(join(root,'ignored','deep','bad.txt'),'bad');
    assert.equal(compare(a,before,snap()).scope_check,'VIOLATION');
  });
  test('write baseline refuses ignored entries',()=>assert.throws(()=>requireClean(root,snap(),runner),/clean worktree/));
  test('read-only collapses ignored trees without reading their bytes',()=>{
    const before=snap('read-only');writeFileSync(join(root,'ignored','deep','bad.txt'),'edited');
    assert.equal(before.records.get('ignored').type,'ignored-listed');
    assert.equal(compare({mode:'read-only',allow:[]},before,snap('read-only')).scope_check,'PASS');
  });
  test('the inventory limit counts index, untracked and ignored entries together',()=>{
    others=['new.txt'];const s=snap('read-only',2);assert.match(s.error,/inventory exceeds entry limit/);
    assert.equal(compare(request,s,s).scope_check,'UNKNOWN');others=[];
  });
  test('expanded ignored tree exceeding the limit is UNKNOWN',()=>{
    const s=snap('workspace-write',3);assert.match(s.error,/entry limit|audit limit/);
    assert.equal(compare(request,s,s).scope_check,'UNKNOWN');
  });
  ignored=[];
  test('ancestor directories are charged to the inspection budget',()=>{
    // Six files in six distinct directories: 6 listing entries, but 12 filesystem inspections.
    for(let i=0;i<6;i++) {mkdirSync(join(root,`a${i}`),{recursive:true});writeFileSync(join(root,`a${i}`,'f.txt'),'x');}
    others=Array.from({length:6},(_,i)=>`a${i}/f.txt`);
    const s=snap('read-only',10);assert.match(s.error,/audit limit/);
    assert.equal(snap('read-only',20).error,null);others=[];
  });
  test('the inspection deadline fails as UNKNOWN with a clear message',()=>{
    const before=snap(),s=snap('workspace-write',DEFAULT_LEAF_LIMIT,{ms:0});
    assert.match(s.error,/audit limit/);assert.equal(compare(request,before,s).scope_check,'UNKNOWN');
  });
  test('metadata failure becomes UNKNOWN instead of an exception',()=>{
    failGit=true;const s=snap();failGit=false;
    assert.match(s.error,/metadata failure/);assert.equal(compare(request,s,s).scope_check,'UNKNOWN');
  });
  test('hidden flags and HEAD/index changes are violations even with identical raw bytes',()=>{
    const before=snap();hidden=['victim.js'];assert.equal(compare(request,before,snap()).scope_check,'VIOLATION');hidden=[];
    head='b'.repeat(40);assert.equal(compare(request,before,snap()).scope_check,'VIOLATION');head=before.head;
    index[0].oid='c'.repeat(40);assert.equal(compare(request,before,snap()).scope_check,'VIOLATION');
  });
  test('unmerged index and index/HEAD disagreement refuse a write baseline',()=>{
    const s=snap();s.index=s.index.map(e=>({...e,stage:'1'}));assert.throws(()=>requireClean(root,s,runner),/clean index/);
    const differing=(r,args)=>args[0]==='ls-tree'?{ok:true,out:'',err:''}:runner(r,args);
    assert.throws(()=>requireClean(root,snap(),differing),/clean index/);
  });
  test('new links are violations even when the path is allowed',()=>{
    const before=snap(),after=snap();after.records.set('allowed.txt',{type:'link',link:true,target:'outside'});
    assert.equal(compare(request,before,after).scope_check,'VIOLATION');
    after.records.set('allowed.txt',{type:'file',link:false,nlink:2,hash:'x'});
    assert.equal(compare(request,before,after).scope_check,'VIOLATION');
  });
  test('production bounds are explicit',()=>{
    assert.equal(DEFAULT_LEAF_LIMIT,20000);assert.equal(SNAPSHOT_MS,120000);
  });
  console.log(`\n${passed} tests passed`);
} finally {rmSync(root,{recursive:true,force:true});}
