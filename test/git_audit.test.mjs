#!/usr/bin/env node
// Test actual Git invocation construction and phase lifetime with a spawn double.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {isAbsolute,join} from 'node:path';
import vm from 'node:vm';
let passed=0;
function test(name,fn){fn();passed++;console.log('PASS '+name);}
const source=readFileSync(new URL('../src/git_audit.mjs',import.meta.url),'utf8')
  .replace(/^import .*;\r?\n/gm,'').replace(/^export /gm,'');
function fixture(){
  const calls=[],configs=new Map([['C:\\one',['filter.late=driver.clean']],['C:\\two',['filter.other.process']]]);
  const context={isAbsolute,join,existsSync:()=>true,statSync:()=>({isFile:()=>true}),realpathSync:{native:p=>p},
    process:{platform:'win32',env:{PATH:'C:\\tools',GIT_CONFIG_COUNT:'1',GIT_CONFIG_KEY_0:'evil',GIT_DIR:'poison',git_work_tree:'poison'}},
    spawnSync:(exe,args,options)=>{calls.push({exe,args,options});const cwd=args[args.indexOf('-C')+1];
      return{status:0,stdout:args.includes('--no-includes')?(configs.get(cwd)||[]).join('\0')+'\0':'',stderr:''};}};
  vm.createContext(context);vm.runInContext(source+'\nthis.phase=gitPhase;',context);
  return{calls,configs,phase:()=>context.phase()};
}
test('literal equals in driver names uses separate configuration keys and values',()=>{
  const f=fixture();assert.ok(f.phase()('C:\\one',['status']).ok);
  const env=f.calls.at(-1).options.env;
  assert.equal(env.GIT_CONFIG_COUNT,'4');assert.equal(env.GIT_CONFIG_KEY_0,'filter.late=driver.clean');
  assert.equal(env.GIT_CONFIG_VALUE_0,'');assert.equal(env.GIT_CONFIG_KEY_3,'filter.late=driver.required');
  assert.equal(env.GIT_CONFIG_VALUE_3,'false');
});
test('system/global config and inherited Git variables are isolated even during config discovery',()=>{
  const f=fixture();f.phase()('C:\\one',['rev-parse','HEAD']);
  for(const c of f.calls){const env=c.options.env;
    assert.equal(env.GIT_CONFIG_NOSYSTEM,'1');assert.equal(env.GIT_CONFIG_GLOBAL,'NUL');
    assert.equal(env.GIT_DIR,undefined);assert.equal(env.git_work_tree,undefined);
    assert.ok(c.args.includes('safe.directory=C:/one'));assert.ok(c.args.includes('core.longpaths=true'));
    assert.ok(c.args.includes('core.fsmonitor=false'));assert.ok(c.options.timeout>0);
  }
});
test('one config read per root per phase; roots never share driver overrides',()=>{
  const f=fixture(),run=f.phase();run('C:\\one',['rev-parse','HEAD']);run('C:\\one',['ls-files']);run('C:\\two',['ls-files']);
  assert.equal(f.calls.filter(c=>c.args.includes('--no-includes')).length,2);
  assert.equal(f.calls.at(-1).options.env.GIT_CONFIG_KEY_0,'filter.other.clean');
});
test('post-turn phase re-reads the frozen configuration and observes new drivers',()=>{
  const f=fixture();f.phase()('C:\\one',['ls-files']);f.configs.set('C:\\one',['filter.new=driver.process']);
  f.phase()('C:\\one',['ls-files']);
  assert.equal(f.calls.filter(c=>c.args.includes('--no-includes')).length,2);
  assert.equal(f.calls.at(-1).options.env.GIT_CONFIG_KEY_0,'filter.new=driver.clean');
});
for(const key of ['include.path','includeif.gitdir:C:/work/.path','filter.bad\nname.clean'])
  test('unsupported config refuses before any downstream Git call: '+JSON.stringify(key),()=>{
    const f=fixture();f.configs.set('C:\\one',[key]);const run=f.phase();
    const r=run('C:\\one',['status']);assert.equal(r.ok,false);assert.match(r.err,/refused|unrepresentable/);
    run('C:\\one',['ls-files']);assert.equal(f.calls.length,1,'refusal cached within the phase');
  });
console.log(`\n${passed} tests passed`);
