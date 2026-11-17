// Actual production functions executed with a minimal DOM, no copied logic.
import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const root = new URL('../', import.meta.url);
function read(path) {return fs.readFileSync(new URL(path,root),'utf8');}
function between(text,start,end) {return text.slice(text.indexOf(start),text.indexOf(end,text.indexOf(start)));}
const esc = s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

test('portal weekday zero displays Monday, matching stored schedules',()=>{
  const ctx=vm.createContext({esc});
  vm.runInContext(between(read('portal/app.js'),'function renderSchedules(', 'async function loadPolicies'),ctx);
  const result=vm.runInContext(`renderSchedules([{name:'school',days:[0,6],start:540,end:600,timezone:'UTC',block_domains:['bad.example']}])`,ctx);
  assert.match(result,/Mon, Sun/);
});

function guardianContext(answers){
  class Element {
    constructor(){this.children=[];this.textContent='';this.innerHTML='';}
    appendChild(e){this.children.push(e);}
    querySelector(){return this;}
  }
  const table=new Element(), error=new Element();
  const sent=[];
  let reads=0;
  const ctx=vm.createContext({esc,accountInfo:{role:'owner'},
    document:{createElement:()=>new Element(),createTextNode:t=>({textContent:t})},
    $:id=>id==='guardians-table'?table:error,
    prompt:()=>answers.shift(),
    api:async(path,options)=>{
      if(options){sent.push({path,body:JSON.parse(options.body)});return {status:200,body:{}};}
      reads++;
      return {status:200,body:{guardians:reads===1?[{id:2,email:'guardian@example.test',role:'guardian',created_at:'2026-01-01'}]:[]}};
    },HDR:{'X-KosherGuard-Request':'1'}
  });
  vm.runInContext(between(read('control-plane/web/app.js'),'async function refreshGuardians()', '$("guardian-invite-form")'),ctx);
  return {ctx,table,sent};
}

test('MFA reset UI includes password, TOTP and explicit confirmation',async()=>{
  const {ctx,table,sent}=guardianContext(['test password','123456','mfa-reset']);
  await vm.runInContext('refreshGuardians()',ctx);
  const reset=table.children[0].children[0].children.find(e=>e.textContent==='reset MFA');
  await reset.onclick();
  assert.equal(sent.length,1);
  assert.equal(sent[0].path,'/api/guardians/2/mfa-reset');
  assert.deepEqual(sent[0].body,{password:'test password',totp_code:'123456',confirm:'mfa-reset'});
});

test('MFA reset UI cancels without sending when confirmation is cancelled',async()=>{
  const {ctx,table,sent}=guardianContext(['test password','123456',null]);
  await vm.runInContext('refreshGuardians()',ctx);
  const reset=table.children[0].children[0].children.find(e=>e.textContent==='reset MFA');
  await reset.onclick();
  assert.equal(sent.length,0);
});
