// Application-level unit tests with a synthetic DOM and mock fetch; no browser,
// production credentials, local storage, real network or password changes.
const assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
class Element {
 constructor(tag='div'){this.tag=tag;this.value='';this.type='password';this.checked=false;this.disabled=false;this.open=false;this.children=[];this.listeners={};this.textContent='';}
 append(...x){this.children.push(...x);}replaceChildren(...x){this.children=x;}
 showModal(){this.open=true;}close(){this.open=false;}focus(){}
 addEventListener(t,f){this.listeners[t]=f;}
 querySelector(){return new Element('button');}
}
const elements=new Map(),get=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
let revision=4,calls=[],fakePassword='Fixture-current-only';
const node={id:'1'.repeat(32),label:'Fixture',state:'enabled',online:true,tunnel_ready:true,direct_ready:true,direct_published:true,direct_port:24443,usage_mode:'password',password_kind:'random',usage_revision:4};
const context=vm.createContext({
 document:{getElementById:get,createElement:t=>new Element(t),addEventListener(){}},
 navigator:{clipboard:{writeText:async()=>{}}},console,
 setInterval:()=>1,clearInterval(){},setTimeout:()=>1,
 confirm:()=>true,prompt:()=>null,Blob,URL,
 fetch:async(url,options)=>{
  const body=options.body?JSON.parse(options.body):null;calls.push({url,body});
  if(url.endsWith('/api/nodes'))return {ok:true,json:async()=>({csrf:'fixture-csrf',nodes:[{...node,usage_revision:revision}],capacity:32,total_rate_kib:256})};
  if(body?.mode==='set'){revision++;fakePassword=body.password;}
  if(body?.mode==='rotate'){revision++;fakePassword='Fixture-random-next';}
  return {ok:true,json:async()=>({server:'203.0.113.20',port:24443,method:'aes-256-gcm',password:fakePassword,ss_uri:'ss://fixture-not-real',flclash_yaml:'fixture',revision})};
 }
});
vm.runInContext(fs.readFileSync(require('node:path').join(__dirname,'../server/app.js'),'utf8'),context);
const run=code=>vm.runInContext(code,context);
(async()=>{
 await new Promise(setImmediate);calls=[];
 run(`openPasswordForm({id:'${node.id}',label:'Fixture',usage_revision:4})`);
 assert.equal(get('passwordDialog').open,true);assert.equal(calls.length,0);
 assert.equal(get('newNodePassword').value,'');assert.equal(get('confirmNodePassword').value,'');
 get('newNodePassword').value='Fixture-choice-123';get('confirmNodePassword').value='mismatch';
 await run(`savePassword('set')`);assert.equal(calls.length,0);assert.match(get('passwordFormError').textContent,/不一致/);
 get('confirmNodePassword').value='Fixture-choice-123';
 await run(`savePassword('set')`);
 const saved=calls.find(x=>x.body?.mode==='set');assert(saved);
 assert.equal(saved.body.password,'Fixture-choice-123');assert.equal(saved.body.confirmation,'Fixture-choice-123');assert.equal(saved.body.expected_revision,4);
 assert.equal(get('passwordDialog').open,false);assert.equal(get('newNodePassword').value,'');assert.equal(get('confirmNodePassword').value,'');
 assert.equal(get('credentialDialog').open,true);
 assert.equal(get('nodePassword').value,'Fixture-choice-123');
 get('editNodePassword').onclick();assert.equal(get('passwordDialog').open,true);assert.equal(get('credentialDialog').open,false);
 run('closePasswordForm()');assert.equal(get('newNodePassword').value,'');
 const before=calls.length;run(`openPasswordForm({id:'${node.id}',label:'Fixture',usage_revision:5})`);assert.equal(calls.length,before);
 await run(`savePassword('rotate')`);assert.equal(calls.findLast(x=>x.body?.mode==='rotate').body.expected_revision,5);
 assert.equal(get('nodePassword').value,'Fixture-random-next');
 console.log(JSON.stringify({panel_password_unit_tests:'passed',opening_never_rotates:true,mismatch_blocks_submit:true,custom_payload_and_revision:true,secret_cleanup:true,random_choice:true}));
})().catch(e=>{console.error(e);process.exitCode=1;});
