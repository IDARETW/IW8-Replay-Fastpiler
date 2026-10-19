const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const vm=require('node:vm');

const source=fs.readFileSync(path.join(__dirname,'../workstation/web/app.js'),'utf8');
const start=source.indexOf('async function loadSoundEntries(');
const end=source.indexOf('\nasync function saveSound(',start);
assert.ok(start>=0&&end>start);
function node(){
  return {hidden:false,inert:false,dataset:{},attributes:{},children:[],
    setAttribute(k,v){this.attributes[k]=v;},removeAttribute(k){delete this.attributes[k];},
    replaceChildren(...children){this.children=children;},focus(){}};
}
const panel=node(),mask=node(),controls=node(),editor=node();
panel.children=[controls,mask];
let apiImpl,requests=0;
const sandbox={
  state:{zone:{relative_path:'sound.ff'},asset:{asset_id:'bank-a'}},
  assetRequest:1,soundLoadOwner:0,soundPanel:panel,soundLoadMask:mask,
  soundLoadTitle:node(),soundLoadDetail:node(),soundLoadRetry:node(),
  soundNotice:node(),soundSelect:node(),soundExport:node(),
  soundSave:node(),soundGainSave:node(),soundEntries:[],soundDrafts:[],
  $:id=>{assert.equal(id,'asset-content');return {parentElement:editor};},
  api:route=>{assert.equal(route,'/api/sounds?path=sound.ff');requests++;return apiImpl();},
  element:()=>node(),guard:fn=>fn,selectSound:()=>{},
};
vm.createContext(sandbox);vm.runInContext(source.slice(start,end),sandbox);
const assetA={asset_id:'bank-a',editable:true},assetB={asset_id:'bank-b',editable:true};
const empty=()=>({entries:[],drafts:[]});

(async()=>{
  let resolve;
  apiImpl=()=>new Promise(r=>{resolve=r;});
  const loading=sandbox.loadSoundEntries(assetA,1);
  assert.equal(editor.hidden,false,'editable alias source remains visible during audio acquisition');
  assert.equal(mask.hidden,false);
  assert.equal(controls.inert,true,'pending audio controls cannot be used');
  resolve(empty());await loading;
  assert.equal(mask.hidden,true);assert.equal(controls.inert,false);

  apiImpl=()=>Promise.reject(new Error('audio read failed'));
  await assert.rejects(sandbox.loadSoundEntries(assetA,1),/audio read failed/);
  assert.equal(mask.hidden,false,'failed audio loading keeps its blocker');
  assert.equal(controls.inert,true);
  assert.equal(editor.hidden,false,'audio failure does not hide the alias editor');
  const staleRetry=sandbox.soundLoadRetry.onclick;

  sandbox.state.asset=assetB;sandbox.assetRequest=2;
  apiImpl=()=>new Promise(r=>{resolve=r;});
  const next=sandbox.loadSoundEntries(assetB,2),before=requests;
  await staleRetry();
  assert.equal(requests,before,'retry from an old bank cannot start a new request');
  assert.equal(mask.hidden,false);
  resolve(empty());await next;

  let resolveOld,resolveNew;
  sandbox.state.asset=assetA;sandbox.assetRequest=3;
  apiImpl=()=>new Promise(r=>{resolveOld=r;});
  const old=sandbox.loadSoundEntries(assetA,3);
  sandbox.state.asset=assetB;sandbox.assetRequest=4;
  apiImpl=()=>new Promise(r=>{resolveNew=r;});
  const newer=sandbox.loadSoundEntries(assetB,4);
  resolveOld(empty());await old;
  assert.equal(mask.hidden,false,'old completion cannot dismiss the selected bank blocker');
  assert.equal(controls.inert,true);
  resolveNew(empty());await newer;
  assert.equal(mask.hidden,true);assert.equal(controls.inert,false);
  console.log('SoundBank alias visibility and scoped audio loading regression passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
