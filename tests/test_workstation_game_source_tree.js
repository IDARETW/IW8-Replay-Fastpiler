'use strict';
const assert=require('node:assert/strict');
const tree=require('../workstation/web/workspace_tree.js');

const page={label:'IW8',total:3,offset:0,limit:2,breadcrumbs:[{id:null,label:'IW8'}],items:[
  {id:'opaque-code',kind:'folder',name:'Code'},
  {id:'opaque-zone',kind:'zone',name:'mp_frontendc3s5.ff',relative_path:'zone/mp_frontendc3s5.ff',source_status:'source-header-checked',bytes:128,inventory_cached:false,extract_target:'zone/mp_frontendc3s5.ff'}
]};
assert.equal(tree.validatePage(page),page);
assert.equal(tree.url(null,'',0,100),'/api/workspace/tree?offset=0&limit=100');
assert.equal(tree.url('opaque/one','origin field',100,60),'/api/workspace/tree?node=opaque%2Fone&q=origin+field&offset=100&limit=60');
assert.deepEqual(tree.action(page.items[0]),{type:'navigate',node:'opaque-code'});
assert.equal(tree.action(page.items[1]).zone.relative_path,'zone/mp_frontendc3s5.ff');
assert.equal(tree.range(page),'1–2 of 3');
assert.equal(tree.range({...page,items:[],offset:3,total:3}),'0–0 of 3');
assert.equal(tree.range({...page,items:[],offset:12,total:3}),'0–0 of 3');
assert.equal(tree.validatePage({...page,items:[],offset:12,total:3}).offset,12);

const leaves=[
  {id:'s',kind:'source',name:'Com_Test',target:{id:'fn_1',variant:'cpp'}},
  {id:'g',kind:'global',name:'ui_test',target:{id:'sym_1',variant:'global-initializer'}},
  {id:'f',kind:'file',name:'engine.cpp',target:{path:'src/engine.cpp'}},
  {id:'a',kind:'asset',name:'image',zone_id:'zone',relative_path:'zone/mp_frontendc3s5.ff',target:{asset_id:'zone:3'}}
];
assert.deepEqual(leaves.map(tree.action).map(x=>x.type),['source','source','file','asset']);
assert.equal(tree.action(leaves[2]).path,'src/engine.cpp');
assert.equal(tree.action(leaves[3]).assetId,'zone:3');

// Real inventory identities supplied for the unified tree review: a recovered
// code function/global, authored source, named asset rows, and an unnamed
// native-table row. The tree keeps target identities independent of labels.
const replayZone={relative_path:'code_post_gfx.ff',zone_id:'f68e1d7599862fa0fa90489309b7313c6039a8bb8c1de19ab32c290857cee6bd'};
const replayAssets=[
  {id:'row-514',kind:'asset',name:'cs_fence.hlsl',type:'shader',type_id:12,
    relative_path:replayZone.relative_path,zone_id:replayZone.zone_id,index:514,
    target:{asset_id:`${replayZone.zone_id}:514`}},
  {id:'row-165',kind:'asset',name:'damage_feedback',type:'image',type_id:19,
    relative_path:'common.ff',zone_id:'9bc95e3362f601e2d4bb04f888f26f21fa7563e5c29e0f86f0ded64527829014',index:165,
    target:{asset_id:'9bc95e3362f601e2d4bb04f888f26f21fa7563e5c29e0f86f0ded64527829014:165'}},
  {id:'row-omnvars',kind:'asset',name:'mp/omnvars.csv',type:'stringtable',type_id:54,
    relative_path:replayZone.relative_path,zone_id:replayZone.zone_id,index:901,
    target:{asset_id:`${replayZone.zone_id}:901`}},
  {id:'row-unknown',kind:'asset',name:'asset-999',type:'Type 77',type_id:77,
    relative_path:replayZone.relative_path,zone_id:replayZone.zone_id,index:999,
    native_name_available:false,identity_status:'xasset-index-only',
    target:{asset_id:`${replayZone.zone_id}:999`}}
];
for(const item of replayAssets)assert.equal(tree.validatePage({
  label:'fixture',total:1,offset:0,limit:100,breadcrumbs:[{id:null,label:'IW8'}],items:[item]
}).items[0],item);
assert.deepEqual(replayAssets.map(item=>tree.action(item).assetId),[
  `${replayZone.zone_id}:514`,
  '9bc95e3362f601e2d4bb04f888f26f21fa7563e5c29e0f86f0ded64527829014:165',
  `${replayZone.zone_id}:901`,
  `${replayZone.zone_id}:999`
]);
assert.equal(tree.action({id:'global-ui',kind:'global',name:'ui_serverFrameDuration',
  target:{id:'sym_ui_serverFrameDuration',variant:'global-initializer'}}).variant,'global-initializer');
assert.equal(tree.action({id:'authored-header',kind:'file',name:'cs_fence.hlsl',
  target:{path:'source-workstation/cs_fence.hlsl'}}).path,'source-workstation/cs_fence.hlsl');
for(const bad of [
  {...page,total:-1},
  {...page,items:[...page.items,{...page.items[0]}]},
  {...page,items:[{id:'x',kind:'alien',name:'bad'}]},
  {...page,items:[{id:'x',kind:'file',name:'bad'}]},
  {...page,items:[{id:'x',kind:'asset',name:'bad',target:{asset_id:'x'}}]},
  {...page,breadcrumbs:[{id:4,label:'bad'}]},
  {...page,items:[...page.items,{id:'too-many',kind:'folder',name:'Overflow'}]}
])assert.throws(()=>tree.validatePage(bad),TypeError);
console.log('workspace tree contract tests passed');
