(function(root,factory){
  const api=factory();
  if(typeof module==='object'&&module.exports)module.exports=api;
  else root.ReplayWorkspaceTree=api;
})(typeof globalThis==='object'?globalThis:this,function(){
  'use strict';
  const kinds=new Set(['folder','source','global','file','asset','zone']);
  function isRecord(value){return value!==null&&typeof value==='object'&&!Array.isArray(value);}
  function validatePage(value){
    if(!isRecord(value)||!Array.isArray(value.items)||!Array.isArray(value.breadcrumbs))throw new TypeError('Invalid workspace tree response.');
    for(const key of ['total','offset','limit'])if(!Number.isSafeInteger(value[key])||value[key]<0)throw new TypeError(`Invalid workspace tree ${key}.`);
    if(value.limit===0)throw new TypeError('Workspace tree page limit must be positive.');
    if(typeof value.label!=='string'||!value.label.trim())throw new TypeError('Workspace tree label is missing.');
    if(value.items.length>value.limit||(value.items.length>0&&value.offset+value.items.length>value.total))throw new TypeError('Workspace tree page bounds are inconsistent.');
    const ids=new Set();
    for(const item of value.items){
      if(!isRecord(item)||!kinds.has(item.kind)||typeof item.name!=='string'||!item.name.trim())throw new TypeError('Workspace tree item is malformed.');
      if(typeof item.id!=='string'||!item.id)throw new TypeError('Workspace tree item id is missing.');
      if(ids.has(item.id))throw new TypeError('Workspace tree contains duplicate item ids.');
      ids.add(item.id);
      if(['folder','zone'].includes(item.kind)&&!item.id)throw new TypeError('Navigable tree item has no id.');
      if(item.kind==='source'&&(!isRecord(item.target)||typeof item.target.id!=='string'||typeof item.target.variant!=='string'))throw new TypeError('Source target is missing.');
      if(item.kind==='global'&&(!isRecord(item.target)||typeof item.target.id!=='string'))throw new TypeError('Global target is missing.');
      if(item.kind==='file'&&(!isRecord(item.target)||typeof item.target.path!=='string'))throw new TypeError('File target is missing.');
      if(item.kind==='asset'&&(!isRecord(item.target)||typeof item.target.asset_id!=='string'))throw new TypeError('Asset target is missing.');
      if(item.kind==='zone'&&(typeof item.relative_path!=='string'||typeof item.extract_target!=='string'||typeof item.inventory_cached!=='boolean'))throw new TypeError('Fastfile identity is incomplete.');
      if(item.kind==='asset'&&(typeof item.relative_path!=='string'||typeof item.zone_id!=='string'))throw new TypeError('Asset owning fastfile identity is missing.');
    }
    for(const crumb of value.breadcrumbs)if(!isRecord(crumb)||typeof crumb.label!=='string'||!(crumb.id===null||typeof crumb.id==='string'))throw new TypeError('Workspace breadcrumb is malformed.');
    return value;
  }
  function url(node,query='',offset=0,limit=100){
    const params=new URLSearchParams();if(node)params.set('node',node);if(query)params.set('q',query);params.set('offset',String(offset));params.set('limit',String(limit));
    return `/api/workspace/tree?${params.toString()}`;
  }
  function action(item){
    if(!isRecord(item)||!kinds.has(item.kind))throw new TypeError('Unknown workspace tree item.');
    if(item.kind==='folder')return {type:'navigate',node:item.id};
    if(item.kind==='zone')return {type:'zone',node:item.id,zone:item};
    if(item.kind==='source'||item.kind==='global')return {type:'source',id:item.target.id,variant:item.target.variant||(item.kind==='global'?'global-initializer':'assembly')};
    if(item.kind==='file')return {type:'file',path:item.target.path};
    return {type:'asset',assetId:item.target.asset_id,asset:item};
  }
  function range(page){
    if(!page.total||page.offset>=page.total)return `0–0 of ${page.total.toLocaleString()}`;
    const first=page.offset+1;
    const last=Math.min(page.offset+page.items.length,page.total);
    return `${first}–${last} of ${page.total.toLocaleString()}`;
  }
  function checkedAsset(asset,id,metadata){
    if(!isRecord(asset)||asset.asset_id!==id)
      throw new Error('The checked asset identity does not match the selected catalog row. Search again before editing.');
    if(metadata?.metadata_only!==true)return asset;
    // Some checked native metadata responses omit zone_id. The canonical
    // asset ID already binds that zone and row; never infer it from UI state.
    const identity=/^([0-9a-f]{64}):(0|[1-9][0-9]*|new-[0-9a-f]{32})$/.exec(id);
    const zone=asset.zone_id===undefined?identity?.[1]:asset.zone_id;
    if(!identity||metadata.zone_id!==identity[1]||zone!==identity[1]||
       (Number.isSafeInteger(metadata.index)&&
         (String(metadata.index)!==identity[2]||asset.index!==metadata.index))||
       (Number.isSafeInteger(metadata.type_id)&&asset.type_id!==metadata.type_id))
      throw new Error('The checked asset no longer matches the fastfile row identity in this search result. Search again before editing.');
    return asset.zone_id===undefined?{...asset,zone_id:zone}:asset;
  }
  return Object.freeze({validatePage,url,action,range,checkedAsset});
});
// Load the presentation layer after the base editor scripts. Keeping it out of
// the initial parallel burst also avoids exhausting the local HTTP backlog.
if (typeof document === 'object') document.addEventListener('DOMContentLoaded', () => {
  const script = document.createElement('script');
  script.src = '/workspace_explorer.js';
  document.body.append(script);
}, {once: true});
