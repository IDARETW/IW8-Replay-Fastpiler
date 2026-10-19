'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const tree = require('../workstation/web/workspace_tree.js');
const css = fs.readFileSync(path.resolve(process.env.REPLAY_WORKSTATION_WORKSPACE_CSS || 'workstation/web/workspace.css'), 'utf8');

const appPath = path.resolve(process.env.REPLAY_WORKSTATION_APP_JS || 'workstation/web/app.js');
const app = fs.readFileSync(appPath, 'utf8');

function block(startToken, endToken) {
  const start = app.indexOf(startToken);
  const end = app.indexOf(endToken, start);
  assert.notEqual(start, -1, `missing app block ${startToken}`);
  assert.ok(end > start, `unbounded app block ${startToken}`);
  return app.slice(start, end);
}

class FakeElement {
  constructor(id = '') {
    this.id = id; this.hidden = false; this.disabled = false; this.textContent = '';
    this.value = ''; this.children = []; this.attrs = {}; this.dataset = {}; this.style = {};
    this.classList = { toggle() {}, add() {}, remove() {}, contains() { return false; } };
    this.parentElement = { hidden: false };
    this.inert = false;
  }
  replaceChildren(...items) { this.children = items; }
  append(...items) { this.children.push(...items); }
  querySelector() { return null; }
  focus() { this.focused = true; }
  close() { this.closed = true; }
  setAttribute(key, value) { this.attrs[key] = value; }
  removeAttribute(key) { delete this.attrs[key]; }
}

function setup({ confirm = false } = {}) {
  const ids = new Map();
  for (const id of ['source-search','workspace-breadcrumbs','workspace-catalog-status','workspace-tree-status','source-list','source-range',
    'source-prev','source-next','page-crumb','page-title','source-editor','source-empty',
    'file-editor','file-empty','asset-editor','source-content','file-content','asset-content',
    'zone-name','zone-detail','zone-extract','new-asset','zone-status','asset-create-dialog',
    'workspace-content-load','workspace-content-load-title','workspace-content-load-detail','workspace-content-load-retry',
    'workspace-tree-content','workspace-tree-load','workspace-tree-load-title','workspace-tree-load-detail','workspace-tree-load-retry','workspace-search-scope',
    'workspace-query','workspace-search-status','workspace-results','workspace-search-dialog','workspace-search-close',
    'workspace-search-pagination','workspace-search-range','workspace-search-prev','workspace-search-next']) ids.set(id, new FakeElement(id));
  for (const id of ['source-content','file-content','asset-content']) ids.get(id).selectionStart = 0;
  ids.get('workspace-tree-load').hidden=true;ids.get('workspace-content-load').hidden=true;
  // Match index.html after attachWorkspaceEditors(): the source editor and
  // empty state stay in the host; the old files/assets editor panes are moved
  // directly under it and their editor controls remain nested inside them.
  const host = new FakeElement('host');
  const filePane = new FakeElement('file-pane'); filePane.parentElement = host;
  const assetPane = new FakeElement('asset-pane'); assetPane.parentElement = host;
  filePane.hidden = true; assetPane.hidden = true;
  ids.get('source-editor').parentElement = host;
  ids.get('source-empty').parentElement = host;
  ids.get('file-editor').parentElement = filePane;
  ids.get('asset-editor').parentElement = assetPane;
  host.children=[ids.get('source-empty'),ids.get('source-editor'),filePane,assetPane,ids.get('workspace-content-load')];
  const treeState = {node:'old-folder',query:'',offset:0,total:0,limit:100,request:0,page:null,active:null,zone:null,loadingRequests:0};
  const state = {page:'sources',source:null,file:null,asset:null,zone:null,zoneId:null,
    assetCodecs:{},assetOffset:0};
  const calls = {confirm:[],opened:[],shown:[],rendered:[],api:[],zones:[],activeEditors:[],pages:[]};
  const sandbox = {
    state, workspaceTree:treeState, ReplayWorkspaceTree:tree,
    workspaceCatalogPollInFlight:false,workspaceCatalogPollAttempts:0,workspaceCatalogPollAfter:0,
    workspaceContentLoadRequest:0,
    workspaceGlobalSearchActive:false,workspaceGlobalSearchRequest:0,workspaceGlobalSearchOffset:0,workspaceTreeLoadRequest:0,
    sourceRequest:0,fileRequest:0,assetRequest:0,assetListRequest:0,pageRequest:0,
    window:{confirm(message){calls.confirm.push(message);return confirm;},scrollTo(){}},
    history:{replaceState(){}}, document:{title:'',
      querySelector(selector){if(selector==='#sources .workspace-editor-host')return host;
        if(selector==='.workspace-file-pane')return filePane;
        if(selector==='.workspace-asset-pane')return assetPane;
        throw new Error(`unexpected selector ${selector}`);},
      querySelectorAll(selector){if(selector==='.page'||selector==='nav button')return [];
        throw new Error(`unexpected selector list ${selector}`);}},
    $:id=>{if(!ids.has(id))ids.set(id,new FakeElement(id));return ids.get(id);},
    dirty(kind){const editor=ids.get(`${kind}-content`);return !!state[kind]&&editor.value!==(state[kind].content??'');},
    resetSoundEditor(){},
    invalidateWorkspaceMutationGuards(){},
    invalidateImageRender(){},
    api:async (url)=>{calls.api.push(url);return {};},
    element:(tag,text)=>{const e=new FakeElement();e.tag=tag;e.textContent=text??'';return e;},
    entry:(name,detail,_selected,onClick)=>{const e=new FakeElement();e.append(new FakeElement(),new FakeElement());e.children[0].textContent=name;e.children[1].textContent=detail;e.onclick=onClick;return e;},
    guard:fn=>async(...args)=>fn(...args),
    toast(){},
    loadJobs:async()=>{},
    page:async id=>{calls.pages.push(id);return true;},
    loadWorkspaceTree:async()=>{},
    openSource:async(id,variant)=>calls.opened.push({kind:'source',id,variant}),
    openFile:async(filePath)=>calls.opened.push({kind:'file',path:filePath}),
    openAsset:async(assetId)=>calls.opened.push({kind:'asset',assetId}),
    openZone:zone=>{calls.zones.push(zone);state.zone=zone;state.zoneId=zone.zone_id||null;treeState.zone=zone;},
    renderWorkspaceTree:page=>calls.rendered.push(page),
  };
  vm.createContext(sandbox);
  vm.runInContext(`${block('function canLeave()', 'function entry(')}
    ${block('function activateWorkspaceEditor(kind)', 'function clearWorkspaceSelection()')}
    ${block('function workspaceItemDetail(item)', 'async function loadSources()')}
    this.__selectWorkspaceItem=selectWorkspaceItem; this.__clearWorkspaceSelection=clearWorkspaceSelection;
    this.__loadWorkspaceTree=loadWorkspaceTree; this.__page=page; this.__activateWorkspaceEditor=activateWorkspaceEditor;`, sandbox, {filename:appPath});
  vm.runInContext(`this.__navigateWorkspaceBreadcrumb=navigateWorkspaceBreadcrumb; this.__navigateWorkspaceFolder=navigateWorkspaceFolder; this.__refreshWorkspaceTree=refreshWorkspaceTree; this.__pollWorkspaceCatalog=pollWorkspaceCatalog; this.__renderWorkspaceCatalogStatus=renderWorkspaceCatalogStatus; this.__renderWorkspaceTree=renderWorkspaceTree; this.__workspaceItemDetail=workspaceItemDetail; this.__workspaceSearchProgress=workspaceSearchProgress;`, sandbox, {filename:appPath});
  vm.runInContext(`this.__loadWorkspaceGlobalSearch=loadWorkspaceGlobalSearch; this.__searchFromGameSource=searchFromGameSource; this.__loadWorkspaceResultsPage=loadWorkspaceResultsPage;`, sandbox, {filename:appPath});
  vm.runInContext(`${block('async function openAsset(', 'function showAsset(asset,replaceContent=true)')}
    this.__openAsset=openAsset;`, sandbox, {filename:appPath});
  vm.runInContext(`${block('function openZone(zone)', 'async function extractZone()')}
    this.__openZone=openZone;`, sandbox, {filename:appPath});
  vm.runInContext(`${block('const workspacePages = [', 'let workspaceSearchRequest=')}
    let workspaceSearchRequest=0,workspaceSearchOffset=0,workspaceSearchTotal=0,workspaceSearchLastQuery='';
    ${block('function workspaceSearchStatus(', 'function workspaceSearchResult(item)')}
    ${block('function workspaceSearchResult(item)', 'async function searchWorkspace(')}
    ${block('async function searchWorkspace(', 'function renderWorkspaceSearch()')}
    this.__searchWorkspace=searchWorkspace; this.__workspaceSearchResult=workspaceSearchResult;`, sandbox, {filename:appPath});
  sandbox.openAsset=async assetId=>calls.opened.push({kind:'asset',assetId});
  sandbox.showAsset=asset=>calls.shown.push(asset.asset_id);
  return {sandbox, state, treeState, ids, calls, host, filePane, assetPane};
}

function sourceItem(id='fn-1', name='DB_FindXAssetHeader') {
  return {id:`source:${id}`,kind:'source',name,target:{id,variant:'assembly'}};
}

(async()=>{
  // A rejected cross-kind selection must leave the dirty asset and editor intact.
  const rejected=setup({confirm:false});
  rejected.state.asset={asset_id:'zone:4',content:'baseline',editable:true};
  rejected.ids.get('asset-content').value='unsaved';
  rejected.treeState.active='asset:asset-row';
  await rejected.sandbox.__selectWorkspaceItem(sourceItem());
  assert.equal(rejected.calls.confirm.length,1,'cross-kind selection asks before discarding a dirty buffer');
  assert.equal(rejected.calls.opened.length,0,'cancel prevents switching to another editor target');
  assert.equal(rejected.state.asset.asset_id,'zone:4');
  assert.equal(rejected.ids.get('asset-content').value,'unsaved');

  // Accepting the discard clears all editor models, then opens the chosen source.
  const accepted=setup({confirm:true});
  accepted.state.asset={asset_id:'zone:4',content:'baseline',editable:true};
  accepted.ids.get('asset-content').value='unsaved';
  accepted.treeState.active='asset:asset-row';
  await accepted.sandbox.__selectWorkspaceItem(sourceItem());
  assert.equal(accepted.state.asset,null);
  assert.equal(accepted.calls.opened.length,1);
  assert.deepEqual(JSON.parse(JSON.stringify(accepted.calls.opened[0])),
    {kind:'source',id:'fn-1',variant:'assembly'});
  assert.equal(accepted.host.hidden,false,'source selection leaves the shared editor host visible');
  assert.equal(accepted.ids.get('source-editor').hidden,false);
  assert.equal(accepted.filePane.hidden,true);
  assert.equal(accepted.assetPane.hidden,true);

  const fileSelection=setup();
  await fileSelection.sandbox.__selectWorkspaceItem({id:'file:shared.h',kind:'file',name:'shared.h',target:{path:'source-workstation/shared.h'}});
  assert.equal(fileSelection.host.hidden,false,'file selection leaves the shared editor host visible');
  assert.equal(fileSelection.ids.get('source-editor').hidden,true);
  assert.equal(fileSelection.filePane.hidden,false);
  assert.equal(fileSelection.assetPane.hidden,true);

  const assetSelection=setup();
  assetSelection.state.zone={relative_path:'code_post_gfx.ff',zone_id:'z'.repeat(64)};
  assetSelection.state.zoneId='z'.repeat(64);
  assetSelection.treeState.zone=assetSelection.state.zone;
  await assetSelection.sandbox.__selectWorkspaceItem({id:'asset:514',kind:'asset',name:'cs_fence',zone_id:'z'.repeat(64),relative_path:'code_post_gfx.ff',target:{asset_id:`${'z'.repeat(64)}:514`}});
  assert.equal(assetSelection.host.hidden,false,'asset selection leaves the shared editor host visible');
  assert.equal(assetSelection.ids.get('source-editor').hidden,true);
  assert.equal(assetSelection.filePane.hidden,true);
  assert.equal(assetSelection.assetPane.hidden,false);
  assert.equal(assetSelection.ids.get('workspace-content-load').hidden,true,
    'a successful strict asset read removes the scoped loading overlay');
  assert.ok(assetSelection.host.children.every(child=>!child.inert),
    'a completed load restores editor keyboard and pointer access');

  // Catalog banners describe display metadata only and never claim edit readiness.
  const catalogUi=setup();
  const status=catalogUi.ids.get('workspace-catalog-status');
  catalogUi.sandbox.__renderWorkspaceCatalogStatus({catalog_status:{state:'building',generation:3,
    indexed_at:'2026-10-03T12:00:00Z',family_counts:{functions:1200,symbols:300,globals:25,authored:40,
      fastfiles:14,decoded_zones:8,native_asset_rows:514,asset_directories:120,inventories:8},
    indexed_fastfiles:6,total_fastfiles:14,
    validation_scope:'display-only-metadata'}});
  assert.equal(status.hidden,false);
  assert.equal(status.textContent,'Indexing workspace… · 6 of 14 fastfiles indexed');
  assert.match(status.title,/Rows speed up navigation/);
  assert.match(status.title,/Selected items are checked before editing/);
  for(const countLabel of ['Functions: 1,200','Symbols: 300','Editable globals: 25','Source files: 40',
    'Fastfiles: 14','Indexed zones: 8','Native assets: 514'])assert.ok(status.title.includes(countLabel));
  assert.doesNotMatch(status.title,/asset_directories|inventories/);
  catalogUi.sandbox.__renderWorkspaceCatalogStatus({catalog_status:{state:'stale',generation:3,
    validation_scope:'display-only-metadata'}});
  assert.equal(status.textContent,'Updating workspace index…');
  catalogUi.sandbox.__renderWorkspaceCatalogStatus({catalog_status:{state:'ready',generation:4,
    validation_scope:'display-only-metadata'}});
  assert.equal(status.textContent,'Workspace index ready');
  catalogUi.sandbox.__renderWorkspaceCatalogStatus({catalog_status:{state:'unavailable',generation:4,
    validation_scope:'display-only-metadata'}});
  assert.equal(status.textContent,'Workspace index unavailable');
  catalogUi.sandbox.__renderWorkspaceCatalogStatus({catalog_status:{state:'ready',generation:4,
    validation_scope:'strictly-validated'}});
  assert.equal(status.hidden,true,'unknown validation scopes do not receive a cache-ready label');
  assert.match(catalogUi.sandbox.__workspaceItemDetail({kind:'zone',name:'example.ff',bytes:20,
    inventory_cached:true,inventory_state:'stale'}),/metadata · refreshing/);

  const fastfileRow=setup();
  fastfileRow.sandbox.__renderWorkspaceTree({label:'Assets',items:[{id:'zone-code-post',kind:'zone',name:'code_post_gfx.ff',
    relative_path:'code_post_gfx.ff',source_status:'source-header-checked',bytes:1234}],total:1,offset:0,limit:100,breadcrumbs:[]});
  const fastfileButton=fastfileRow.ids.get('source-list').children[0];
  assert.equal(fastfileButton.attrs['aria-label'],'Expand fastfile code_post_gfx.ff');
  assert.equal(fastfileButton.title.startsWith('Expand fastfile code_post_gfx.ff'),true);
  assert.equal(fastfileButton.children[0].textContent,'›','fastfiles have a clear drill-down chevron');

  const globalFastfile=setup();
  const fastfileHit=globalFastfile.sandbox.__workspaceSearchResult({id:'zone-code-post',node:'zone-code-post',
    area:'Assets',kind:'zone',name:'code_post_gfx.ff',relative_path:'code_post_gfx.ff',status:'source-header-checked',
    source_xfile_version:4053,metadata_only:true,target:{relative_path:'code_post_gfx.ff',metadata_only:true}});
  assert.equal(fastfileHit.source_status,'source-header-checked',
    'global fastfile search preserves its source-header status instead of displaying an unavailable fallback');
  assert.equal(fastfileHit.extract_target,'code_post_gfx.ff');
  globalFastfile.sandbox.__openZone(fastfileHit);
  assert.match(globalFastfile.ids.get('zone-detail').textContent,/source header checked/);
  assert.doesNotMatch(globalFastfile.ids.get('zone-detail').textContent,/source unavailable/);
  assert.match(globalFastfile.ids.get('zone-status').textContent,/selected assets are checked before editing/);

  const unknownFastfile=setup();
  unknownFastfile.sandbox.__openZone({relative_path:'code_post_gfx.ff',source_xfile_version:4053});
  assert.doesNotMatch(unknownFastfile.ids.get('zone-detail').textContent,/source unavailable/);
  assert.match(unknownFastfile.ids.get('zone-status').textContent,/source status is not present/);
  assert.equal(unknownFastfile.ids.get('zone-extract').disabled,true,
    'missing status metadata does not claim a source is unavailable or offer an unchecked extraction');

  const cachedGlobalFastfile=setup();
  cachedGlobalFastfile.sandbox.__openZone({...fastfileHit,zone_id:'f'.repeat(64),inventory_cached:true,
    inventory_state:'ready'});
  assert.match(cachedGlobalFastfile.ids.get('zone-status').textContent,/Cached native metadata is available/);
  assert.equal(cachedGlobalFastfile.ids.get('zone-extract').disabled,true,
    'a reported ready inventory does not ask the user to extract it again');

  const cachedButEmptyZone=setup();
  cachedButEmptyZone.sandbox.openZone=cachedButEmptyZone.sandbox.__openZone;
  const knownCachedHit=cachedButEmptyZone.sandbox.__workspaceSearchResult({...fastfileHit,inventory_cached:true,
    inventory_state:'ready',zone_id:'f'.repeat(64)});
  cachedButEmptyZone.sandbox.api=async()=>({node:knownCachedHit.id,label:knownCachedHit.name,items:[],total:0,
    offset:0,limit:100,breadcrumbs:[],extract_required:true});
  await cachedButEmptyZone.sandbox.__selectWorkspaceItem(knownCachedHit);
  assert.equal(cachedButEmptyZone.ids.get('zone-extract').disabled,true,
    'a known cached inventory is not offered for redundant extraction if a folder response is empty');
  assert.doesNotMatch(cachedButEmptyZone.ids.get('zone-status').textContent,/Extract it to build/);

  const staleInventory=setup();
  staleInventory.sandbox.renderWorkspaceTree=()=>{};
  const staleZoneId='c'.repeat(64);
  staleInventory.sandbox.api=async()=>({node:'zone:stale',label:'common.ff',items:[],total:0,offset:0,limit:100,
    breadcrumbs:[],zone_id:staleZoneId,inventory_cached:false,inventory_state:'stale',
    inventory_validation_scope:'display-only-metadata'});
  await staleInventory.sandbox.__selectWorkspaceItem({id:'zone:stale',kind:'zone',name:'common.ff',
    relative_path:'common.ff',source_status:'source-header-checked',extract_target:'common.ff',inventory_cached:true});
  assert.equal(staleInventory.state.zoneId,staleZoneId,
    'stale display catalog identities remain navigable while strict asset reads validate on open');
  assert.equal(staleInventory.ids.get('zone-extract').disabled,false,
    'a stale inventory can be rebuilt from the current header-checked fastfile');
  assert.match(staleInventory.ids.get('zone-status').textContent,/display-only/);

  const emptyBuilding=setup();
  emptyBuilding.sandbox.api=async()=>({node:'functions',label:'Functions',items:[],total:0,offset:0,limit:100,
    breadcrumbs:[],catalog_status:{state:'building',generation:1,validation_scope:'display-only-metadata'}});
  await emptyBuilding.sandbox.__loadWorkspaceTree('functions',0);
  assert.equal(emptyBuilding.ids.get('workspace-tree-status').textContent,'Indexing workspace…');

  // A slow folder response cannot overwrite the tree after a terminal selection.
  const race=setup();
  race.sandbox.renderWorkspaceTree=page=>race.calls.rendered.push(page);
  let resolveList;
  race.sandbox.api=()=>new Promise(resolve=>{resolveList=resolve;});
  const pending=race.sandbox.__loadWorkspaceTree('folder-A',0);
  const leaf=sourceItem('fn-2','DB_Test');
  await race.sandbox.__selectWorkspaceItem(leaf);
  const page={node:'folder-A',label:'A',items:[],total:0,offset:0,limit:100,
    breadcrumbs:[{id:null,label:'IW8'}]};
  resolveList(page);await pending;
  assert.equal(race.calls.rendered.length,0,
    'an in-flight tree page is ignored after selection changes the visible context');
  assert.equal(race.calls.opened[0].id,'fn-2');

  // Explicit folder and breadcrumb navigation start a fresh folder search.
  // This prevents a filename query from producing an apparently empty root.
  for(const navigate of [
    async sandbox=>sandbox.__selectWorkspaceItem({id:'folder:root',kind:'folder',name:'IW8'}),
    async sandbox=>sandbox.__navigateWorkspaceBreadcrumb({id:'folder:root',label:'IW8'})
  ]){
    const navigation=setup();
    navigation.ids.get('source-search').value='shared_header.h';
    navigation.sandbox.renderWorkspaceTree=()=>{};
    navigation.sandbox.api=async url=>{
      navigation.calls.api.push(url);
      return {node:'folder:root',label:'IW8',items:[],total:0,offset:0,limit:100,breadcrumbs:[]};
    };
    await navigate(navigation.sandbox);
    const url=new URL(navigation.calls.api.at(-1),'http://localhost');
    assert.ok(!url.searchParams.has('q')||url.searchParams.get('q')==='',
      'explicit folder navigation clears the previous folder query');
  }

  // Pagination and programmatic refresh stay in the current query context.
  const queryContext=setup();
  queryContext.ids.get('source-search').value='cs_fence';
  queryContext.sandbox.renderWorkspaceTree=()=>{};
  queryContext.sandbox.api=async url=>{
    queryContext.calls.api.push(url);
    return {node:'assets-type',label:'shader',items:[],total:0,offset:0,limit:100,breadcrumbs:[]};
  };
  await queryContext.sandbox.__loadWorkspaceTree('assets-type',100);
  assert.equal(new URL(queryContext.calls.api.at(-1),'http://localhost').searchParams.get('q'),'cs_fence',
    'pagination preserves the current folder query');
  await queryContext.sandbox.__refreshWorkspaceTree();
  assert.equal(new URL(queryContext.calls.api.at(-1),'http://localhost').searchParams.get('q'),'cs_fence',
    'programmatic refresh preserves the current folder query');
  await queryContext.sandbox.__navigateWorkspaceFolder('assets-type');
  assert.equal(new URL(queryContext.calls.api.at(-1),'http://localhost').searchParams.get('q'),'cs_fence',
    'reopening the same folder preserves its query');

  // Background catalog polling refreshes only the visible tree, retains its
  // current folder/query/page, and never overlaps another catalog refresh.
  const catalogPoll=setup();
  catalogPoll.treeState.node='asset-type-12';catalogPoll.treeState.offset=40;
  catalogPoll.treeState.page={catalog_status:{state:'building'}};
  catalogPoll.ids.get('source-search').value='cs_fence';
  catalogPoll.state.file={path:'src/shared.h',content:'saved'};
  catalogPoll.ids.get('file-content').value='unsaved file edit';
  catalogPoll.sandbox.renderWorkspaceTree=page=>catalogPoll.sandbox.__renderWorkspaceCatalogStatus(page);
  let finishCatalogRequest;
  catalogPoll.sandbox.api=url=>{
    catalogPoll.calls.api.push(url);
    return new Promise(resolve=>{finishCatalogRequest=resolve;});
  };
  const poll= catalogPoll.sandbox.__pollWorkspaceCatalog(0);
  assert.equal(catalogPoll.treeState.loadingRequests,1);
  assert.equal(await catalogPoll.sandbox.__pollWorkspaceCatalog(0),false,
    'a second poll is skipped while the catalog refresh is in flight');
  assert.equal(catalogPoll.calls.api.length,1);
  const refreshUrl=new URL(catalogPoll.calls.api[0],'http://localhost');
  assert.equal(refreshUrl.searchParams.get('node'),'asset-type-12');
  assert.equal(refreshUrl.searchParams.get('q'),'cs_fence');
  assert.equal(refreshUrl.searchParams.get('offset'),'40');
  finishCatalogRequest({node:'asset-type-12',label:'shader',items:[],total:0,offset:40,limit:100,breadcrumbs:[],
    catalog_status:{state:'ready',generation:5,indexed_at:'2026-10-03T12:00:00Z',
      family_counts:{symbols:2000},validation_scope:'display-only-metadata'}});
  assert.equal(await poll,true);
  assert.equal(catalogPoll.state.file.path,'src/shared.h');
  assert.equal(catalogPoll.ids.get('file-content').value,'unsaved file edit');
  assert.equal(catalogPoll.ids.get('workspace-catalog-status').dataset.catalogState,'ready');
  assert.equal(await catalogPoll.sandbox.__pollWorkspaceCatalog(1),false,
    'ready catalogs stop background refresh attempts');

  const catalogBackoff=setup();
  catalogBackoff.treeState.page={catalog_status:{state:'stale'}};
  catalogBackoff.sandbox.renderWorkspaceTree=()=>{};
  catalogBackoff.sandbox.api=async url=>{
    catalogBackoff.calls.api.push(url);
    return {node:'old-folder',label:'folder',items:[],total:0,offset:0,limit:100,breadcrumbs:[],
      catalog_status:{state:'stale',generation:2,validation_scope:'display-only-metadata'}};
  };
  assert.equal(await catalogBackoff.sandbox.__pollWorkspaceCatalog(Date.now()),true);
  assert.equal(await catalogBackoff.sandbox.__pollWorkspaceCatalog(Date.now()),false,
    'stale catalogs use backoff instead of polling every status tick');
  catalogBackoff.state.page='builds';
  catalogBackoff.sandbox.workspaceCatalogPollAfter=0;
  assert.equal(await catalogBackoff.sandbox.__pollWorkspaceCatalog(Date.now()),false,
    'catalog polling pauses away from Game Source');
  assert.equal(catalogBackoff.calls.api.length,1);

  const selectedZone=setup();
  const selectedZoneId='e'.repeat(64);
  selectedZone.treeState.node='zone-node';selectedZone.treeState.active='zone:zone-node';
  selectedZone.treeState.page={catalog_status:{state:'building'}};
  selectedZone.state.zone={relative_path:'zone/common.ff',source_status:'source-header-checked',
    inventory_state:'building',inventory_cached:false};
  selectedZone.treeState.zone=selectedZone.state.zone;
  selectedZone.state.zoneId=null;
  selectedZone.ids.get('zone-extract').disabled=false;
  selectedZone.ids.get('new-asset').disabled=true;
  selectedZone.ids.get('zone-status').textContent='Indexing…';
  selectedZone.state.file={path:'src/engine.h',content:'baseline'};
  selectedZone.ids.get('file-content').value='unsaved header edit';
  selectedZone.sandbox.renderWorkspaceTree=()=>{};
  selectedZone.sandbox.api=async()=>({node:'zone-node',label:'common.ff',items:[],total:0,offset:0,limit:100,
    breadcrumbs:[],zone_id:selectedZoneId,inventory_cached:true,inventory_state:'ready',
    inventory_validation_scope:'display-only-metadata',
    catalog_status:{state:'ready',generation:6,validation_scope:'display-only-metadata'}});
  assert.equal(await selectedZone.sandbox.__pollWorkspaceCatalog(Date.now()),true);
  assert.equal(selectedZone.state.zoneId,selectedZoneId,
    'a ready catalog refresh updates the selected zone context');
  assert.equal(selectedZone.ids.get('zone-extract').disabled,true);
  assert.equal(selectedZone.ids.get('new-asset').disabled,false);
  assert.match(selectedZone.ids.get('zone-status').textContent,/checked before editing/);
  assert.equal(selectedZone.state.file.path,'src/engine.h');
  assert.equal(selectedZone.ids.get('file-content').value,'unsaved header edit');

  const openAssetZone=setup();
  openAssetZone.treeState.node='zone-node';openAssetZone.treeState.active='asset:old-row';
  openAssetZone.treeState.page={catalog_status:{state:'building'}};
  openAssetZone.state.zone={relative_path:'zone/common.ff',source_status:'source-header-checked',
    inventory_state:'building',inventory_cached:false};
  openAssetZone.treeState.zone=openAssetZone.state.zone;
  openAssetZone.state.zoneId='old-zone-id';
  openAssetZone.state.asset={asset_id:'old-zone-id:165',content:'before',editable:true};
  openAssetZone.ids.get('asset-content').value='unsaved asset bytes';
  openAssetZone.sandbox.renderWorkspaceTree=()=>{};
  openAssetZone.sandbox.api=async()=>({node:'zone-node',label:'common.ff',items:[],total:0,offset:0,limit:100,
    breadcrumbs:[],zone_id:'new-zone-id',inventory_cached:true,inventory_state:'ready',
    inventory_validation_scope:'display-only-metadata',catalog_status:{state:'ready',generation:7,
      validation_scope:'display-only-metadata'}});
  assert.equal(await openAssetZone.sandbox.__pollWorkspaceCatalog(Date.now()),true);
  assert.equal(openAssetZone.state.zoneId,'old-zone-id',
    'a catalog identity update never silently rebinds a currently opened asset');
  assert.equal(openAssetZone.state.asset.asset_id,'old-zone-id:165');
  assert.equal(openAssetZone.ids.get('asset-content').value,'unsaved asset bytes');

  // A late asset GET cannot replace a newer selection.
  const assetRace=setup();
  let pendingAssets=[];
  assetRace.sandbox.api=()=>new Promise(resolve=>pendingAssets.push(resolve));
  assetRace.sandbox.showAsset=asset=>assetRace.calls.shown.push(asset.asset_id);
  const oldAsset=assetRace.sandbox.__openAsset('zone:old');
  const newAsset=assetRace.sandbox.__openAsset('zone:new');
  pendingAssets[1]({asset_id:'zone:new',name:'new'});await newAsset;
  pendingAssets[0]({asset_id:'zone:old',name:'old'});await oldAsset;
  assert.deepEqual(assetRace.calls.shown,['zone:new'],
    'a slow earlier asset GET cannot replace the currently selected asset');

  // Workspace-wide search retains partial matches while showing honest index coverage.
  const globalSearch=setup();
  globalSearch.ids.get('workspace-query').value='cs_fence';
  globalSearch.sandbox.page=async id=>{globalSearch.calls.pages.push(id);return true;};
  globalSearch.sandbox.selectWorkspaceItem=async item=>globalSearch.calls.opened.push({kind:item.kind,
    name:item.name,area:item.area,target:item.target,metadata_only:item.metadata_only});
  globalSearch.sandbox.api=async url=>{
    globalSearch.calls.api.push(url);
    return {items:[
      {id:'asset-row-514',node:'zone-node',area:'Assets',kind:'asset',name:'cs_fence',
        relative_path:'code_post_gfx.ff',zone_id:'f'.repeat(64),type_id:12,index:514,metadata_only:true,
        target:{asset_id:`${'f'.repeat(64)}:514`,relative_path:'code_post_gfx.ff',zone_id:'f'.repeat(64),type_id:12,index:514,metadata_only:true}},
      {id:'cfg-row',area:'Authored files',kind:'file',name:'settings.cfg',target:{path:'src/settings.cfg'}}
    ],total:2,offset:0,limit:100,search_status:{state:'building',complete:false,indexed_fastfiles:6,
      total_fastfiles:14,asset_rows:600,native_asset_rows:520,table_only_fastfiles:3,
      generation:9,validation_scope:'display-only-metadata'}};
  };
  await globalSearch.sandbox.__searchWorkspace('cs_fence');
  assert.equal(globalSearch.ids.get('workspace-results').children.length,2);
  assert.equal(globalSearch.ids.get('workspace-results').inert,false,
    'useful indexed rows become interactive while the complete scan continues');
  assert.match(globalSearch.ids.get('workspace-search-status').textContent,/6 of 14 fastfiles indexed/);
  assert.match(globalSearch.ids.get('workspace-search-status').textContent,/600 cached asset rows/);
  assert.match(globalSearch.ids.get('workspace-search-status').textContent,/520 verified native rows/);
  assert.match(globalSearch.ids.get('workspace-search-status').textContent,/3 fastfiles lack native asset names/);
  assert.match(globalSearch.ids.get('workspace-search-status').textContent,/Name coverage is partial/);
  assert.doesNotMatch(globalSearch.ids.get('workspace-search-status').textContent,/metadata coverage complete/);
  const completeButLimited=globalSearch.sandbox.__workspaceSearchProgress({state:'ready',complete:true,
    validation_scope:'display-only-metadata',asset_rows:600,native_asset_rows:520,table_only_fastfiles:3},42);
  assert.match(completeButLimited,/workspace index scan complete/);
  assert.match(completeButLimited,/Name coverage is partial/,
    'finished background scans still report incomplete native-name coverage for table-only fastfiles');
  assert.match(globalSearch.ids.get('workspace-results').children[0].children[1].textContent,/Assets/);
  assert.match(globalSearch.ids.get('workspace-results').children[1].children[1].textContent,/Authored files/);
  await globalSearch.ids.get('workspace-results').children[0].onclick();
  assert.equal(globalSearch.calls.pages.at(-1),'sources');
  assert.equal(globalSearch.calls.opened.at(-1).metadata_only,true,
    'metadata-only asset result retains its provenance when dispatched');
  assert.equal(globalSearch.calls.opened.at(-1).target.path,undefined);

  // A response for an older query cannot replace results for the current query.
  const searchRace=setup();
  let pendingSearch=[];
  searchRace.sandbox.api=url=>new Promise(resolve=>pendingSearch.push({url,resolve}));
  searchRace.ids.get('workspace-query').value='first';
  const firstSearch=searchRace.sandbox.__searchWorkspace('first');
  assert.equal(searchRace.ids.get('workspace-search-close').disabled,true,
    'search results cannot be dismissed while the scoped results area is loading');
  assert.equal(searchRace.ids.get('workspace-results').inert,true,
    'the affected search result area is inert during its request');
  searchRace.ids.get('workspace-query').value='second';
  const secondSearch=searchRace.sandbox.__searchWorkspace('second');
  const searchPage=(name)=>({items:[{id:`file-${name}`,kind:'file',area:'Authored files',name,
    target:{path:`src/${name}.cfg`}}],total:1,offset:0,limit:100,
    search_status:{state:'ready',complete:true,generation:1,validation_scope:'display-only-metadata'}});
  pendingSearch[0].resolve(searchPage('first'));await firstSearch;
  assert.equal(searchRace.ids.get('workspace-results').children.length,0);
  pendingSearch[1].resolve(searchPage('second'));await secondSearch;
  assert.equal(searchRace.ids.get('workspace-results').children[0].children[0].textContent,'second');
  assert.equal(searchRace.ids.get('workspace-search-close').disabled,false,
    'usable partial or complete results unlock the search dialog');

  const searchPaging=setup();
  const searchOffsets=[];
  searchPaging.sandbox.api=async url=>{
    const parsed=new URL(url,'http://localhost');searchOffsets.push(parsed.searchParams.get('offset'));
    return {items:[{id:`asset-${parsed.searchParams.get('offset')}`,kind:'asset',area:'Assets',name:'common material',
      relative_path:'common.ff',zone_id:'z',target:{asset_id:`z:${parsed.searchParams.get('offset')}`,relative_path:'common.ff',zone_id:'z',metadata_only:true}}],
      total:150,offset:Number(parsed.searchParams.get('offset')),limit:100,
      search_status:{state:'ready',complete:true,generation:2,validation_scope:'display-only-metadata'}};
  };
  await searchPaging.sandbox.__searchWorkspace('material',0);
  assert.equal(searchPaging.ids.get('workspace-search-pagination').hidden,false);
  await searchPaging.sandbox.__searchWorkspace('material',100);
  assert.deepEqual(searchOffsets,['0','100'],'workspace search pages beyond its first 100 global matches');

  const searchFailure=setup();
  searchFailure.ids.get('workspace-query').value='player';
  let failedOnce=true;
  searchFailure.sandbox.api=async()=>{
    if(failedOnce){failedOnce=false;throw new Error('Index worker unavailable');}
    return {items:[],total:0,offset:0,limit:100,
      search_status:{state:'ready',complete:true,generation:2,validation_scope:'display-only-metadata'}};
  };
  await assert.rejects(searchFailure.sandbox.__searchWorkspace('player'),/Index worker unavailable/);
  assert.equal(searchFailure.ids.get('workspace-search-status').dataset.state,'error');
  const retry=searchFailure.ids.get('workspace-search-status').children.at(-1);
  assert.equal(retry.hidden,false,'search failures leave a visible scoped retry action');
  await retry.onclick();
  assert.match(searchFailure.ids.get('workspace-search-status').textContent,/No workspace matches/);

  // The main Game Source filter searches all IW8 areas while retaining the
  // focused node as the return destination when its query is cleared.
  const mainGlobal=setup();
  mainGlobal.treeState.node='assets/type/12';mainGlobal.treeState.offset=100;
  mainGlobal.treeState.page={breadcrumbs:[{id:'assets',label:'Assets'},{id:'assets/type/12',label:'Shaders'}]};
  mainGlobal.ids.get('source-search').value='fence';
  mainGlobal.sandbox.renderWorkspaceTree=page=>mainGlobal.calls.rendered.push(page);
  mainGlobal.sandbox.api=async url=>{
    mainGlobal.calls.api.push(url);
    if(url.startsWith('/api/workspace/search'))return {items:[
      {id:'source:fn-fence',kind:'source',area:'Code',name:'R_Fence',target:{id:'fn-fence',variant:'assembly'}},
      {id:'asset:fence',node:'zone-code-post',kind:'asset',area:'Assets',name:'cs_fence',
        target:{asset_id:'zone-514',relative_path:'code_post_gfx.ff',zone_id:'zone',type_id:12,index:514,metadata_only:true}},
      {id:'file:fence',kind:'file',area:'Authored files',name:'fence.cfg',target:{path:'configs/fence.cfg'}}
    ],total:3,offset:0,limit:100,search_status:{state:'building',complete:false,indexed_fastfiles:6,total_fastfiles:14,
      asset_rows:900,native_asset_rows:810,table_only_fastfiles:2,
      generation:12,validation_scope:'display-only-metadata'}};
    return {node:'assets/type/12',label:'Shaders',items:[],total:0,offset:0,limit:100,breadcrumbs:[]};
  };
  await mainGlobal.sandbox.__searchFromGameSource();
  assert.ok(mainGlobal.calls.api[0].startsWith('/api/workspace/search?q=fence'),
    'the main Game Source query uses the all-workspace endpoint');
  assert.equal(mainGlobal.treeState.node,'assets/type/12','global search leaves the focused folder identity intact');
  assert.equal(mainGlobal.calls.rendered[0].items.length,3);
  assert.deepEqual(mainGlobal.calls.rendered[0].items.map(row=>row.area),['Code','Assets','Authored files']);
  assert.equal(mainGlobal.calls.rendered[0].items[1].target.asset_id,'zone-514',
    'global results retain their canonical asset target for open');
  assert.match(mainGlobal.ids.get('workspace-search-scope').textContent,/All IW8 · outside the focused folder/);
  assert.match(mainGlobal.ids.get('workspace-search-scope').textContent,/6 of 14 fastfiles indexed/);
  assert.match(mainGlobal.ids.get('workspace-search-scope').textContent,/900 cached asset rows/);
  assert.match(mainGlobal.ids.get('workspace-search-scope').textContent,/2 fastfiles lack native asset names/);
  assert.equal(mainGlobal.sandbox.__workspaceItemDetail(mainGlobal.calls.rendered[0].items[2]),'Authored files · configs/fence.cfg');
  await mainGlobal.sandbox.__loadWorkspaceResultsPage(100);
  const nextSearchPage = new URL(mainGlobal.calls.api[1], 'http://localhost');
  assert.equal(nextSearchPage.pathname, '/api/workspace/search');
  assert.equal(nextSearchPage.searchParams.get('q'), 'fence');
  assert.equal(nextSearchPage.searchParams.get('offset'), '100',
    'main search pagination keeps using the global query and offset');
  mainGlobal.ids.get('source-search').value='';
  await mainGlobal.sandbox.__searchFromGameSource();
  const restoredFolder=new URL(mainGlobal.calls.api.at(-1),'http://localhost');
  assert.ok(restoredFolder.pathname.endsWith('/api/workspace/tree'));
  assert.equal(restoredFolder.searchParams.get('node'),'assets/type/12',
    'clearing main search returns to the previously focused folder');
  assert.equal(mainGlobal.ids.get('workspace-search-scope').hidden,true);

  const mainSearchRace=setup();
  mainSearchRace.treeState.node='functions';
  mainSearchRace.sandbox.document.activeElement=mainSearchRace.ids.get('source-search');
  mainSearchRace.sandbox.renderWorkspaceTree=page=>mainSearchRace.calls.rendered.push(page);
  let pendingMain=[];
  mainSearchRace.sandbox.api=url=>new Promise(resolve=>pendingMain.push({url,resolve}));
  mainSearchRace.ids.get('source-search').value='older';
  const oldMainSearch=mainSearchRace.sandbox.__searchFromGameSource();
  assert.equal(mainSearchRace.ids.get('workspace-tree-content').attrs['aria-busy'],'true');
  assert.equal(mainSearchRace.ids.get('source-list').inert,true,
    'the affected tree stays inert until its global search response arrives');
  assert.equal(mainSearchRace.ids.get('workspace-tree-load').focused,undefined,
    'search loading must not steal focus from the active search field');
  mainSearchRace.ids.get('source-search').value='newer';
  const newMainSearch=mainSearchRace.sandbox.__searchFromGameSource();
  const mainPage=(name)=>({items:[{id:`file:${name}`,kind:'file',area:'Authored files',name,
    target:{path:`configs/${name}.cfg`}}],total:1,offset:0,limit:100,
    search_status:{state:'ready',complete:true,generation:1,validation_scope:'display-only-metadata'}});
  pendingMain[0].resolve(mainPage('older'));await oldMainSearch;
  assert.equal(mainSearchRace.calls.rendered.length,0,'an older main-search response cannot replace the newer query');
  pendingMain[1].resolve(mainPage('newer'));await newMainSearch;
  assert.equal(mainSearchRace.calls.rendered[0].items[0].name,'newer');
  assert.equal(mainSearchRace.ids.get('source-list').inert,false);
  assert.equal(mainSearchRace.ids.get('workspace-tree-load').hidden,true);

  const searchFocusFailure=setup();
  searchFocusFailure.ids.get('source-search').value='fence';
  searchFocusFailure.sandbox.document.activeElement=searchFocusFailure.ids.get('source-search');
  searchFocusFailure.sandbox.api=async()=>{throw new Error('Search unavailable');};
  await assert.rejects(searchFocusFailure.sandbox.__searchFromGameSource(),/Search unavailable/);
  assert.equal(searchFocusFailure.ids.get('workspace-tree-load-retry').focused,undefined,
    'a failed search must not steal focus from the active search field');
  assert.equal(searchFocusFailure.ids.get('source-search').inert,false);
  assert.equal(searchFocusFailure.ids.get('source-list').inert,true,
    'failed results remain blocked while the search field stays usable');

  const strictZoneId='a'.repeat(64),strictAssetId=`${'a'.repeat(64)}:514`;
  const cachedMetadataOpen=setup();
  const cachedOrder=[];
  cachedMetadataOpen.sandbox.api=async(path)=>{
    cachedOrder.push(path);
    if(path.startsWith('/api/asset?'))return {asset_id:strictAssetId,zone_id:strictZoneId,index:514,type_id:12,
      name:'cs_fence',content:'checked',editable:true};
    throw new Error(`unexpected asset request ${path}`);
  };
  cachedMetadataOpen.sandbox.showAsset=asset=>cachedMetadataOpen.calls.shown.push(asset.asset_id);
  await cachedMetadataOpen.sandbox.__openAsset(strictAssetId,false,{metadata_only:true,
    relative_path:'code_post_gfx.ff',zone_id:strictZoneId,index:514,type_id:12});
  assert.deepEqual(cachedOrder,[`/api/asset?id=${encodeURIComponent(strictAssetId)}`],
    'a strict GET opens an already cached metadata-only search result without redundant extraction');
  assert.deepEqual(cachedMetadataOpen.calls.shown,[strictAssetId]);

  const missingMetadataOpen=setup();
  const missingOrder=[];let firstPayloadGet=true;
  missingMetadataOpen.sandbox.api=async(path,body)=>{
    assert.equal(missingMetadataOpen.ids.get('workspace-content-load').hidden,false,
      'the editor content overlay remains shown during every acquisition stage');
    assert.ok(missingMetadataOpen.host.children.filter(child=>child!==missingMetadataOpen.ids.get('workspace-content-load')).every(child=>child.inert),
      'the editor content stays inert during every acquisition stage');
    missingOrder.push(path);
    if(path.startsWith('/api/asset?')){
      if(firstPayloadGet){firstPayloadGet=false;const error=new Error('No strict payload cache');error.code='asset_payload_cache_missing';throw error;}
      return {asset_id:strictAssetId,zone_id:strictZoneId,index:514,type_id:12,
        name:'cs_fence',content:'checked',editable:true};
    }
    if(path==='/api/fastfile/extract'){assert.equal(body.path,'code_post_gfx.ff');return {zone_id:strictZoneId};}
    throw new Error(`unexpected asset request ${path}`);
  };
  missingMetadataOpen.sandbox.showAsset=asset=>missingMetadataOpen.calls.shown.push(asset.asset_id);
  await missingMetadataOpen.sandbox.__openAsset(strictAssetId,false,{metadata_only:true,
    relative_path:'code_post_gfx.ff',zone_id:strictZoneId,index:514,type_id:12});
  assert.deepEqual(missingOrder,[`/api/asset?id=${encodeURIComponent(strictAssetId)}`,'/api/fastfile/extract',`/api/asset?id=${encodeURIComponent(strictAssetId)}`],
    'only the explicit missing-payload response triggers extraction before a second strict GET');
  assert.deepEqual(missingMetadataOpen.calls.shown,[strictAssetId]);
  assert.equal(missingMetadataOpen.ids.get('workspace-content-load').hidden,true,
    'the editor overlay remains active across the GET, extraction, and final GET');

  const rejectedValidation=setup();
  const validationCalls=[];
  rejectedValidation.sandbox.api=async path=>{
    validationCalls.push(path);const error=new Error('Current source fastfile changed after cataloging');
    error.code='asset_source_identity_mismatch';throw error;
  };
  await assert.rejects(rejectedValidation.sandbox.__openAsset(strictAssetId,false,{metadata_only:true,
    relative_path:'code_post_gfx.ff',zone_id:strictZoneId,index:514,type_id:12}),/source fastfile changed/);
  assert.deepEqual(validationCalls,[`/api/asset?id=${encodeURIComponent(strictAssetId)}`],
    'codec, stale-source, and identity validation failures never bypass strict checks with extraction');

  const wrongExtractIdentity=setup();
  const wrongIdentityCalls=[];let missingFirst=true;
  wrongExtractIdentity.sandbox.api=async path=>{
    wrongIdentityCalls.push(path);
    if(path.startsWith('/api/asset?')&&missingFirst){missingFirst=false;const error=new Error('Cache missing');error.code='asset_payload_cache_missing';throw error;}
    if(path==='/api/fastfile/extract')return {zone_id:'b'.repeat(64)};
    return {asset_id:strictAssetId,zone_id:strictZoneId,index:514,type_id:12,name:'cs_fence',content:'x'};
  };
  await assert.rejects(wrongExtractIdentity.sandbox.__openAsset(strictAssetId,false,{metadata_only:true,
    relative_path:'code_post_gfx.ff',zone_id:strictZoneId,index:514,type_id:12}),/identity changed/);
  assert.deepEqual(wrongIdentityCalls,[`/api/asset?id=${encodeURIComponent(strictAssetId)}`,'/api/fastfile/extract'],
    'a mismatched extraction receipt prevents the second asset GET');

  const wrongRowIdentity=setup();
  wrongRowIdentity.sandbox.api=async path=>{
    if(path.startsWith('/api/asset?'))return {asset_id:strictAssetId,zone_id:strictZoneId,index:514,type_id:54,
      name:'omnvars.csv',content:'x'};
    throw new Error(`unexpected asset request ${path}`);
  };
  await assert.rejects(wrongRowIdentity.sandbox.__openAsset(strictAssetId,false,{metadata_only:true,
    relative_path:'code_post_gfx.ff',zone_id:strictZoneId,index:514,type_id:12}),/row identity/);

  const tableOnlyOpen=setup();
  const tableOnlyCalls=[];
  tableOnlyOpen.sandbox.api=async path=>{
    tableOnlyCalls.push(path);
    if(path.startsWith('/api/asset?'))return {asset_id:strictAssetId,zone_id:strictZoneId,index:514,type_id:255,
      name:'native_type_255',content:null,editable:false,payload_format:'Native XAsset table identity only',
      package_status:'Native table row is available; typed payload reader is unsupported.'};
    throw new Error(`unexpected table-only request ${path}`);
  };
  await tableOnlyOpen.sandbox.__openAsset(strictAssetId,false,{metadata_only:true,relative_path:'common.ff',
    zone_id:strictZoneId,index:514,type_id:255});
  assert.deepEqual(tableOnlyCalls,[`/api/asset?id=${encodeURIComponent(strictAssetId)}`],
    'table-only read-only metadata opens from the basic GET without extraction');
  assert.match(tableOnlyOpen.ids.get('zone-status').textContent,/read-only metadata/);
  assert.doesNotMatch(tableOnlyOpen.ids.get('zone-status').textContent,/checked against its current fastfile/);

  tableOnlyOpen.sandbox.api=async path=>{
    tableOnlyCalls.push(path);
    return {asset_id:strictAssetId,zone_id:strictZoneId,index:514,type_id:51,
      name:'Asset 514',content:'{"type_id":51}',language:'json',editable:false,
      reader_scope:'xasset-table-only',payload_format:'Validated XAsset table metadata'};
  };
  await tableOnlyOpen.sandbox.__openAsset(strictAssetId,false,{metadata_only:true,
    relative_path:'unsupported.ff',zone_id:strictZoneId,index:514,type_id:51});
  assert.match(tableOnlyOpen.ids.get('zone-status').textContent,/read-only metadata/,
    'the exact table-only backend format also keeps native ownership claims disabled');
  assert.doesNotMatch(tableOnlyOpen.ids.get('zone-status').textContent,/checked against its current fastfile/);
  assert.equal(tableOnlyCalls.length,2,'table-only RawFile metadata never asks for a payload extraction');

  const apiContract={state:{backendRestart:false,csrf:'token'},$(){return {textContent:''};}};
  apiContract.fetch=async()=>({ok:false,status:400,json:async()=>({error:'payload cache missing',code:'asset_payload_cache_missing'})});
  vm.createContext(apiContract);
  vm.runInContext(block('async function api(path, body)', 'function guard('),apiContract,{filename:appPath});
  await assert.rejects(apiContract.api('/api/asset?id=missing'),error=>error.code==='asset_payload_cache_missing',
    'the real API wrapper preserves the server cache-missing code for the narrow acquisition path');

  const failedAsset=setup();
  failedAsset.sandbox.openAsset=failedAsset.sandbox.__openAsset;
  let assetRetry=false;
  failedAsset.sandbox.api=async()=>{if(!assetRetry)throw new Error('Current fastfile could not be validated');
    return {asset_id:'strict-zone:514',name:'cs_fence',content:'checked',editable:true};};
  failedAsset.sandbox.showAsset=asset=>failedAsset.calls.shown.push(asset.asset_id);
  await assert.rejects(failedAsset.sandbox.__openAsset('strict-zone:514'),/could not be validated/);
  assert.equal(failedAsset.ids.get('workspace-content-load').hidden,false);
  assert.equal(failedAsset.ids.get('workspace-content-load').dataset.failed,'true');
  assert.ok(failedAsset.host.children.filter(child=>child!==failedAsset.ids.get('workspace-content-load')).every(child=>child.inert),
    'failed asset validation keeps only the affected editor area inert');
  assetRetry=true;
  await failedAsset.ids.get('workspace-content-load-retry').onclick();
  assert.equal(failedAsset.ids.get('workspace-content-load').hidden,true);
  assert.deepEqual(failedAsset.calls.shown,['strict-zone:514']);

  // Changing zones must replace the asset context before a later leaf is opened.
  const zones=setup();
  zones.sandbox.loadWorkspaceTree=async()=>{};
  await zones.sandbox.__selectWorkspaceItem({id:'zone:old',kind:'zone',name:'old.ff',relative_path:'zone/old.ff',zone_id:'a'.repeat(64),action:{type:'zone',node:'zone:old',zone:{}}});
  await zones.sandbox.__selectWorkspaceItem({id:'zone:new',kind:'zone',name:'new.ff',relative_path:'zone/new.ff',zone_id:'b'.repeat(64),action:{type:'zone',node:'zone:new',zone:{}}});
  await zones.sandbox.__selectWorkspaceItem({id:'asset:row',kind:'asset',name:'row',zone_id:'b'.repeat(64),relative_path:'zone/new.ff',index:514,type_id:12,target:{asset_id:`${'b'.repeat(64)}:514`}});
  assert.equal(zones.state.zoneId,'b'.repeat(64));
  assert.equal(zones.state.zone.relative_path,'zone/new.ff');
  assert.equal(zones.calls.opened.at(-1).assetId,`${'b'.repeat(64)}:514`);

  // Selecting an authored file must expose its editor without hiding the shared editor host.
  const authoredSelection=setup();
  await authoredSelection.sandbox.__selectWorkspaceItem({id:'file:engine',kind:'file',name:'engine.cpp',target:{path:'src/engine.cpp'}});
  assert.equal(authoredSelection.host.hidden,false,'the shared host remains visible for every editor kind');
  assert.equal(authoredSelection.ids.get('source-editor').hidden,true,'file selection hides only the source editor');
  assert.equal(authoredSelection.filePane.hidden,false,'file selection reveals the file editor pane');

  // Breadcrumbs must remain a single horizontally scrollable row despite the global vertical nav style.
  assert.match(css,/#sources \.tree-breadcrumbs\s*\{[^}]*flex-direction:\s*row/s,
    'Game Source breadcrumbs override the sidebar nav column direction');

  // Leaving and returning to the unified page must not reopen a stale editor pane.
  const paging=setup();
  paging.sandbox.loadWorkspaceTree=async()=>{};
  paging.treeState.active='asset:zone:165';
  paging.state.asset={asset_id:'zone:165',content:'old',editable:true};
  paging.ids.get('asset-content').value='old';
  await paging.sandbox.__page('builds');
  assert.equal(paging.state.asset,null);
  await paging.sandbox.__page('sources');
  assert.ok(paging.calls.activeEditors.at(-1)!=='asset'||paging.state.asset,
    'the page cannot reveal a stale asset editor when its backing selection was cleared');

  console.log('workspace tree navigation regressions passed');
})().catch(error=>{console.error(error);process.exitCode=1;});
