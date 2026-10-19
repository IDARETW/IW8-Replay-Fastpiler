'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const appPath = process.env.REPLAY_WORKSTATION_APP_JS || 'workstation/web/app.js';
const app = fs.readFileSync(appPath, 'utf8');
const start = app.indexOf('const assetCreateType=element(');
const end = app.indexOf('\nassetRemove.onclick=guard', start);
assert.notEqual(start, -1, 'asset create handlers exist');
assert.notEqual(end, -1, 'asset create handler block is bounded');
const source = app.slice(start, end).trim();

class FakeElement {
  constructor(tag, text = '') {
    this.tag = tag; this.textContent = text; this.children = []; this.options = [];
    this.attrs = {}; this.value = ''; this.hidden = false; this.disabled = false;
    this.placeholder = ''; this.firstChild = { textContent: text };
    this.listeners = {};
  }
  append(child) { this.children.push(child); if (this.tag === 'select') { this.options.push(child); if (this.options.length === 1) this.value = child.value; } }
  before(child) { this.beforeChild = child; }
  setAttribute(key, value) { this.attrs[key] = value; }
  querySelector(selector) { if (selector === 'h3') return this.h3; if (selector === 'p') return this.p; if (selector === 'label') return this.label; throw new Error(`unexpected selector ${selector}`); }
  reset() { this.type.value = 'localize'; this.name.value = ''; this.content.value = ''; }
  showModal() { this.open = true; }
  close() { this.open = false; }
  focus() { this.focused = true; }
  addEventListener(name, callback) { this.listeners[name] = callback; }
}

function setup(assetCodecs = {}, apiImpl) {
  const calls = { api: [], toasts: [], errors: [], loaded: 0, refreshed: 0, opened: [], modal: 0, blockers: [], finished: [] };
  const state = { page:'sources', zoneId: 'zone-1', assetCodecs, assetOffset: 9 };
  const form = new FakeElement('form');
  form.h3 = new FakeElement('h3', 'Add Localize asset');
  form.p = new FakeElement('p');
  form.label = new FakeElement('label', 'Key');
  const close = new FakeElement('button');
  const name = new FakeElement('input');
  name.parentElement = new FakeElement('label');
  name.parentElement.firstChild = { textContent: 'Key' };
  const content = new FakeElement('textarea');
  const contentLabel = new FakeElement('label');
  content.closest = selector => selector === 'label' ? contentLabel : null;
  const submit = new FakeElement('button');
  const type = new FakeElement('select');
  const imageFile = new FakeElement('input'); imageFile.files = [];
  const imageFileLabel = new FakeElement('label');
  const imageFileStatus = new FakeElement('p');
  const dialog = new FakeElement('dialog');
  const newAsset = new FakeElement('button');
  const zoneExtract = new FakeElement('button');
  const assetSearch = new FakeElement('input');
  const byId = {
    'asset-create-form': form, 'asset-create-close': close, 'asset-create-name': name,
    'asset-create-content': content, 'asset-create-submit': submit,
    'asset-create-dialog': dialog, 'zone-extract': zoneExtract, 'asset-search': assetSearch,
    'asset-create-image-file':imageFile,'asset-create-image-file-label':imageFileLabel,
    'asset-create-image-file-status':imageFileStatus,
    'asset-create-type':type,
  };
  const readers=[];
  const sandbox = {
    state, assetRequest: 1, workspaceContentLoadRequest:0, assetDiscard: new FakeElement('button'),
    assetRecompile: new FakeElement('button'),
    element: (tag, text) => new FakeElement(tag, text),
    $: id => { if (!byId[id]) throw new Error(`unexpected element id ${id}`); return byId[id]; },
    guard: fn => async (...args) => { try { return await fn(...args); } catch (error) { calls.errors.push(error.message); } },
    api: async (route, body) => { calls.api.push({ route, body }); return apiImpl ? apiImpl(route, body) : { name: body.name, asset_id: 'asset-new' }; },
    beginWorkspaceContentLoad:(message,retry)=>{const owner=++sandbox.workspaceContentLoadRequest;calls.blockers.push({owner,message,retry});return owner;},
    finishWorkspaceContentLoad:owner=>calls.finished.push(owner),
    failWorkspaceContentLoad:(owner,message,retry)=>calls.blockers.push({owner,message,retry,failed:true}),
    loadAssets: async () => { calls.loaded++; }, openAsset: async id => { calls.opened.push(id); },
    refreshWorkspaceTree: async () => { calls.refreshed++; },
    toast: message => calls.toasts.push(message),
    FileReader:class {constructor(){this.readyState=0;readers.push(this);}readAsDataURL(file){this.file=file;this.readyState=1;}abort(){this.readyState=2;this.onabort?.();}finish(){this.readyState=2;this.result='data:application/octet-stream;base64,RERTIA==';this.onload?.();}},
    atob: encoded => Buffer.from(encoded, 'base64').toString('binary'),
  };
  sandbox.newAsset = newAsset;
  vm.runInNewContext(`${source}\nthis.__assetCreateType=assetCreateType; this.__assetCreateForm=$('asset-create-form');`, sandbox, { filename: appPath });
  form.type = sandbox.__assetCreateType; form.name = name; form.content = content;
  return { calls, state, sandbox, form, close, name, content, submit, type: sandbox.__assetCreateType, dialog, newAsset, imageFile, imageFileLabel, imageFileStatus, readers };
}

function setupRemoval(assetCodecs = {}, apiImpl) {
  const capability = app.match(/^function canRemoveAsset\(asset\)\{.*\}$/m);
  assert.ok(capability, 'asset removal capability exists');
  const start = app.indexOf('assetRemove.onclick=guard');
  const end = app.indexOf('\nconst imagePanel=', start);
  assert.ok(start !== -1 && end > start, 'asset removal handler is bounded');
  const calls = { api: [], errors: [], opened: [], shown: [], loaded: 0, refreshed: 0, toasts: [], blockers: [], finished: [], confirms: [] };
  const state = { page:'sources', zoneId:'zone', assetCodecs, asset: { type_id: 52, asset_id: 'zone:17', revision: 'revision-1' } };
  const button = new FakeElement('button');
  const sandbox = {
    state, assetRequest: 1, workspaceContentLoadRequest:0, assetRemove: button,
    assetLifecycleBusy:false,assetLifecycleOwner:0,assetSaveInFlight:false,assetSaveOwner:0,
    window:{confirm(message){calls.confirms.push(message);return true;}},dirty:()=>false,
    guard: fn => async () => { try { await fn(); } catch (error) { calls.errors.push(error.message); } },
    api: async (route, body) => {
      calls.api.push({ route, body });
      if(apiImpl)return apiImpl(route, body);
      return { ...state.asset, zone_id:state.zoneId, revision:'revision-queued',
        operation:'remove', pending_path:'draft.json' };
    },
    beginWorkspaceContentLoad:(message,retry)=>{const owner=++sandbox.workspaceContentLoadRequest;calls.blockers.push({owner,message,retry});return owner;},
    finishWorkspaceContentLoad:owner=>calls.finished.push(owner),
    failWorkspaceContentLoad:(owner,message)=>calls.errors.push(message),
    openAsset: async id => { calls.opened.push(id); },
    showAsset: asset => { calls.shown.push(asset); state.asset=asset; },
    loadAssets: async () => { calls.loaded++; }, refreshWorkspaceTree: async () => { calls.refreshed++; },
    toast: message => calls.toasts.push(message),
  };
  const mutationStart=app.indexOf('async function runScopedAssetMutation(');
  const mutationEnd=app.indexOf('\nasync function loadJobs()',mutationStart);
  assert.ok(mutationStart>=0&&mutationEnd>mutationStart,'shared mutation handler is bounded');
  vm.runInNewContext(capability[0] + '\n' + app.slice(mutationStart,mutationEnd) + '\n' +
    app.slice(start, end), sandbox, { filename: appPath });
  return { state, sandbox, button, calls };
}

function setupSave(apiImpl) {
  const calls={api:[],blockers:[],finished:[],failed:[],shown:[],tree:[],toasts:[]};
  const selected={asset_id:'zone:51',zone_id:'zone',revision:'revision-1',editable:true,content:'old'};
  const state={asset:selected,zoneId:'zone'};
  const editor=new FakeElement('textarea');editor.value='new text';
  const sandbox={state,assetRequest:7,workspaceContentLoadRequest:0,assetSaveInFlight:false,assetSaveOwner:0,imageRenderBusy:false,
    assetLifecycleBusy:false,assetLifecycleOwner:0,workspaceTree:{node:'zone',offset:0},
    $:id=>{if(id==='asset-content')return editor;throw new Error(`unexpected element ${id}`);},
    beginWorkspaceContentLoad:(message,retry)=>{const owner=++sandbox.workspaceContentLoadRequest;calls.blockers.push({owner,message,retry});return owner;},
    finishWorkspaceContentLoad:owner=>calls.finished.push(owner),
    failWorkspaceContentLoad:(owner,message)=>calls.failed.push({owner,message,retry:calls.blockers.at(-1)?.retry}),
    api:async(route,body)=>{calls.api.push({route,body});return apiImpl(route,body);},
    showAsset:asset=>{calls.shown.push(asset);state.asset=asset;},
    loadWorkspaceTree:async(node,offset)=>{calls.tree.push({node,offset});},toast:message=>calls.toasts.push(message)};
  const start=app.indexOf('async function saveAsset() {'),end=app.indexOf('\nasync function loadJobs()',start);
  assert.ok(start>=0&&end>start,'asset save handler is bounded');
  vm.runInNewContext(app.slice(start,end)+'\nthis.__saveAsset=saveAsset;',sandbox,{filename:appPath});
  return {sandbox,calls,state,editor};
}

(async () => {
  const bankContent='{"soundBank":"bank","aliases":[]}';
  const soundbankSave=setupSave((route,body)=>route==='/api/asset/save'?
    {revision:'bank-revision-2'}:
    {asset_id:'zone:21',zone_id:'zone',type_id:21,revision:'bank-revision-2',editable:true,content:bankContent});
  soundbankSave.state.asset={asset_id:'zone:21',zone_id:'zone',type_id:21,revision:'bank-revision-1',editable:true,content:'old bank source'};
  soundbankSave.editor.value=bankContent;
  soundbankSave.sandbox.saveSound=()=>{throw new Error('Alias JSON must not route through the WAV saver');};
  await soundbankSave.sandbox.__saveAsset();
  assert.equal(soundbankSave.calls.api[0].route,'/api/asset/save');
  assert.equal(soundbankSave.calls.api[0].body.content,bankContent,'SoundBank JSON uses the generic revisioned source saver');
  assert.equal(soundbankSave.calls.shown[0].revision,'bank-revision-2');

  const unavailable = setup({});
  unavailable.newAsset.onclick();
  assert.equal(unavailable.dialog.open, true);
  const unavailableOptions = Object.fromEntries(unavailable.type.options.map(option => [option.value, option]));
  assert.equal(unavailableOptions.localize.hidden, false);
  assert.equal(unavailableOptions.localize.disabled, false);
  assert.equal(unavailableOptions.luafile.hidden, true);
  assert.equal(unavailableOptions.luafile.disabled, true);
  assert.equal(unavailableOptions.scriptfile.hidden, true);
  assert.equal(unavailableOptions.scriptfile.disabled, true);
  assert.equal(unavailableOptions.rawfile.hidden,true,'RawFile creation stays hidden unless the backend advertises the writer');
  assert.equal(unavailableOptions['rawfile-base64'].hidden,true,'binary creation requires a mode-aware backend');
  assert.equal(unavailableOptions.stringtable.hidden,true,'StringTable creation requires the native writer capability');

  const rawfileDenied=setup({rawfile:{row_remove:true}});rawfileDenied.newAsset.onclick();
  assert.equal(rawfileDenied.type.options.find(option=>option.value==='rawfile').disabled,true,
    'RawFile removal capability does not grant creation capability');

  const imageCreate=setup({image:{row_create:true,row_create_types:[19]}});
  imageCreate.newAsset.onclick();imageCreate.type.value='image';imageCreate.type.onchange();
  imageCreate.imageFile.files=[{name:'older.dds',size:256}];
  const oldRead=imageCreate.imageFile.onchange();
  assert.equal(imageCreate.imageFile.disabled,true,'DDS chooser is locked while a read is pending');
  assert.equal(imageCreate.close.disabled,true,'creation dialog cannot close during a pending DDS read');
  let cancelled=false;imageCreate.dialog.listeners.cancel({preventDefault(){cancelled=true;}});
  assert.equal(cancelled,true,'Escape cannot dismiss creation while DDS bytes are loading');
  imageCreate.imageFile.files=[{name:'newer.dds',size:512}];
  const newRead=imageCreate.imageFile.onchange();
  imageCreate.readers[0].finish();
  await Promise.resolve();await Promise.resolve();
  assert.match(imageCreate.imageFileStatus.textContent,/Reading newer\.dds/,
    'a late earlier FileReader result cannot overwrite the active selection');
  imageCreate.readers[1].finish();await Promise.all([oldRead,newRead]);
  assert.match(imageCreate.imageFileStatus.textContent,/newer\.dds · 512 bytes ready/);
  imageCreate.name.value='images/custom_roundtrip';
  await imageCreate.form.onsubmit({preventDefault(){}});
  assert.match(imageCreate.calls.api[0].body.content,/^data:application\/octet-stream;base64,/);
  assert.equal(imageCreate.calls.api[0].body.name,'images/custom_roundtrip');

  const enabled = setup({ lua: { row_create: true }, gsc: { row_create: true }, rawfile:{row_create:true} });
  enabled.newAsset.onclick();
  const options = Object.fromEntries(enabled.type.options.map(option => [option.value, option]));
  assert.equal(options.luafile.disabled, false);
  assert.equal(options.scriptfile.hidden, false);
  assert.equal(options.scriptfile.disabled, false);
  assert.equal(options.rawfile.hidden,false);
  assert.equal(options.rawfile.disabled,false);
  enabled.type.value = 'scriptfile'; enabled.type.onchange();
  assert.equal(enabled.form.h3.textContent, 'Add GSC ScriptFile');
  assert.equal(enabled.name.placeholder, 'custom/frontend.gsc');
  assert.equal(enabled.name.parentElement.firstChild.textContent, 'Filename');
  assert.equal(enabled.content.attrs['aria-label'], 'New GSC ScriptFile source');
  assert.equal(enabled.submit.textContent, 'Create GSC ScriptFile');
  assert.match(enabled.form.p.textContent, /staged in this fastfile/);
  assert.match(enabled.form.p.textContent, /validates the ScriptFile row/);
  enabled.name.value = 'custom/test_feature.gsc';
  enabled.content.value = 'main() {\n  return;\n}\n';
  await enabled.form.onsubmit({ preventDefault() {} });
  assert.deepEqual(JSON.parse(JSON.stringify(enabled.calls.api)), [{ route: '/api/asset/create', body: {
    zone_id: 'zone-1', type: 'scriptfile', name: 'custom/test_feature.gsc', content: 'main() {\n  return;\n}\n',
  }}]);
  assert.equal(enabled.dialog.open, false);
  assert.equal(enabled.calls.loaded, 1);
  assert.equal(enabled.calls.refreshed, 1);
  assert.deepEqual(enabled.calls.opened, ['asset-new']);
  assert.deepEqual(enabled.calls.errors, []);
  assert.equal(enabled.submit.disabled, false);
  assert.match(enabled.calls.toasts[0], /Asset creation queued/);

  const rawfile=setup({rawfile:{row_create:true}});
  rawfile.newAsset.onclick();rawfile.type.value='rawfile';rawfile.type.onchange();
  assert.equal(rawfile.name.placeholder,'custom/frontend.cfg');
  assert.equal(rawfile.form.h3.textContent,'Add RawFile text');
  assert.equal(rawfile.content.attrs['aria-label'],'New RawFile text');
  assert.equal(rawfile.form.p.textContent,'Adds a text file to this fastfile. Compile game includes the saved file in the build.');
  rawfile.name.value='custom/frontend.cfg';rawfile.content.value='seta ui_language "english"\n';
  let resolveRawfile;rawfile.sandbox.api=async(route,body)=>{
    rawfile.calls.api.push({route,body});
    return new Promise(resolve=>{resolveRawfile=resolve;});
  };
  const rawfileSubmit=rawfile.form.onsubmit({preventDefault(){}});
  assert.equal(rawfile.dialog.open,false,'the modal closes during the request so unrelated app areas stay usable');
  assert.match(rawfile.calls.blockers[0].message,/Adding RawFile text/);
  assert.equal(rawfile.calls.blockers.length,1,'creation visibly blocks the shared content region while pending');
  resolveRawfile({name:'custom/frontend.cfg',asset_id:'raw-51'});await rawfileSubmit;
  assert.deepEqual(JSON.parse(JSON.stringify(rawfile.calls.api)),[{route:'/api/asset/create',body:{zone_id:'zone-1',
    type:'rawfile',name:'custom/frontend.cfg',content:'seta ui_language "english"\n'}}]);
  assert.deepEqual(rawfile.calls.opened,['raw-51']);
  assert.deepEqual(rawfile.calls.finished,[rawfile.calls.blockers[0].owner]);

  const binaryDenied=setup({rawfile:{row_create:true}});binaryDenied.newAsset.onclick();
  assert.equal(binaryDenied.type.options.find(option=>option.value==='rawfile-base64').disabled,true,
    'a text-only public API must not advertise binary creation');
  const binary=setup({rawfile:{row_create:true,row_create_modes:['text','base64']}});
  binary.newAsset.onclick();binary.type.value='rawfile-base64';binary.type.onchange();
  assert.equal(binary.name.placeholder,'custom/data.bin');
  assert.equal(binary.content.attrs['aria-label'],'New RawFile Base64 data');
  binary.name.value='custom/data.bin';binary.content.value='AAH/';
  await binary.form.onsubmit({preventDefault(){}});
  assert.deepEqual(JSON.parse(JSON.stringify(binary.calls.api)),[{route:'/api/asset/create',body:{
    zone_id:'zone-1',type:'rawfile',editor_mode:'base64',name:'custom/data.bin',content:'AAH/'}}]);

  const table=setup({stringtable:{row_create:true}});
  table.newAsset.onclick();table.type.value='stringtable';table.type.onchange();
  assert.equal(table.form.h3.textContent,'Add StringTable');
  assert.equal(table.name.placeholder,'custom/frontend.csv');
  assert.equal(table.content.attrs['aria-label'],'New StringTable CSV');
  assert.equal(table.submit.textContent,'Create StringTable');
  table.name.value='custom/frontend.csv';table.content.value='key,value\nexample,"quoted, cell"\n';
  await table.form.onsubmit({preventDefault(){}});
  assert.deepEqual(JSON.parse(JSON.stringify(table.calls.api)),[{route:'/api/asset/create',body:{
    zone_id:'zone-1',type:'stringtable',name:'custom/frontend.csv',content:'key,value\nexample,"quoted, cell"\n'}}]);
  assert.deepEqual(table.calls.opened,['asset-new']);
  assert.deepEqual(table.calls.errors,[]);

  let resolveSave,resolveReadback;const saveFlow=setupSave((route)=>route==='/api/asset/save'?
    new Promise(resolve=>{resolveSave=resolve;}):new Promise(resolve=>{resolveReadback=resolve;}));
  const saving=saveFlow.sandbox.__saveAsset();
  assert.equal(saveFlow.calls.blockers.length,1,'save blocks only the editor content region while compiling');
  assert.match(saveFlow.calls.blockers[0].message,/Saving asset/);
  assert.deepEqual(JSON.parse(JSON.stringify(saveFlow.calls.api[0])),{route:'/api/asset/save',body:{asset_id:'zone:51',content:'new text',revision:'revision-1'}});
  await saveFlow.sandbox.__saveAsset();
  assert.equal(saveFlow.calls.api.length,1,'duplicate save submissions are ignored while the first is pending');
  resolveSave({asset_id:'zone:51',revision:'revision-2'});
  await new Promise(resolve=>setImmediate(resolve));
  assert.equal(saveFlow.calls.api.length,2,'readback starts after the accepted save');
  resolveReadback({asset_id:'zone:51',zone_id:'zone',revision:'revision-2',content:'new text',editable:true});
  await saving;
  assert.deepEqual(saveFlow.calls.finished,[saveFlow.calls.blockers[0].owner]);
  assert.equal(saveFlow.calls.tree.length,1);
  assert.equal(saveFlow.calls.api.filter(call=>call.route==='/api/asset/save').length,1);

  let readbackAttempts=0;const failedReadback=setupSave((route)=>route==='/api/asset/save'?
    Promise.resolve({asset_id:'zone:51',revision:'revision-2'}):(++readbackAttempts===1?
      Promise.reject(new Error('temporary readback error')):Promise.resolve({asset_id:'zone:51',zone_id:'zone',revision:'revision-2',content:'new text',editable:true})));
  await assert.rejects(failedReadback.sandbox.__saveAsset(),/temporary readback error/);
  assert.equal(failedReadback.editor.value,'new text','failed readback leaves the submitted editor text intact');
  assert.equal(failedReadback.calls.failed.length,1);
  await failedReadback.calls.blockers[0].retry();
  assert.equal(failedReadback.calls.api.filter(call=>call.route==='/api/asset/save').length,1,
    'retry after accepted save performs readback only');
  assert.equal(failedReadback.calls.shown.length,1);

  const rawfileFailure=setup({rawfile:{row_create:true}},async()=>{throw new Error('RawFile source must be text');});
  rawfileFailure.newAsset.onclick();rawfileFailure.type.value='rawfile';rawfileFailure.type.onchange();
  rawfileFailure.name.value='custom/frontend.cfg';rawfileFailure.content.value='preserve this text';
  await rawfileFailure.form.onsubmit({preventDefault(){}});
  assert.equal(rawfileFailure.dialog.open,true,'a rejected RawFile create reopens the modal with its draft intact');
  assert.equal(rawfileFailure.content.value,'preserve this text');
  assert.deepEqual(rawfileFailure.calls.finished,[rawfileFailure.calls.blockers[0].owner]);

  const failed = setup({ gsc: { row_create: true } }, async () => { throw new Error('ScriptFile compiler rejected source'); });
  failed.newAsset.onclick(); failed.type.value = 'scriptfile'; failed.type.onchange();
  failed.name.value = 'custom/bad.gsc'; failed.content.value = 'not valid';
  await failed.form.onsubmit({ preventDefault() {} });
  assert.equal(failed.calls.api.length, 1);
  assert.equal(failed.dialog.open, true, 'failed create leaves the form open');
  assert.equal(failed.name.value, 'custom/bad.gsc');
  assert.equal(failed.content.value, 'not valid');
  assert.equal(failed.submit.disabled, false, 'failed create re-enables submit');
  assert.deepEqual(failed.calls.errors, ['ScriptFile compiler rejected source']);
  assert.equal(failed.calls.loaded, 0);

  const denied = setup({}); denied.newAsset.onclick(); denied.type.value = 'scriptfile';
  await denied.form.onsubmit({ preventDefault() {} });
  assert.equal(denied.calls.api.length, 0, 'submit rechecks backend capability');
  assert.equal(denied.dialog.open, true);
  assert.equal(denied.submit.disabled, false);
  assert.match(denied.calls.errors[0], /not supported by this backend/);

  const removeDenied = setupRemoval({ gsc: { row_create: true } });
  await removeDenied.button.onclick();
  assert.equal(removeDenied.calls.api.length, 0, 'create capability does not grant removal');

  const rawfileRemoveDenied=setupRemoval({rawfile:{row_create:true}});
  rawfileRemoveDenied.state.asset.type_id=51;
  await rawfileRemoveDenied.button.onclick();
  assert.equal(rawfileRemoveDenied.calls.api.length,0,'RawFile create capability does not grant row removal');

  const rawfileRemove=setupRemoval({rawfile:{row_remove:true}});
  rawfileRemove.state.asset.type_id=51;rawfileRemove.state.asset.asset_id='zone:51';
  rawfileRemove.state.asset.row_remove_supported=true;
  await rawfileRemove.button.onclick();
  assert.deepEqual(JSON.parse(JSON.stringify(rawfileRemove.calls.api.filter(call=>call.route==='/api/asset/remove'))),[{route:'/api/asset/remove',body:{
    asset_id:'zone:51',revision:'revision-1'}}]);
  assert.match(rawfileRemove.calls.blockers[0].message,/Removing asset/);
  assert.deepEqual(rawfileRemove.calls.finished,[rawfileRemove.calls.blockers[0].owner]);

  const remove = setupRemoval({ gsc: { row_remove: true } });
  await remove.button.onclick();
  assert.deepEqual(JSON.parse(JSON.stringify(remove.calls.api.filter(call=>call.route==='/api/asset/remove'))), [{ route: '/api/asset/remove', body: {
    asset_id: 'zone:17', revision: 'revision-1',
  }}]);
  assert.deepEqual(remove.calls.shown.map(asset=>asset.asset_id), ['zone:17']);
  assert.equal(remove.calls.loaded, 1);
  assert.equal(remove.calls.refreshed, 1);
  assert.match(remove.calls.toasts[0], /Removal queued/);

  const tableRemove=setupRemoval({stringtable:{row_remove:true}});
  tableRemove.state.asset.type_id=54;
  await tableRemove.button.onclick();
  assert.equal(tableRemove.calls.api.length,0,'StringTable removal needs explicit per-row eligibility');
  tableRemove.state.asset.row_remove_supported=true;
  await tableRemove.button.onclick();
  assert.equal(tableRemove.calls.api.filter(call=>call.route==='/api/asset/remove').length,1);

  for (const pending of [{ operation: 'remove' }, { pending_path: 'draft.json' }]) {
    const test = setupRemoval({ gsc: { row_remove: true } });
    Object.assign(test.state.asset, pending);
    await test.button.onclick();
    assert.equal(test.calls.api.length, 0, 'pending edits cannot be removed through the UI');
  }

  const refused = setupRemoval({ gsc: { row_remove: true } }, async () => {
    throw new Error('ScriptFile removal requires the final exclusive row');
  });
  await refused.button.onclick();
  assert.deepEqual(refused.calls.errors, ['ScriptFile removal requires the final exclusive row']);
  assert.equal(refused.button.disabled, false, 'backend refusal restores the control');
  assert.equal(refused.calls.loaded, 0);
  assert.equal(refused.calls.toasts.length, 0);

  let resolveRemoval;
  const changed = setupRemoval({ gsc: { row_remove: true } }, () => new Promise(resolve => { resolveRemoval = resolve; }));
  const inFlight = changed.button.onclick();
  assert.equal(changed.button.disabled, true);
  changed.sandbox.assetRequest++;
  changed.state.asset = { type_id: 52, asset_id: 'zone:18', revision: 'revision-2' };
  resolveRemoval({});
  await inFlight;
  assert.equal(changed.calls.opened.length, 0, 'late removal response cannot reopen the old selection');
  assert.equal(changed.calls.toasts.length, 0);

  process.stdout.write('Asset create/remove UI regression passed: capability gating, revisioned requests, error recovery and stale selection.\n');
})().catch(error => { console.error(error); process.exitCode = 1; });
