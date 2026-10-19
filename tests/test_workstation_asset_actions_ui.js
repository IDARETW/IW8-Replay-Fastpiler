'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const app = fs.readFileSync(process.env.REPLAY_WORKSTATION_APP_JS || 'workstation/web/app.js', 'utf8');

function makeMutationHarness(api) {
  const selected={asset_id:'zone:51',revision:'rev-1',content:'unsaved editor text'};
  const state={asset:selected,zoneId:'zone'};
  const calls={api:[],blockers:[],finished:[],failed:[],refresh:[],applied:[],toasts:[]};
  const sandbox={state,assetRequest:3,workspaceContentLoadRequest:0,assetLifecycleBusy:false,assetLifecycleOwner:0,
    assetSaveInFlight:false,assetSaveOwner:0,soundMutationOwner:0,soundBusy:false,
    api:async(...args)=>{calls.api.push(args);return api(...args);},
    beginWorkspaceContentLoad:(message,retry)=>{const owner=++sandbox.workspaceContentLoadRequest;calls.blockers.push({owner,message,retry});return owner;},
    finishWorkspaceContentLoad:owner=>calls.finished.push(owner),
    failWorkspaceContentLoad:(owner,message)=>calls.failed.push({owner,message}),
    refresh:async(value)=>calls.refresh.push(value),apply:value=>calls.applied.push(value),
    toast:message=>calls.toasts.push(message)};
  const start=app.indexOf('async function runScopedAssetMutation('),end=app.indexOf('\nasync function loadJobs()',start);
  assert.ok(start>=0&&end>start,'shared scoped asset mutation helper exists');
  const invalidateStart=app.indexOf('function invalidateWorkspaceMutationGuards()'),invalidateEnd=app.indexOf('\nasync function openAsset',invalidateStart);
  vm.runInNewContext(app.slice(invalidateStart,invalidateEnd)+'\n'+app.slice(start,end)+
    '\nthis.invalidate=invalidateWorkspaceMutationGuards;this.runMutation=runScopedAssetMutation;',sandbox,{filename:'app.js'});
  return {sandbox,calls,state};
}

function makeSoundHarness(api) {
  const row={zone_id:'zone',asset_id:'zone:21',file_id:5,revision:'sound-rev-1'};
  const calls={api:[],blockers:[],finished:[],failed:[],selected:0,toasts:[]};
  let implementation=api;
  const sandbox={state:{page:'sources',zoneId:'zone',asset:{asset_id:row.asset_id}},assetRequest:4,
    workspaceContentLoadRequest:0,assetLifecycleBusy:false,assetLifecycleOwner:0,assetSaveInFlight:false,
    assetSaveOwner:0,soundMutationOwner:0,
    soundSelection:row,soundBusy:false,soundEntries:[row],soundDrafts:[],
    soundImport:{files:[],value:''},soundSave:{disabled:false},soundGainSave:{disabled:false},
    soundDiscard:{disabled:false},soundGain:{value:'100'},
    soundSelect:{value:'5'},soundNotice:{textContent:''},soundPlayer:{pause(){},removeAttribute(){},load(){}},
    selectSound(){calls.selected++;},
    api:async(...args)=>{calls.api.push(args);return implementation(...args);},
    beginWorkspaceContentLoad:(message,retry)=>{const owner=++sandbox.workspaceContentLoadRequest;calls.blockers.push({owner,message,retry});return owner;},
    finishWorkspaceContentLoad:owner=>calls.finished.push(owner),
    failWorkspaceContentLoad:(owner,message)=>calls.failed.push({owner,message}),
    toast:message=>calls.toasts.push(message),
    failWorkspaceContentLoadRetry:null};
  const start=app.indexOf('async function saveSound(action){'),end=app.indexOf('\nsoundSelect.onchange=',start);
  assert.ok(start>=0&&end>start,'resident sound mutation handler exists');
  const invalidateStart=app.indexOf('function invalidateWorkspaceMutationGuards()'),invalidateEnd=app.indexOf('\nasync function openAsset',invalidateStart);
  vm.runInNewContext(app.slice(invalidateStart,invalidateEnd)+'\n'+app.slice(start,end)+
    '\nthis.invalidate=invalidateWorkspaceMutationGuards;this.saveSound=saveSound;',sandbox,{filename:'app.js'});
  return {sandbox,calls,row,setApi:fn=>{implementation=fn;}};
}

(async()=>{
  assert.match(app,/postPath:'\/api\/asset\/recompile'/,'Recompile uses the scoped mutation flow');
  assert.match(app,/postPath:'\/api\/asset\/remove'/,'asset removal uses the scoped mutation flow');
  assert.match(app,/postPath:'\/api\/asset\/discard'/,'restore and cancel use the scoped mutation flow');
  const openStart=app.indexOf('async function openAsset('),openEnd=app.indexOf('\nfunction showAsset(',openStart);
  assert.match(app.slice(openStart,openEnd),/invalidateWorkspaceMutationGuards\(\)/,
    'opening another asset releases a failed prior selection guard');
  assert.match(app,/function clearWorkspaceSelection\(\)\{\s*invalidateWorkspaceMutationGuards\(\)/,
    'leaving Game Source releases selection-scoped guards');
  const removalStart=app.indexOf('function canRemoveAsset('),removalEnd=app.indexOf('\n',removalStart);
  const removalSandbox={state:{assetCodecs:{rawfile:{row_remove:true}}}};
  vm.runInNewContext(app.slice(removalStart,removalEnd)+'\nthis.canRemoveAsset=canRemoveAsset;',removalSandbox);
  assert.equal(removalSandbox.canRemoveAsset({type_id:51,row_remove_supported:false}),false,
    'backend RawFile capability alone cannot enable unsupported rows');
  assert.equal(removalSandbox.canRemoveAsset({type_id:51,row_remove_supported:true}),true,
    'only rows explicitly marked removable expose native RawFile removal');

  let resolvePost,rejectGet,getCount=0;const asset=makeMutationHarness(route=>route==='/api/asset/recompile'?
    new Promise(resolve=>{resolvePost=resolve;}):(++getCount===1?new Promise((_resolve,reject)=>{rejectGet=reject;}):
      Promise.resolve({asset_id:'zone:51',zone_id:'zone',revision:'rev-2',content:'checked'})));
  const action=asset.sandbox.runMutation({message:'Recompiling asset draft…',selected:asset.state.asset,
    request:3,zoneId:'zone',postPath:'/api/asset/recompile',body:{asset_id:'zone:51',revision:'rev-1'},
    readBack:()=>asset.sandbox.api('/api/asset?id=zone%3A51'),refresh:value=>asset.sandbox.refresh(value),
    apply:value=>asset.sandbox.apply(value),success:()=>'ok'});
  await asset.sandbox.runMutation({message:'duplicate',selected:asset.state.asset,request:3,zoneId:'zone',
    postPath:'/api/asset/recompile',body:{asset_id:'zone:51',revision:'rev-1'},readBack:async()=>null});
  assert.equal(asset.calls.api.length,1,'duplicate lifecycle submissions are suppressed');
  assert.match(asset.calls.blockers[0].message,/Recompiling/);
  resolvePost({asset_id:'zone:51',revision:'rev-2'});
  await new Promise(resolve=>setImmediate(resolve));
  rejectGet(new Error('readback pending'));
  await assert.rejects(action,/readback pending/);
  assert.equal(asset.state.asset.content,'unsaved editor text','failed readback leaves the active editor buffer untouched');
  assert.equal(asset.calls.applied.length,0);
  await asset.calls.blockers[0].retry();
  assert.equal(asset.calls.finished.length,1);
  assert.equal(asset.calls.applied[0].content,'checked');
  assert.equal(asset.calls.api.filter(args=>args[0]==='/api/asset/recompile').length,1);

  let createRefreshes=0;const cancelCreate=makeMutationHarness(async()=>({asset_id:'zone:51',
    revision:'rev-1',discarded:true,operation_id:'op-a-1'}));
  cancelCreate.sandbox.refresh=async()=>{if(++createRefreshes===1)throw new Error('tree refresh pending');};
  const cancelCreateAction={message:'Cancelling asset creation…',selected:cancelCreate.state.asset,request:3,
    zoneId:'zone',postPath:'/api/asset/discard',body:{asset_id:'zone:51',revision:'rev-1'},
    readBack:async()=>null,refresh:()=>cancelCreate.sandbox.refresh(),apply:value=>cancelCreate.sandbox.apply(value)};
  await assert.rejects(cancelCreate.sandbox.runMutation(cancelCreateAction),/tree refresh pending/);
  await cancelCreate.calls.blockers[0].retry();
  assert.equal(cancelCreate.calls.api.length,1,'creation-cancel refresh retry does not repost discard');
  assert.equal(cancelCreate.calls.finished.length,1);

  const cancelRemoval=makeMutationHarness(async()=>({asset_id:'zone:51',revision:'rev-1',discarded:true}));
  const restoredNative={asset_id:'zone:51',zone_id:'zone',revision:'native-original-rev',content:'original'};
  await cancelRemoval.sandbox.runMutation({message:'Restoring original asset…',selected:cancelRemoval.state.asset,
    request:3,zoneId:'zone',postPath:'/api/asset/discard',body:{asset_id:'zone:51',revision:'rev-1'},
    readBack:async()=>restoredNative,apply:value=>cancelRemoval.sandbox.apply(value)});
  assert.equal(cancelRemoval.calls.applied[0].revision,'native-original-rev',
    'restored native revision is allowed to differ from the discarded draft revision');
  assert.equal(cancelRemoval.calls.api.length,1);

  let resolveNewPost,resolveNewRead;let oldReadCount=0;
  const transition=makeMutationHarness(route=>{
    if(route==='/old-mutation')return Promise.resolve({asset_id:'zone:51'});
    if(route==='/old-readback')return ++oldReadCount===1?Promise.reject(new Error('old readback failed')):
      Promise.resolve({asset_id:'zone:51',zone_id:'zone',revision:'rev-1'});
    if(route==='/new-mutation')return new Promise(resolve=>{resolveNewPost=resolve;});
    if(route==='/new-readback')return new Promise(resolve=>{resolveNewRead=resolve;});
    throw new Error(`unexpected route ${route}`);
  });
  const oldAction=transition.sandbox.runMutation({message:'Old mutation…',selected:transition.state.asset,
    request:3,zoneId:'zone',postPath:'/old-mutation',body:{},readBack:()=>transition.sandbox.api('/old-readback')});
  await assert.rejects(oldAction,/old readback failed/);
  assert.equal(transition.sandbox.assetLifecycleBusy,true,'accepted failed readback retains its retry guard');
  transition.sandbox.invalidate();
  transition.state.asset={asset_id:'zone:52',revision:'rev-new'};transition.sandbox.assetRequest++;
  assert.equal(transition.sandbox.assetLifecycleBusy,false,'changing asset selection releases the abandoned guard');
  const newAction=transition.sandbox.runMutation({message:'New mutation…',selected:transition.state.asset,
    request:transition.sandbox.assetRequest,zoneId:'zone',postPath:'/new-mutation',body:{},
    readBack:()=>transition.sandbox.api('/new-readback')});
  resolveNewPost({asset_id:'zone:52'});await new Promise(resolve=>setImmediate(resolve));
  const newOwner=transition.sandbox.assetLifecycleOwner;
  await transition.calls.blockers[0].retry();
  assert.equal(transition.sandbox.assetLifecycleBusy,true,'late retry from old selection cannot clear new busy owner');
  assert.equal(transition.sandbox.assetLifecycleOwner,newOwner);
  resolveNewRead({asset_id:'zone:52',zone_id:'zone',revision:'rev-new'});await newAction;
  assert.equal(transition.sandbox.assetLifecycleBusy,false);
  transition.sandbox.assetSaveInFlight=true;const oldSaveOwner=transition.sandbox.assetSaveOwner;
  transition.sandbox.invalidate();
  assert.equal(transition.sandbox.assetSaveInFlight,false,'selection change also releases asset-save guard');
  assert.ok(transition.sandbox.assetSaveOwner>oldSaveOwner);

  let draftsAttempt=0;const sound=makeSoundHarness(route=>route==='/api/sound/discard'?
    {zone_id:'zone',file_id:5,discarded_revision:'sound-rev-1'}:
    (++draftsAttempt===1?Promise.reject(new Error('draft readback unavailable')):Promise.resolve({items:[]})));
  await assert.rejects(sound.sandbox.saveSound('discard'),/draft readback unavailable/);
  assert.equal(sound.calls.blockers.length,1,'SFX restore blocks the editor while mutation/readback runs');
  assert.equal(sound.calls.failed.length,1);
  assert.equal(sound.calls.api.filter(args=>args[0]==='/api/sound/discard').length,1);
  await sound.calls.blockers[0].retry();
  assert.equal(sound.calls.api.filter(args=>args[0]==='/api/sound/discard').length,1,
    'SFX retry after accepted restore repeats readback only');
  assert.equal(sound.calls.finished.length,1);
  assert.equal(sound.calls.selected,1);

  const soundSaveCheck=makeSoundHarness(route=>route==='/api/sound/gain'?
    {zone_id:'zone',asset_id:'zone:21',file_id:5,revision:'sound-rev-2'}:
    {items:[{zone_id:'zone',file_id:5,revision:'sound-rev-2'}]});
  await soundSaveCheck.sandbox.saveSound('gain');
  assert.equal(soundSaveCheck.calls.finished.length,1);
  assert.equal(soundSaveCheck.sandbox.soundDrafts[0].revision,'sound-rev-2',
    'sound save readback is bound to the acknowledged file revision');

  let soundGetCount=0;const leavingSound=makeSoundHarness(route=>route==='/api/sound/discard'?
    {zone_id:'zone',file_id:5,discarded_revision:'sound-rev-1'}:
    (++soundGetCount===1?Promise.reject(new Error('old sound readback failed')):Promise.resolve({items:[]})));
  await assert.rejects(leavingSound.sandbox.saveSound('discard'),/old sound readback failed/);
  leavingSound.sandbox.invalidate();
  const nextRow={zone_id:'zone',asset_id:'zone:22',file_id:6,revision:'sound-rev-2'};
  leavingSound.sandbox.soundSelection=nextRow;leavingSound.sandbox.state.asset.asset_id=nextRow.asset_id;
  leavingSound.sandbox.assetRequest++;
  let resolveSoundPost,resolveSoundRead;
  leavingSound.setApi(route=>route==='/api/sound/discard'?new Promise(resolve=>{resolveSoundPost=resolve;}):
    new Promise(resolve=>{resolveSoundRead=resolve;}));
  const nextSoundAction=leavingSound.sandbox.saveSound('discard');
  assert.equal(leavingSound.sandbox.soundBusy,true);
  await leavingSound.calls.blockers[0].retry();
  assert.equal(leavingSound.sandbox.soundBusy,true,'late sound retry from prior selection cannot clear new sound guard');
  resolveSoundPost({zone_id:'zone',file_id:6,discarded_revision:'sound-rev-2'});
  await new Promise(resolve=>setImmediate(resolve));
  resolveSoundRead({items:[]});await nextSoundAction;
  assert.equal(leavingSound.sandbox.soundBusy,false);
  console.log('Asset lifecycle and resident sound scoped-mutation regression passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
