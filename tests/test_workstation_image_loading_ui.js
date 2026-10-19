'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const app = fs.readFileSync(process.env.REPLAY_WORKSTATION_APP_JS || 'workstation/web/app.js', 'utf8');

function node(extra={}) {
  return {hidden:false,inert:false,disabled:false,dataset:{},style:{},attributes:{},children:[],
    setAttribute(name,value){this.attributes[name]=value;},removeAttribute(name){delete this.attributes[name];},
    setAttributeBusy(value){this.attributes['aria-busy']=value;},focus(){this.focused=true;},...extra};
}
function makeHarness() {
  const drawn=[],images=[];
  class DeferredImage {
    constructor(){this.id=images.length+1;images.push(this);}
    set src(value){this.source=value;}
  }
  const imagePanel=node(),tools=node(),view=node();imagePanel.children=[tools,view];
  const imageLoadMask=node(),imageLoadTitle=node(),imageLoadDetail=node(),imageLoadRetry=node();
  imagePanel.children.push(imageLoadMask);
  const imageCanvas=node({width:9,height:9,getContext:()=>({drawImage:image=>drawn.push(image.id)})});
  const imageDownload=node({href:'data:stale',download:''});
  const imageSize=node({textContent:''}),imageMips=node({max:'16',value:'1'}),assetSave=node({});
  const text=node({value:'image-a'});
  const ids={'asset-content':text,'asset-save':assetSave};
  const sandbox={
    state:{asset:{asset_id:'zone:asset',name:'picture.png',editable:true,source:{typed_layout:{level_count:1}}},assetCodecs:{image:{mip_editing:true}},buildActive:false,buildStarting:false},
    assetRequest:7,assetSaveInFlight:false,assetLifecycleBusy:false,
    imageRenderSequence:0,imageRenderToken:null,imageRenderBusy:false,imageStroke:null,imageUndoContent:null,
    imagePanel,imageLoadMask,imageLoadTitle,imageLoadDetail,imageLoadRetry,imageCanvas,imageDownload,imageSize,imageMips,
    imageTools:tools,imageView:view,
    Image:DeferredImage,$:id=>ids[id],guard:fn=>fn,
    toast:()=>{},
  };
  sandbox.imageCanvas.getContext=()=>({drawImage:image=>drawn.push(image.id)});
  const start=app.indexOf('function imageLoadCurrent('),end=app.indexOf('\nasync function saveAsset()',start);
  assert.ok(start>=0&&end>start,'image render lifecycle helpers exist');
  vm.runInNewContext(app.slice(start,end)+
    '\nthis.render=renderAssetImage;this.begin=beginImagePanelLoad;this.current=imageLoadCurrent;',sandbox,{filename:'app.js'});
  return {sandbox,images,drawn,imageLoadMask,imageLoadRetry,imageLoadTitle,imagePanel,tools,view,imageCanvas,imageDownload,assetSave,text};
}

(async()=>{
  assert.match(app,/imagePanel\.append\(imageTools,imageView,imageLoadMask\)/,'image blocker covers the image tools and preview');
  assert.match(app,/imageCanvas\.onpointerdown=event=>\{if\(imageRenderBusy\|\|!imageLoadCurrent\(imageRenderToken\)/,
    'painting is rejected while pixels are loading or belong to an old render');
  const h=makeHarness(),commit=value=>()=>{h.text.value=value;};
  const first=h.sandbox.render('image-a',{commit:commit('image-a')}),second=h.sandbox.render('image-b',{commit:commit('image-b')});
  assert.equal(h.imageLoadMask.hidden,false,'content remains masked after the asset request has handed off to PNG decoding');
  assert.equal(h.imageCanvas.width,0,'old canvas pixels are cleared while the new PNG is pending');
  assert.equal(h.tools.inert,true);assert.equal(h.view.inert,true);assert.equal(h.assetSave.disabled,true);
  h.images[0].width=1;h.images[0].height=1;h.images[0].onload();
  assert.equal(await first,false,'older same-asset decode is discarded');
  assert.equal(h.imageLoadMask.hidden,false,'an older completion cannot release a newer render blocker');
  assert.deepEqual(h.drawn,[],'old pixels are never painted during the newer decode');
  h.images[1].width=4;h.images[1].height=3;h.images[1].onload();
  assert.equal(await second,true,'newer render draws and releases the image panel');
  assert.equal(h.imageCanvas.width,4);assert.equal(h.imageCanvas.height,3);assert.deepEqual(h.drawn,[2]);
  assert.equal(h.imageLoadMask.hidden,true);assert.equal(h.tools.inert,false);assert.equal(h.assetSave.disabled,false);
  const third=h.sandbox.render('image-c',{commit:commit('image-c')}),fourth=h.sandbox.render('image-d',{commit:commit('image-d')});
  h.images[3].width=5;h.images[3].height=6;h.images[3].onload();assert.equal(await fourth,true);
  h.images[2].width=2;h.images[2].height=2;h.images[2].onload();assert.equal(await third,false);
  assert.deepEqual(h.drawn,[2,4],'older PNG cannot overwrite newer same-asset import/redraw pixels');
  assert.equal(h.imageCanvas.width,5);assert.equal(h.imageLoadMask.hidden,true);

  const failed=h.sandbox.render('bad-png',{commit:commit('bad-png')});h.images[4].onerror();
  assert.equal(await failed,false);assert.equal(h.imageLoadMask.hidden,false,'decode failure keeps the image content blocked');
  assert.equal(h.imageLoadMask.dataset.failed,'true');assert.equal(h.imageLoadRetry.hidden,false);
  assert.equal(h.imageLoadTitle.textContent,'Image preview could not be loaded');assert.equal(h.tools.inert,true);
  const retried=h.imageLoadRetry.onclick();
  assert.equal(h.imageLoadMask.hidden,false,'retry keeps the blocker up during its new decode');
  h.images[5].width=2;h.images[5].height=2;h.images[5].onload();
  assert.equal(await retried,true,'Retry releases the panel only after a successful draw');
  assert.equal(h.imageLoadMask.hidden,true);assert.equal(h.imageCanvas.width,2);assert.deepEqual(h.drawn,[2,4,6]);
  console.log('Image loading-mask UI tests passed.');
})().catch(error=>{console.error(error);process.exitCode=1;});
