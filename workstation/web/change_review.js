'use strict';
(() => {
  const make=(tag,text,className)=>element(tag,text,className);
  const action=(text,title,fn)=>{const b=make('button',text);b.type='button';b.title=title;b.onclick=guard(fn);return b;};
  const icon=document.createElementNS('http://www.w3.org/2000/svg','svg');
  icon.setAttribute('viewBox','0 0 24 24');icon.setAttribute('class','nav-icon ui-icon');icon.setAttribute('aria-hidden','true');
  // Fixed geometry only; review content always uses textContent or Monaco models.
  icon.innerHTML='<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 12h8M12 9v6M8 18h8"/>';
  const nav=action('', 'Review code and asset changes against their original baseline',open);
  nav.id='source-review';nav.setAttribute('aria-label','Review changes');nav.setAttribute('aria-haspopup','dialog');nav.setAttribute('aria-controls','source-review-dialog');
  nav.append(icon,make('span','Review changes','nav-text'));
  document.querySelector('#sidebar [data-page="sources"]').after(nav);

  const dialog=make('dialog',undefined,'change-review');dialog.id='source-review-dialog';dialog.setAttribute('aria-labelledby','source-review-title');
  const heading=make('header',undefined,'change-review-heading'),headingText=make('div');
  const title=make('h2','Change review');title.id='source-review-title';
  headingText.append(title,make('p','Inspect original code and assets, saved edits, and working buffers.','muted'));
  const close=action('×','Close source review',()=>dialog.close());close.className='icon-button';close.setAttribute('aria-label','Close source review');heading.append(headingText,close);
  const layout=make('div',undefined,'change-review-layout'),left=make('aside',undefined,'change-review-browser');left.setAttribute('aria-label','Source review candidates');
  const tools=make('div',undefined,'change-review-filters'),search=make('input'),filter=make('select');
  search.type='search';search.placeholder='Find a source or asset…';search.setAttribute('aria-label','Search review candidates');
  for(const [value,label] of [['all','All changes & inputs'],['working','Unsaved buffers'],['assets','Assets'],['audio','Audio'],['added','Added assets'],['removed','Removed assets'],['functions','Functions'],['globals','Globals'],['files','Authored files']]){const option=make('option',label);option.value=value;filter.append(option);}
  filter.setAttribute('aria-label','Filter review candidates');
  const refresh=action('Refresh','Refresh saved revisions and working buffers',load);
  tools.append(search,filter,refresh);const count=make('p','','change-review-count');count.setAttribute('role','status');
  const list=make('div',undefined,'change-review-list');list.setAttribute('aria-label','Review sources');left.append(tools,count,list);
  const detail=make('section',undefined,'change-review-detail'),header=make('div',undefined,'change-review-document');
  const name=make('h3','Choose a source'),path=make('p','','muted'),badges=make('div',undefined,'change-review-badges');header.append(name,path,badges);
  const controls=make('div',undefined,'change-review-controls');
  const previous=action('↑ Change','Previous changed section',()=>diff?.goToDiff('previous'));
  const next=action('↓ Change','Next changed section',()=>diff?.goToDiff('next'));
  const view=action('Inline','Toggle side-by-side or inline comparison',()=>{sideBySide=!sideBySide;applyOptions();});
  const wrap=action('Wrap lines','Toggle wrapping long lines',()=>{wordWrap=!wordWrap;applyOptions();});
  const collapse=action('Hide unchanged','Collapse unchanged code between changes',()=>{hideUnchanged=!hideUnchanged;applyOptions();});
  const edit=action('Open in editor','Open the selected source in the Game source editor',openEditor);
  const exportButton=action('Export review','Download this comparison with its source metadata',exportReview);
  controls.append(previous,next,view,wrap,collapse,exportButton,edit);
  const notes=make('div',undefined,'change-review-insights');notes.setAttribute('aria-live','polite');
  const labels=make('div',undefined,'change-review-labels'),originalLabel=make('span','Original'),modifiedLabel=make('span','Saved source');labels.append(originalLabel,modifiedLabel);
  const body=make('div',undefined,'change-review-diff'),loading=make('div',undefined,'change-review-loading');loading.hidden=true;loading.setAttribute('role','status');
  loading.append(make('span',undefined,'loading-spinner'),make('strong','Loading comparison…'),make('small','Reading the original baseline and current revision.'));
  const content=make('div',undefined,'change-review-content');content.append(body,loading);
  detail.append(header,controls,notes,labels,content);layout.append(left,detail);
  const footer=make('footer','Read-only review · Saving and compiling use the existing editor controls.','change-review-footer');dialog.append(heading,layout,footer);document.body.append(dialog);

  let candidates=[],buffers=new Map(),selected=null,data=null,diff=null,models=[],request=0,listRequest=0,audioPlayers=null;
  let sideBySide=!matchMedia('(max-width:900px)').matches,wordWrap=false,hideUnchanged=true,reviewText=null;
  const baselineControls=[previous,next,view,wrap,collapse];
  function dispose(){audioPlayers?.querySelectorAll('audio').forEach(player=>{player.pause();player.removeAttribute('src');player.load();});audioPlayers?.remove();audioPlayers=null;diff?.dispose();diff=null;for(const model of models)model.dispose();models=[];}
  function pending(value){loading.hidden=!value;detail.setAttribute('aria-busy',String(value));for(const b of [...baselineControls,edit,exportButton])b.disabled=value;}
  function snapshot(){buffers=new Map((window.ReplayStudio?.reviewDocuments()||[]).map(doc=>[doc.key,doc]));}
  function dirty(doc){return !!doc&&(doc.saved!==doc.buffer||doc.conflict);}
  function bufferFor(row){return buffers.get(row.key)||[...buffers.values()].find(doc=>doc.kind==='file'&&row.path&&doc.id===row.path);}
  function isWorking(row){return dirty(bufferFor(row));}
  async function open(){if(!dialog.open)dialog.showModal();nav.setAttribute('aria-expanded','true');await load();search.focus();}
  async function load(){
    const token=++listRequest;++request;snapshot();dispose();data=null;reviewText=null;body.replaceChildren();notes.replaceChildren();pending(true);refresh.disabled=true;
    count.textContent='Loading source inputs…';list.setAttribute('aria-busy','true');
    try{
      const responses=await Promise.allSettled([api('/api/changes'),api('/api/asset-changes')]);if(token!==listRequest||!dialog.open)return;
      const warnings=[],rows=new Map();let result={note:''};
      for(const response of responses){if(response.status==='fulfilled'){result=response.value;for(const row of result.items)rows.set(row.key,row);warnings.push(...(result.warnings||[]));}else warnings.push(response.reason.message);}
      for(const doc of buffers.values()){
        if(!dirty(doc)&&doc.kind!=='source')continue;
        if(doc.kind==='file'&&[...rows.values()].some(row=>row.path===doc.id))continue;
        if(!rows.has(doc.key))rows.set(doc.key,{key:doc.key,kind:doc.kind,id:doc.id,variant:doc.variant,name:doc.name,path:doc.path,category:doc.kind==='asset'?'Working asset buffers':'Open sources'});
      }
      candidates=[...rows.values()];footer.textContent=warnings.length?'Some inputs could not be listed: '+warnings.join(' · '):'Code overrides, authored files, and all staged asset operations across fastfiles. Recovered code follows the current reference database. Review is read-only.';renderList();
      const shown=visible(),retained=shown.find(row=>row.key===selected?.key);
      const current=shown.find(row=>row.kind==='source'&&row.id===state.source?.id||row.kind==='file'&&row.id===state.file?.path);
      const first=retained||shown.find(isWorking)||current||shown.find(row=>row.category==='Function overrides')||shown[0];
      if(first)await select(first);else clearComparison();
    }catch(error){if(token!==listRequest||!dialog.open)return;count.textContent='Source list unavailable';pending(false);for(const b of [...baselineControls,edit,exportButton])b.disabled=true;body.replaceChildren(make('p',error.message,'change-review-empty'),action('Retry','Retry loading review inputs',load));}
    finally{if(token===listRequest){refresh.disabled=false;list.removeAttribute('aria-busy');}}
  }
  function visible(){const query=search.value.toLocaleLowerCase(),type=filter.value;return candidates.filter(row=>
    (!query||[row.name,row.path,row.id,row.category,row.type,row.zone,row.operation,row.status].filter(Boolean).join(' ').toLocaleLowerCase().includes(query))&&
    (type==='all'||type==='working'&&isWorking(row)||type==='assets'&&row.kind==='asset'||type==='audio'&&row.kind==='sound'||type==='added'&&row.operation==='append'||type==='removed'&&row.operation==='remove'||type==='functions'&&row.kind==='source'&&row.variant!=='global-initializer'||type==='globals'&&row.variant==='global-initializer'||type==='files'&&row.kind==='file'));
  }
  function renderList(){
    const rows=visible();count.textContent=`${rows.length} of ${candidates.length} inputs · ${candidates.filter(isWorking).length} unsaved`;list.replaceChildren();
    for(const row of rows){const b=action('',`Review ${row.name}`,()=>select(row));b.className='change-review-entry';b.classList.toggle('selected',selected?.key===row.key);b.setAttribute('aria-current',selected?.key===row.key?'true':'false');
      b.append(make('strong',row.name),make('small',[row.category,row.type,row.operation,row.status,isWorking(row)?'Unsaved':null].filter(Boolean).join(' · ')),make('small',row.path||row.id,'change-review-path'));list.append(b);}
    if(!rows.length)list.append(make('p','No inputs match these filters.','change-review-empty'));
  }
  function clearComparison(){
    ++request;selected=null;data=null;reviewText=null;dispose();notes.replaceChildren();badges.replaceChildren();
    name.textContent='No matching changes';path.textContent='';originalLabel.textContent='Original';modifiedLabel.textContent='Modified';
    pending(false);for(const b of [...baselineControls,edit,exportButton])b.disabled=true;
    body.className='change-review-diff';body.replaceChildren(make('p','Saved changes and unsaved working buffers will appear here when they match the selected filter.','change-review-empty'));
  }
  async function select(row){
    const token=++request;selected=row;data=null;reviewText=null;dispose();body.replaceChildren();notes.replaceChildren();badges.replaceChildren();name.textContent=row.name;path.textContent=row.path||row.id;pending(true);renderList();
    try{
      const doc=bufferFor(row);
      const value=await api(`/api/change?kind=${encodeURIComponent(row.kind)}&id=${encodeURIComponent(row.id)}&variant=${encodeURIComponent(row.variant||'cpp')}`);
      if(token!==request||!dialog.open)return;
      value.saved=value.modified;value.unsaved=dirty(doc);
      if(value.unsaved)value.modified=doc.buffer;
      value.conflict=!!doc?.conflict;data=value;reviewText={original:value.original,modified:value.modified};
      name.textContent=value.name||row.name;path.textContent=value.path||row.path||row.id;
      originalLabel.textContent=value.original===null?'Original unavailable':value.operation==='append'?'Absent from original':row.kind==='asset'||row.kind==='sound'?'Original asset':value.baseline?.startsWith('Earliest')?'Archived baseline':'Original source';
      modifiedLabel.textContent=value.unsaved?'Working buffer · Unsaved':value.operation==='remove'?'Removed asset':row.kind==='source'&&row.variant!=='global-initializer'?'Saved translation unit':row.kind==='asset'||row.kind==='sound'?'Saved asset':'Saved source';
      badges.append(make('span',value.unsaved?'Unsaved buffer':'Saved input'),make('span',value.compilable===true?'Compiler input':value.compilable===false?'Compile support limited':'Authored content'));
      if(value.conflict)badges.append(make('span','Saved revision changed; buffer retained','change-review-warning'));
      if(value.operation)badges.append(make('span',{append:'Asset added',remove:'Asset removed',replace:'Asset modified'}[value.operation]||value.operation));
      if(value.status==='stale'||value.status==='invalid')badges.append(make('span',value.status==='stale'?'Stale draft':'Invalid draft','change-review-warning'));
      renderInsights(value.unsaved?null:value.insights);
      await renderDiff(value,token);
      if(token!==request||!dialog.open)return;
      pending(false);edit.disabled=row.kind==='sound'||value.operation==='remove'||value.status==='invalid';exportButton.disabled=false;
      for(const b of baselineControls)b.disabled=!diff;
      applyOptions();
    }catch(error){if(token!==request||!dialog.open)return;pending(false);for(const b of [...baselineControls,edit,exportButton])b.disabled=true;body.replaceChildren(make('p',error.message,'change-review-empty'),action('Retry','Retry the selected comparison',()=>select(row)));}
  }
  function renderInsights(stats){
    notes.replaceChildren();if(!data)return;
    const basis=make('p',data.baseline,'change-review-basis');notes.append(basis);
    if(data.error)notes.append(make('p',data.error,'change-review-warning'));
    if(data.original_payload||data.modified_payload){
      const payload=make('p',undefined,'change-review-mentions'),format=entry=>entry?.bytes===undefined||entry?.bytes===null?'unknown':Number(entry.bytes).toLocaleString();
      payload.textContent=`Native payload: ${format(data.original_payload)} → ${format(data.modified_payload)} bytes`;
      if(data.original_payload?.sha256&&data.modified_payload?.sha256)payload.textContent+=data.original_payload.sha256===data.modified_payload.sha256?' · Same payload hash':' · Payload hash changed';
      if(data.unsaved)payload.textContent+=' · Describes the saved payload; buffer has not been encoded';notes.append(payload);
    }
    if(stats){const totals=make('div',undefined,'change-review-totals');
      if(stats.binary)totals.append(make('span',stats.changed?'Binary/image content differs':'No source-content changes'));
      else if(stats.limited)totals.append(make('span',stats.reason));
      else totals.append(make('strong',`+${stats.added||0} lines`,'change-review-added'),make('strong',`−${stats.removed||0} lines`,'change-review-removed'),make('span',`${stats.hunks||0} changed sections`),make('span',stats.changed?'Text differs':'No textual changes'));
      notes.append(totals);
      if(stats.field_changes?.length){const fields=make('details',undefined,'change-review-metadata');fields.append(make('summary',`${stats.field_changes.length} changed fields${stats.field_changes.length>=200?' (first 200)':''}`));for(const field of stats.field_changes)fields.append(make('p',`${field.path}: ${JSON.stringify(field.before)} → ${JSON.stringify(field.after)}`,'change-review-mentions'));notes.append(fields);}
      if(stats.call_mentions_added?.length||stats.call_mentions_removed?.length){
        const mentions=make('details',undefined,'change-review-metadata');mentions.append(make('summary','Changed identifiers'));
        for(const [key,label] of [['call_mentions_added','Added'],['call_mentions_removed','Removed']])if(stats[key]?.length)mentions.append(make('p',`${label}: ${stats[key].join(', ')}.`,'change-review-mentions'));
        mentions.append(make('p','Identifiers are matched from declarations and call-like text; this is not a verified call graph.','muted'));notes.append(mentions);
      }
    }else if(data.unsaved)notes.append(make('p','Review includes unsaved work. Line counts update when the editor finishes computing the diff.','muted'));
    const metadata=make('details',undefined,'change-review-metadata');metadata.append(make('summary','Identity & provenance'));
    const lines=[`Identity: ${selected.id}`,`Saved revision: ${data.revision||'Unavailable'}`,`Baseline revision: ${data.baseline_revision||'Unavailable'}`,`Baseline SHA256: ${data.original_sha256||'Unavailable'}`];
    if(data.unsaved)lines.push('The modified side is the in-memory buffer; its content differs from the saved revision.');
    else lines.push(`Saved SHA256: ${data.modified_sha256||'Unavailable'}`);
    if(data.original_payload)lines.push('Original payload: '+JSON.stringify(data.original_payload,null,2));
    if(data.modified_payload)lines.push('Saved payload: '+JSON.stringify(data.modified_payload,null,2));
    if(data.compiler_receipt)lines.push('Asset compiler receipt: '+JSON.stringify(data.compiler_receipt,null,2));
    if(data.package_status)lines.push(data.package_status);
    if(selected.kind==='source'&&selected.variant!=='global-initializer')lines.push('Comparison scope: one recovered function against its complete authored translation unit, which may include headers, helpers, and other functions.');
    lines.push('Compilation and runtime behavior have not been validated by this review.');
    if(data.provenance&&Object.keys(data.provenance).length)lines.push(JSON.stringify(data.provenance,null,2));
    metadata.append(make('pre',lines.join('\n')));notes.append(metadata);
  }
  async function renderDiff(value,token){
    if(value.language==='image/png-base64'){
      body.className='change-review-diff change-review-images';
      for(const [index,content] of [value.original,value.modified].entries()){
        const panel=make('div',undefined,'change-review-image');body.append(panel);
        if(!content){panel.append(make('p',value.original===null&&index===0?'Original preview unavailable':index===0?'New image; no original':'Image removed','change-review-empty'));continue;}
        const img=make('img'),dimensions=make('p','','muted');img.alt=index===0?'Original image':'Modified image';panel.append(img,dimensions);
        await new Promise(resolve=>{img.onload=()=>{dimensions.textContent=`${img.naturalWidth} × ${img.naturalHeight} pixels`;resolve();};img.onerror=()=>{dimensions.textContent='Image preview could not be decoded';resolve();};img.src=imagePngData(content);});
        if(token!==request||!dialog.open)return;
      }return;
    }
    body.className='change-review-diff';
    if(value.original===null){body.classList.add('change-review-fallback');body.append(make('p','A verified original is unavailable. The saved source is shown without inventing a baseline.','muted'),make('pre',value.modified));return;}
    if(value.modified.length+value.original.length>2_000_000||value.language?.startsWith('image/')){body.append(make('p','This input is too large or binary for the interactive text diff. Export the review to inspect the content.','change-review-empty'));return;}
    if(value.original_audio&&value.modified_audio){
      const players=make('div',undefined,'change-review-audio');
      for(const [label,url] of [['Original',value.original_audio],['Modified',value.modified_audio]]){const panel=make('div'),player=make('audio');player.controls=true;player.preload='none';player.src=url;panel.append(make('small',label),player);players.append(panel);}body.before(players);audioPlayers=players;
    }
    // Monaco loads asynchronously on first visit. Keep this scoped loading mask until it is ready.
    const deadline=Date.now()+8000;while(!window.monaco&&Date.now()<deadline){await new Promise(resolve=>setTimeout(resolve,80));if(token!==request||!dialog.open)return;}
    if(!window.monaco){body.classList.add('change-review-fallback');body.append(make('pre',value.original),make('pre',value.modified));return;}
    const language=value.language==='ida-pseudocode'?'cpp':value.language?.includes('asm')||value.language==='assembly'?'replay-asm':value.language||'plaintext';
    models=[monaco.editor.createModel(value.original,language),monaco.editor.createModel(value.modified,language)];
    diff=monaco.editor.createDiffEditor(body,{theme:'replay-black',readOnly:true,originalEditable:false,automaticLayout:true,renderSideBySide:sideBySide,fontFamily:'Cascadia Code, Consolas, monospace',fontSize:13,minimap:{enabled:false},scrollBeyondLastLine:false,renderOverviewRuler:true,accessibilityVerbose:true});
    diff.onDidUpdateDiff(()=>{if(token!==request||!dialog.open||!data?.unsaved)return;const changes=diff.getLineChanges();if(changes===null)return;let added=0,removed=0;for(const change of changes){added+=change.modifiedEndLineNumber?change.modifiedEndLineNumber-change.modifiedStartLineNumber+1:0;removed+=change.originalEndLineNumber?change.originalEndLineNumber-change.originalStartLineNumber+1:0;}renderInsights({added,removed,hunks:changes.length,changed:value.original!==value.modified});});
    diff.setModel({original:models[0],modified:models[1]});
  }
  function applyOptions(){
    view.textContent=sideBySide?'Inline':'Side by side';view.setAttribute('aria-pressed',String(!sideBySide));wrap.setAttribute('aria-pressed',String(wordWrap));collapse.setAttribute('aria-pressed',String(hideUnchanged));collapse.textContent=hideUnchanged?'Show all code':'Hide unchanged';
    diff?.updateOptions({renderSideBySide:sideBySide,wordWrap:wordWrap?'on':'off',hideUnchangedRegions:{enabled:hideUnchanged,contextLineCount:4,minimumLineCount:8,revealLineCount:12}});
  }
  async function openEditor(){
    if(!selected||loading.hidden===false)return;
    const row=selected;dialog.close();if(!await page('sources'))return;
    if(row.kind==='source')await openSource(row.id,row.variant||'cpp');else if(row.kind==='file')await openFile(row.id);else if(row.kind==='asset')await openAsset(row.id);
  }
  function exportReview(){
    if(!data||!reviewText)return;
    const text=[`Replay source review: ${data.name}`,`Identity: ${selected.id}`,`Baseline: ${data.baseline}`,`Saved revision: ${data.revision||'Unavailable'}`,`Working buffer: ${data.unsaved?'Unsaved':'Saved'}`,'','===== ORIGINAL / BASELINE =====',reviewText.original??'[No verified baseline]','','===== MODIFIED SOURCE =====',reviewText.modified].join('\n');
    const url=URL.createObjectURL(new Blob([text],{type:'text/plain;charset=utf-8'})),link=make('a');link.href=url;link.download=(data.name||'source').replace(/[^\w.-]/g,'_')+'.review.txt';document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  }
  search.oninput=renderList;
  filter.onchange=guard(async()=>{const rows=visible();renderList();if(rows.some(row=>row.key===selected?.key))return;if(rows.length)await select(rows[0]);else clearComparison();});
  dialog.addEventListener('close',()=>{++request;++listRequest;dispose();nav.setAttribute('aria-expanded','false');nav.focus();});
  window.ReplayStudio?.registerCommand('Review code and asset changes against original','',open);
})();
