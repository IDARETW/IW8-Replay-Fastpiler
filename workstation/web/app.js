'use strict';
const $ = id => document.getElementById(id);
const state = {page:'overview', csrf:'', assetCodecs:{}, backendRestart:false, source:null, file:null, asset:null, zone:null, zoneId:null, job:null, sourceOffset:0, zoneOffset:0, assetOffset:0, sourceTotal:0, zoneTotal:0, files:[], logOffset:0, loadingLog:false, buildStarting:false, buildActive:false};
const editors={};
let sourceListRequest=0, zoneListRequest=0, assetListRequest=0, fileRequest=0, pageRequest=0, jobRequest=0;
const workspaceTree={node:null,query:'',offset:0,total:0,limit:100,request:0,page:null,active:null,zone:null,loadingRequests:0};
let workspaceCatalogPollInFlight=false,workspaceCatalogPollAttempts=0,workspaceCatalogPollAfter=0;
let workspaceContentLoadRequest=0;
let imageRenderSequence=0,imageRenderToken=null,imageRenderBusy=false;
let workspaceGlobalSearchActive=false,workspaceGlobalSearchRequest=0,workspaceGlobalSearchOffset=0;
let jobsSignature='';
let toastTimer;
function attachWorkspaceEditors(){
  const host=document.querySelector('#sources .workspace-editor-host');
  const filePane=document.querySelector('#files .editor-pane');
  const assetPane=document.querySelector('#assets .editor-pane');
  if(!host||!filePane||!assetPane)return;
  filePane.classList.add('workspace-file-pane');assetPane.classList.add('workspace-asset-pane');
  host.append(filePane,assetPane);filePane.hidden=true;assetPane.hidden=true;
  for(const button of document.querySelectorAll('nav button[data-page="files"],nav button[data-page="assets"]'))button.hidden=true;
}
attachWorkspaceEditors();
function toast(message) { $('toast').textContent=message; $('toast').hidden=false; clearTimeout(toastTimer); toastTimer=setTimeout(()=>$('toast').hidden=true,6500); }
async function api(path, body) {
  if(body!==undefined&&state.backendRestart)throw new Error('The backend changed. Restart the server and reload this tab before saving or compiling. Your unsaved editor text is still here.');
  const options=body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json','X-Replay-Token':state.csrf},body:JSON.stringify(body)};
  const response=await fetch(path,options), value=await response.json();
  if(value.restart_required){state.backendRestart=true;$('connection').textContent='Backend restart required';}
  if(!response.ok){const error=new Error(value.error||`HTTP ${response.status}`);if(typeof value.code==='string')error.code=value.code;throw error;}
  return value;
}
function guard(fn) { return async (...args)=>{try{return await fn(...args);}catch(e){toast(e.message); console.error(e);}}; }
function element(tag,text,cls) {const e=document.createElement(tag); if(text!==undefined)e.textContent=text; if(cls)e.className=cls;return e;}
function dirty(kind) {return state[kind] && ($(`${kind}-content`).value!==(state[kind].content??'')||(kind==='asset'&&$('sound-import')?.files.length>0));}
function setEditor(kind, content, language='cpp', readonly=false){const text=$(`${kind}-content`);text.value=content;text.readOnly=readonly;if(editors[kind]){if(editors[kind].getValue()!==content)editors[kind].setValue(content);editors[kind].updateOptions({readOnly:readonly});monaco.editor.setModelLanguage(editors[kind].getModel(),language==='assembly'||language.includes('asm')?'replay-asm':language==='ida-pseudocode'?'cpp':language);editors[kind].layout();}}
function initializeEditors(){
  if(!window.require)return;
  window.require.config({paths:{vs:'/vendor/monaco/vs'}});
  window.require(['vs/editor/editor.main'],()=>{
    monaco.editor.defineTheme('replay-black',{base:'vs-dark',inherit:true,rules:[{token:'comment',foreground:'6F667C'},{token:'keyword',foreground:'BC8DE0'},{token:'string',foreground:'B1BE8F'},{token:'number',foreground:'D69BAF'},{token:'type',foreground:'A798C4'}],colors:{'editor.background':'#0B0C10','editor.foreground':'#D8D0E2','editorLineNumber.foreground':'#514A5D','editorLineNumber.activeForeground':'#B08CC5','editor.selectionBackground':'#49335E88','editor.lineHighlightBackground':'#15101D','editorCursor.foreground':'#D8A2EB','editorIndentGuide.background1':'#231D2D','editorWidget.background':'#14101D','editorWidget.border':'#44314F'}});
    monaco.languages.register({id:'replay-asm'});
    monaco.languages.register({id:'gsc'});
    monaco.languages.setMonarchTokensProvider('gsc',{tokenizer:{root:[[/\/\/.*$/,'comment'],[/\/\*/,'comment','@comment'],[/"(?:[^"\\]|\\.)*"/,'string'],[/\b(?:if|else|for|while|switch|case|default|break|continue|return|thread|wait|waittill|endon|notify|isdefined|true|false|undefined)\b/,'keyword'],[/\b(?:level|self|game)\b/,'type'],[/\b(?:0x[\da-fA-F]+|\d+(?:\.\d+)?)\b/,'number']],comment:[[/[^*]+/,'comment'],[/\*\//,'comment','@pop'],[/\*/,'comment']]}});
    monaco.languages.setMonarchTokensProvider('replay-asm',{tokenizer:{root:[[/[#;].*$/,'comment'],[/^\s*\.[a-zA-Z_]+/,'keyword'],[/\b(?:mov\w*|add|sub|lea|call|ret|push|pop|j\w+|cmp|test|xor|and|or|nop)\b/,'keyword'],[/\b(?:[re]?[abcd]x|[re]?(?:si|di|sp|bp)|r\d+[dwb]?|[xyz]mm\d+|rip)\b/,'type'],[/\b(?:0x[\da-fA-F]+|\d+)\b/,'number'],[/\b(?:fn|sym)_[\da-f]+\b/,'string']]}});
    for(const kind of ['source','file','asset']){
      const text=$(`${kind}-content`),wrap=text.parentElement,host=element('div',undefined,'monaco-host');wrap.append(host);text.hidden=true;$(`${kind}-lines`).hidden=true;
      const editor=monaco.editor.create(host,{value:text.value,language:'cpp',theme:'replay-black',automaticLayout:true,editContext:false,fontFamily:'Cascadia Code, Consolas, monospace',fontSize:12,lineHeight:20,minimap:{enabled:false},scrollBeyondLastLine:false,wordWrap:'off',padding:{top:14},readOnly:text.readOnly,ariaLabel:kind==='source'?'Function source':kind==='asset'?'Asset source':'Authored source',renderLineHighlight:'line',bracketPairColorization:{enabled:true}});
      editors[kind]=editor;
      globalThis.ReplayStudioReferences?.editorReady(kind,editor);
      globalThis.ReplaySourceErrors?.editorReady(kind,editor);
      editor.onDidChangeModelContent(()=>{text.value=editor.getValue();editorChanged(kind);});
      editor.onDidChangeCursorPosition(e=>$(`${kind}-location`).textContent=`Ln ${e.position.lineNumber}, Col ${e.position.column}`);
      if(state[kind])setEditor(kind,state[kind].content,state[kind].language,!state[kind].editable);
    }
  },error=>console.warn('Monaco editor unavailable; text editor remains usable.',error));
}
function canLeave() {return window.ReplayStudio?.preserveWorkingBuffers()||!dirty('source')&&!dirty('file')&&!dirty('asset')||window.confirm('There are unsaved changes. Discard them?');}
async function page(name) {
  if(name==='files'||name==='assets')name='sources';
  if(state.page!==name&&!canLeave())return false;
  const request=++pageRequest;
  if(state.page!==name){globalThis.ReplayStudio?.cleared();resetSoundEditor();++sourceRequest;++fileRequest;++assetRequest;++workspaceTree.request;}
  if(state.page!==name){state.source=null;state.file=null;state.asset=null;$('source-editor').hidden=true;$('source-empty').hidden=false;$('file-editor').hidden=true;$('file-empty').hidden=false;$('asset-editor').hidden=true;}
  if(state.page==='sources'&&name!=='sources'){cancelWorkspaceContentLoad();workspaceTree.active=null;workspaceTree.zone=null;state.zone=null;state.zoneId=null;activateWorkspaceEditor('empty');}
  state.page=name;
  for(const p of document.querySelectorAll('.page'))p.classList.toggle('active',p.id===name);
  for(const b of document.querySelectorAll('nav button')){b.classList.toggle('active',b.dataset.page===name);if(b.dataset.page===name)b.setAttribute('aria-current','page');else b.removeAttribute('aria-current');}
  $('page-title').textContent={overview:'Overview',sources:'Game source',files:'Authored files',assets:'Fastfile assets',builds:'Builds & output',settings:'Project details'}[name];
  $('page-crumb').textContent=$('page-title').textContent;
  document.title=`${$('page-title').textContent} · Replay Workstation`;
  if(name==='sources'){activateWorkspaceEditor(workspaceTree.active?.startsWith('file:')?'file':workspaceTree.active?.startsWith('asset:')?'asset':workspaceTree.active?.startsWith('zone:')?'zone':workspaceTree.active?.startsWith('source:')||workspaceTree.active?.startsWith('global:')?'source':'empty');await loadWorkspaceTree(workspaceTree.node,0);}
  if(name==='builds')await loadJobs();
  if(request===pageRequest){history.replaceState(null,'',`#${name}`);window.scrollTo(0,0);}
  return request===pageRequest;
}
function entry(name,detail,selected,onClick) {const b=element('button',undefined,selected?'selected':'');b.title=name;b.append(element('strong',name),element('small',detail));b.onclick=guard(onClick);return b;}
function workspaceItemDetail(item){
  let detail='';
  if(item.kind==='zone'){
    const label={building:'catalog updating',ready:'cached metadata',stale:'cached metadata · refreshing',unavailable:'catalog unavailable'}[item.inventory_state];
    const fallback=item.inventory_cached?'metadata cache candidate':null;
    detail=`${item.source_status||'Fastfile'} · ${Number(item.bytes||0).toLocaleString()} bytes${label||fallback?` · ${label||fallback}`:''}`;
  }
  if(item.kind==='asset')detail=`${item.type||`Type ${item.type_id}`} · ${item.operation==='remove'?'removal queued':item.operation==='append'?'creation queued':item.reference_only?'reference only':item.editable?'editable':'native metadata'}`;
  if(item.kind==='source'||item.kind==='global')detail=`${item.source_kind==='global'||item.kind==='global'?'Global initializer':item.type||item.source_kind||item.kind}${item.has_cpp?' · C++':''}`;
  if(item.kind==='file')detail=item.path||item.target?.path||item.detail||'Authored file';
  if(!detail)detail=item.detail||item.summary||(item.kind==='folder'?'Folder':'');
  if(item.match)detail=`Line ${item.match.line} · ${detail}`;
  return item.area?`${item.area}${detail?` · ${detail}`:''}`:detail;
}
function renderWorkspaceCatalogStatus(page){
  const status=$('workspace-catalog-status'),catalog=page.catalog_status;
  if(!catalog||catalog.validation_scope!=='display-only-metadata'){
    status.hidden=true;status.textContent='';status.removeAttribute('title');return;
  }
  const labels={building:'Indexing workspace…',ready:'Workspace index ready',
    stale:'Updating workspace index…',unavailable:'Workspace index unavailable'};
  const indexedFastfiles=catalog.indexed_fastfiles,totalFastfiles=catalog.total_fastfiles;
  const progress=Number.isSafeInteger(indexedFastfiles)&&Number.isSafeInteger(totalFastfiles)?
    ` · ${indexedFastfiles.toLocaleString()} of ${totalFastfiles.toLocaleString()} fastfiles indexed`:'';
  const label=`${labels[catalog.state]||'Workspace index ready'}${['building','stale'].includes(catalog.state)?progress:''}`;
  const indexed=Date.parse(catalog.indexed_at||''),when=Number.isFinite(indexed)?new Date(indexed).toLocaleString():'';
  status.textContent=label;
  const countLabels={functions:'Functions',symbols:'Symbols',globals:'Editable globals',authored:'Source files',
    fastfiles:'Fastfiles',decoded_zones:'Indexed zones',native_asset_rows:'Native assets'};
  const counts=Object.entries(countLabels).filter(([family])=>Number.isSafeInteger(catalog.family_counts?.[family])&&catalog.family_counts[family]>=0)
    .map(([family,label])=>`${label}: ${catalog.family_counts[family].toLocaleString()}`);
  status.title=['Rows speed up navigation. Selected items are checked before editing.',when?`Indexed ${when}`:'',...counts].filter(Boolean).join('\n');
  status.dataset.catalogState=catalog.state||'unknown';status.hidden=false;
}
function renderWorkspaceTree(page){
  renderWorkspaceCatalogStatus(page);
  const nav=$('workspace-breadcrumbs');nav.replaceChildren();
  for(const [index,crumb] of page.breadcrumbs.entries()){
    if(index)nav.append(element('span','›','tree-crumb-separator'));
    const button=element('button',crumb.label,'tree-crumb');button.disabled=index===page.breadcrumbs.length-1;
    button.onclick=guard(()=>navigateWorkspaceBreadcrumb(crumb));nav.append(button);
  }
  $('workspace-tree-status').hidden=page.items.length>0;
  const catalogState=page.catalog_status?.state;
  $('workspace-tree-status').textContent=page.items.length?'':
    ['building','stale'].includes(catalogState)&&page.total===0?(catalogState==='building'?'Indexing workspace…':'Updating workspace index…'):
    (page.total?'No items on this page.':'This folder is empty.');
  const list=$('source-list');list.replaceChildren(...page.items.map(item=>{
    const button=element('button',undefined,workspaceTree.active===`${item.kind}:${item.id}`?'selected':'');
    button.type='button';button.setAttribute('role','listitem');button.dataset.kind=item.kind;button.dataset.itemId=item.id;
    const icon=element('span',item.source_kind==='global'?'◇':({folder:'▸',zone:'›',source:'ƒ',global:'◇',file:'▤',asset:'◈'})[item.kind]||'·','tree-item-icon');
    const copy=element('span',undefined,'tree-item-copy');copy.append(element('strong',item.name),element('small',workspaceItemDetail(item)));
    if(item.match){const snippet=element('code',item.match.snippet,'code-search-snippet');copy.append(snippet);}
    button.append(icon,copy);
    button.title=item.kind==='zone'?`Expand fastfile ${item.name}${workspaceItemDetail(item)?` — ${workspaceItemDetail(item)}`:''}`:`${item.name}${workspaceItemDetail(item)?` — ${workspaceItemDetail(item)}`:''}`;
    if(item.kind==='zone')button.setAttribute('aria-label',`Expand fastfile ${item.name}`);
    button.onclick=guard(()=>selectWorkspaceItem(item));return button;
  }));
  $('source-range').textContent=ReplayWorkspaceTree.range(page);
  $('source-prev').disabled=page.offset===0;$('source-next').disabled=page.offset+page.items.length>=page.total;
  $('source-prev').setAttribute('aria-label','Previous folder page');$('source-next').setAttribute('aria-label','Next folder page');
  $('page-crumb').textContent=page.label;
}
async function navigateWorkspaceBreadcrumb(crumb){
  const leavesZone=['IW8','Code','Assets'].includes(crumb.label);
  const changesZone=leavesZone&&!!workspaceTree.zone;
  if(changesZone&&!canLeave())return;
  if(changesZone){clearWorkspaceSelection();workspaceTree.zone=null;state.zone=null;state.zoneId=null;workspaceTree.active=null;activateWorkspaceEditor('empty');}
  else if(crumb.kind==='zone'&&crumb.relative_path){
    const current=workspaceTree.zone;
    if(!current||current.relative_path!==crumb.relative_path){if(!canLeave())return;clearWorkspaceSelection();workspaceTree.active=null;activateWorkspaceEditor('empty');}
    workspaceTree.zone={...(current?.relative_path===crumb.relative_path?current:{}),...crumb};state.zone=workspaceTree.zone;state.zoneId=workspaceTree.zone.zone_id||null;
  }else if(crumb.relative_path&&crumb.zone_id){workspaceTree.zone={...(workspaceTree.zone||{}),...crumb};state.zone=workspaceTree.zone;state.zoneId=crumb.zone_id;}
  return navigateWorkspaceFolder(crumb.id);
}
let workspaceTreeLoadRequest=0;
function beginWorkspaceTreeLoad(message,retry){
  const overlay=$('workspace-tree-load'),content=$('workspace-tree-content');
  const request=++workspaceTreeLoadRequest;
  overlay.hidden=false;overlay.dataset.request=String(request);overlay.dataset.failed='false';
  $('workspace-tree-load-title').textContent=message||'Loading workspace items…';
  $('workspace-tree-load-detail').textContent='Wait for the requested items to load.';
  const button=$('workspace-tree-load-retry');button.hidden=true;button.onclick=null;overlay.__retry=retry;
  content.setAttribute('aria-busy','true');$('source-list').inert=true;
  $('source-prev').inert=true;$('source-next').inert=true;
  if(document.activeElement!==$('source-search'))overlay.focus?.();return request;
}
function finishWorkspaceTreeLoad(request){
  const overlay=$('workspace-tree-load'),content=$('workspace-tree-content');
  if(!request||request!==workspaceTreeLoadRequest||overlay.dataset.request!==String(request))return;
  overlay.hidden=true;overlay.__retry=null;overlay.removeAttribute('data-failed');content.removeAttribute('aria-busy');
  $('source-list').inert=false;$('source-prev').inert=false;$('source-next').inert=false;
}
function failWorkspaceTreeLoad(request,message){
  const overlay=$('workspace-tree-load');
  if(!request||request!==workspaceTreeLoadRequest||overlay.dataset.request!==String(request))return;
  overlay.dataset.failed='true';$('workspace-tree-load-title').textContent='Workspace items could not be loaded';
  $('workspace-tree-load-detail').textContent=message||'Retry to request these items again.';
  const button=$('workspace-tree-load-retry');button.hidden=false;button.onclick=guard(()=>overlay.__retry?.());
  if(document.activeElement!==$('source-search'))button.focus?.();
}
function cancelWorkspaceTreeLoad(){
  workspaceTreeLoadRequest++;const overlay=$('workspace-tree-load');
  if(overlay)overlay.hidden=true;
  $('workspace-tree-content').removeAttribute('aria-busy');$('source-list').inert=false;
  $('source-prev').inert=false;$('source-next').inert=false;
}
async function navigateWorkspaceFolder(node){
  if(workspaceGlobalSearchActive){workspaceGlobalSearchActive=false;++workspaceGlobalSearchRequest;
    $('source-search').value='';$('workspace-search-scope').hidden=true;workspaceGlobalSearchOffset=0;}
  else if(node!==workspaceTree.node)$('source-search').value='';
  return loadWorkspaceTree(node,0);
}
async function loadWorkspaceTree(node=workspaceTree.node,offset=0){
  const globalQuery=$('source-search').value.trim();
  if(workspaceGlobalSearchActive&&globalQuery)return loadWorkspaceGlobalSearch(globalQuery,offset);
  const request=++workspaceTree.request,query=$('source-search').value.trim();
  workspaceTree.query=query;workspaceTree.offset=offset;
  cancelWorkspaceTreeLoad();
  const load=beginWorkspaceTreeLoad('Loading folder contents…',()=>loadWorkspaceTree(node,offset));
  workspaceTree.loadingRequests++;
  let data;
  try{
    data=ReplayWorkspaceTree.validatePage(await api(ReplayWorkspaceTree.url(node,query,offset,workspaceTree.limit)));
  }catch(error){if(request===workspaceTree.request)failWorkspaceTreeLoad(load,error.message);throw error;}
  finally{workspaceTree.loadingRequests=Math.max(0,workspaceTree.loadingRequests-1);}
  if(request!==workspaceTree.request)return;
  workspaceTree.node=node||null;workspaceTree.offset=data.offset;workspaceTree.total=data.total;workspaceTree.page=data;
  $('workspace-search-scope').hidden=true;renderWorkspaceTree(data);finishWorkspaceTreeLoad(load);return data;
}
function workspaceSearchInventoryDetail(status){
  const details=[];
  if(Number.isSafeInteger(status?.asset_rows))details.push(`${status.asset_rows.toLocaleString()} cached asset rows`);
  if(Number.isSafeInteger(status?.native_asset_rows))details.push(`${status.native_asset_rows.toLocaleString()} verified native rows`);
  if(Number.isSafeInteger(status?.table_only_fastfiles)&&status.table_only_fastfiles>0)
    details.push(`${status.table_only_fastfiles.toLocaleString()} fastfiles lack native asset names`);
  return details.join(' · ');
}
function workspaceSearchProgress(status,total){
  const details=workspaceSearchInventoryDetail(status),detailText=details?` ${details}.`:'';
  const tableOnly=Number.isSafeInteger(status?.table_only_fastfiles)?status.table_only_fastfiles:0;
  const nameLimit=tableOnly?` Name coverage is partial for those fastfiles; cached rows remain visible where they have searchable names.`:'';
  if(status?.state==='unavailable'||status?.state==='error')
    return `${status.error||'Some workspace search data is unavailable.'}${detailText}${nameLimit}`;
  const indexed=status?.indexed_fastfiles,files=status?.total_fastfiles,unavailable=status?.unavailable_fastfiles;
  const coverage=Number.isSafeInteger(indexed)&&Number.isSafeInteger(files)?`${indexed.toLocaleString()} of ${files.toLocaleString()} fastfiles indexed${Number.isSafeInteger(unavailable)&&unavailable?`; ${unavailable.toLocaleString()} unavailable`:''}`:'';
  if(status?.complete===true&&status.validation_scope==='display-only-metadata')
    return `${total.toLocaleString()} results · workspace index scan complete.${detailText}${nameLimit} Selected items are checked before editing.`;
  return `Showing available indexed matches${coverage?` · ${coverage}`:''}.${detailText}${nameLimit} More matches may appear while indexing continues.`;
}
function renderWorkspaceGlobalSearch(data,query){
  const rows=data.items.map(workspaceSearchResult),searchStatus=data.search_status;
  const page={...data,items:rows,node:workspaceTree.node||null,label:'All IW8 results',
    breadcrumbs:workspaceTree.page?.breadcrumbs||[],catalog_status:data.catalog_status||workspaceTree.page?.catalog_status};
  renderWorkspaceTree(page);
  const scope=$('workspace-search-scope');scope.hidden=false;scope.dataset.state=searchStatus.state||'partial';
  scope.textContent=data.search_mode==='code'?`All Code · ${searchStatus.indexed.toLocaleString()} documents indexed · ${searchStatus.state} · ${data.elapsed_ms} ms · ${data.has_more?'more matches available':'end of results'}`:
    `All IW8 · outside the focused folder · ${workspaceSearchProgress(searchStatus,data.total)}`;
  if(searchStatus.error||['unavailable','error'].includes(searchStatus.state)){
    const retry=element('button','Retry');retry.type='button';retry.onclick=guard(()=>loadWorkspaceGlobalSearch(query,data.offset));scope.append(retry);
  }
  if(!rows.length&&!searchStatus.complete){
    $('workspace-tree-status').textContent=`No indexed matches for “${query}” yet. ${scope.textContent}`;
    $('workspace-tree-status').hidden=false;
  }else if(!rows.length){$('workspace-tree-status').textContent=`No IW8 matches for “${query}”.`;$('workspace-tree-status').hidden=false;}
  $('source-range').textContent=ReplayWorkspaceTree.range(data);
  if(data.search_mode==='code'&&data.has_more)$('source-range').textContent=`${data.offset+1}–${data.offset+data.items.length} · more matches`;
  $('source-prev').disabled=data.offset===0;$('source-next').disabled=data.offset+data.items.length>=data.total;
}
async function loadWorkspaceGlobalSearch(query=$('source-search').value.trim(),offset=0){
  if(!query){workspaceGlobalSearchActive=false;$('workspace-search-scope').hidden=true;return loadWorkspaceTree(workspaceTree.node,0);}
  workspaceGlobalSearchActive=true;workspaceGlobalSearchOffset=offset;workspaceTree.query='';
  const searchMode=$('source-search-mode')?.value||'names';
  const request=++workspaceGlobalSearchRequest,treeRequest=++workspaceTree.request;
  cancelWorkspaceTreeLoad();
  const load=beginWorkspaceTreeLoad('Searching all IW8…',()=>loadWorkspaceGlobalSearch(query,offset));
  workspaceTree.loadingRequests++;
  try{
    const data=await api(`/api/workspace/search?q=${encodeURIComponent(query)}&mode=${searchMode}&offset=${offset}&limit=${workspaceTree.limit}`);
    if(request!==workspaceGlobalSearchRequest||treeRequest!==workspaceTree.request||!workspaceGlobalSearchActive||$('source-search').value.trim()!==query)return;
    if(!data||!Array.isArray(data.items)||!data.search_status||!Number.isSafeInteger(data.total)||data.total<0||
       !Number.isSafeInteger(data.offset)||!Number.isSafeInteger(data.limit)||data.limit<1||
       data.items.length>data.limit||data.offset+data.items.length>data.total||typeof data.search_status.complete!=='boolean')
      throw new Error('The workspace search response is incomplete.');
    renderWorkspaceGlobalSearch(data,query);
    if(!data.items.length&&(data.search_status.error||['unavailable','error'].includes(data.search_status.state)))
      failWorkspaceTreeLoad(load,data.search_status.error||'Workspace search is unavailable. Retry to continue.',()=>loadWorkspaceGlobalSearch(query,offset));
    else finishWorkspaceTreeLoad(load);
    workspaceGlobalSearchOffset=data.offset;return data;
  }catch(error){
    if(request!==workspaceGlobalSearchRequest||treeRequest!==workspaceTree.request)return;
    failWorkspaceTreeLoad(load,error.message);
    throw error;
  }finally{workspaceTree.loadingRequests=Math.max(0,workspaceTree.loadingRequests-1);}
}
function searchFromGameSource(){
  const query=$('source-search').value.trim();
  if($('source-search-mode')?.value==='code'&&query&&query.length<3){
    ++workspaceGlobalSearchRequest;++workspaceTree.request;cancelWorkspaceTreeLoad();
    $('source-list').replaceChildren();$('source-range').textContent='Enter 3 or more characters';
    $('source-prev').disabled=true;$('source-next').disabled=true;
    $('workspace-search-scope').hidden=false;$('workspace-search-scope').textContent='Code text search needs at least 3 characters.';return;
  }
  if(query){workspaceGlobalSearchActive=true;return loadWorkspaceGlobalSearch(query,0);}
  workspaceGlobalSearchActive=false;++workspaceGlobalSearchRequest;workspaceGlobalSearchOffset=0;
  cancelWorkspaceTreeLoad();$('workspace-search-scope').hidden=true;
  return loadWorkspaceTree(workspaceTree.node,0);
}
function loadWorkspaceResultsPage(offset){
  return workspaceGlobalSearchActive?loadWorkspaceGlobalSearch($('source-search').value.trim(),Math.max(0,offset)):
    loadWorkspaceTree(workspaceTree.node,Math.max(0,offset));
}
async function refreshWorkspaceTree(){
  const page=await loadWorkspaceTree(workspaceTree.node,workspaceTree.offset);
  syncSelectedZoneCatalog(page);
  const assetId=state.asset?.asset_id;
  const row=assetId&&page?.items.find(item=>item.kind==='asset'&&item.target?.asset_id===assetId);
  if(row){workspaceTree.active=`asset:${row.id}`;renderWorkspaceTree(page);}
  return page;
}
function syncSelectedZoneCatalog(page){
  const zone=state.zone;
  if(!page||!zone?.relative_path||state.asset||!workspaceTree.active?.startsWith('zone:')||
      page.type_id!==undefined||page.zone_id===undefined||
      page.inventory_validation_scope!=='display-only-metadata'||
      page.label!==zone.relative_path.split('/').at(-1))return;
  const updated={...zone,zone_id:page.zone_id,inventory_cached:page.inventory_cached===true,
    inventory_state:page.inventory_state};
  state.zone=updated;workspaceTree.zone=updated;state.zoneId=updated.zone_id||null;
  const detail={building:'catalog updating',ready:'cached metadata available',stale:'cached metadata · refreshing',
    unavailable:'catalog unavailable'}[updated.inventory_state];
  $('zone-name').textContent=updated.relative_path;
  $('zone-detail').textContent=`Source XFile version ${updated.source_xfile_version||'?'} · ${detail||'metadata status unavailable'}`;
  $('zone-extract').disabled=updated.inventory_state==='ready'||updated.inventory_state==='building'||
    updated.source_status!=='source-header-checked';
  $('new-asset').disabled=state.buildActive||state.buildStarting||!state.zoneId;
  $('zone-status').textContent=updated.inventory_state==='ready'?
    'Cached native metadata is available. Each selected asset is checked before editing.':
    updated.inventory_state==='building'?'Native metadata is being cataloged. Folder contents may be incomplete while the catalog updates.':
    updated.inventory_state==='stale'?'Cached native metadata is being refreshed. Selected assets still require a current source check.':
    updated.inventory_state==='unavailable'?'Workspace indexing could not read this fastfile inventory. Extract it again after checking the source file.':
    'Native metadata status is unavailable; selected assets are checked before editing.';
}
async function pollWorkspaceCatalog(now=Date.now()){
  if(state.page!=='sources'||workspaceGlobalSearchActive)return false;
  const status=workspaceTree.page?.catalog_status?.state;
  if(!['building','stale'].includes(status)){
    workspaceCatalogPollAttempts=0;workspaceCatalogPollAfter=0;return false;
  }
  if(workspaceCatalogPollInFlight||workspaceTree.loadingRequests||now<workspaceCatalogPollAfter)return false;
  workspaceCatalogPollInFlight=true;
  try{
    const page=await refreshWorkspaceTree();
    if(!['building','stale'].includes(page?.catalog_status?.state)){
      workspaceCatalogPollAttempts=0;workspaceCatalogPollAfter=0;
    }else{
      workspaceCatalogPollAttempts++;
      workspaceCatalogPollAfter=Date.now()+(workspaceCatalogPollAttempts>=5?30000:7000);
      if(workspaceCatalogPollAttempts>=5)workspaceCatalogPollAttempts=0;
    }
    return true;
  }catch(error){
    workspaceCatalogPollAttempts++;
    workspaceCatalogPollAfter=Date.now()+(workspaceCatalogPollAttempts>=5?30000:7000);
    if(workspaceCatalogPollAttempts>=5)workspaceCatalogPollAttempts=0;
    return false;
  }finally{workspaceCatalogPollInFlight=false;}
}
function activateWorkspaceEditor(kind){
  const host=document.querySelector('#sources .workspace-editor-host');
  const sourcePane=$('source-editor');
  const filePane=document.querySelector('.workspace-file-pane');
  const assetPane=document.querySelector('.workspace-asset-pane');
  sourcePane.hidden=kind!=='source';filePane.hidden=kind!=='file';assetPane.hidden=kind!=='zone'&&kind!=='asset';
  $('source-empty').hidden=kind!=='empty';
  host.dataset.activeEditor=kind;
}
function beginWorkspaceContentLoad(message,retry){
  window.ReplayStudio?.loading();
  const host=document.querySelector('#sources .workspace-editor-host'),overlay=$('workspace-content-load');
  if(!host||!overlay)return 0;
  const request=++workspaceContentLoadRequest;
  for(const child of host.children||[])if(child!==overlay&&!child.classList.contains('studio-tabs'))child.inert=true;
  const tabs=host.querySelector('.studio-tabs');overlay.style.top=tabs?`${tabs.offsetHeight}px`:'0';
  host.setAttribute('aria-busy','true');overlay.hidden=false;overlay.dataset.failed='false';
  $('workspace-content-load-title').textContent=message||'Loading selected content…';
  $('workspace-content-load-detail').textContent='The editor is unavailable until this request completes.';
  const button=$('workspace-content-load-retry');button.hidden=true;button.onclick=null;
  overlay.dataset.request=String(request);overlay.focus?.();overlay.__retry=retry;return request;
}
function failWorkspaceContentLoad(request,message){
  const overlay=$('workspace-content-load');
  if(!request||request!==workspaceContentLoadRequest||overlay.dataset.request!==String(request))return;
  overlay.dataset.failed='true';$('workspace-content-load-title').textContent='Content could not be loaded';
  $('workspace-content-load-detail').textContent=message||'The request failed. Retry to check this item again.';
  const button=$('workspace-content-load-retry');button.hidden=false;
  button.onclick=guard(()=>overlay.__retry?.());button.focus?.();
}
function finishWorkspaceContentLoad(request){
  if(!request||request!==workspaceContentLoadRequest)return;
  const host=document.querySelector('#sources .workspace-editor-host'),overlay=$('workspace-content-load');
  if(overlay.dataset.request!==String(request))return;
  overlay.hidden=true;overlay.__retry=null;overlay.removeAttribute('data-failed');
  host?.removeAttribute('aria-busy');
  for(const child of host?.children||[])child.inert=false;
  window.ReplayStudio?.opened(host?.dataset.activeEditor);
}
function cancelWorkspaceContentLoad(){
  workspaceContentLoadRequest++;
  const host=document.querySelector('#sources .workspace-editor-host'),overlay=$('workspace-content-load');
  if(overlay)overlay.hidden=true;
  host?.removeAttribute('aria-busy');
  for(const child of host?.children||[])child.inert=false;
}
function clearWorkspaceSelection(){
  invalidateWorkspaceMutationGuards();
  globalThis.ReplayStudio?.cleared();
  invalidateImageRender();
  resetSoundEditor();++sourceRequest;++fileRequest;++assetRequest;++assetListRequest;++workspaceTree.request;
  cancelWorkspaceContentLoad();
  state.source=null;state.file=null;state.asset=null;workspaceTree.active=null;
  $('source-editor').hidden=true;$('source-empty').hidden=false;$('file-editor').hidden=true;$('file-empty').hidden=false;$('asset-editor').hidden=true;
}
async function selectWorkspaceItem(item){
  const action=ReplayWorkspaceTree.action(item),same=workspaceTree.active===`${item.kind}:${item.id}`;
  if(action.type==='navigate'){
    if((!same||item.zone_id)&&!canLeave())return;
    if(!same||item.zone_id){clearWorkspaceSelection();workspaceTree.active=`${item.kind}:${item.id}`;if(['Code','Assets'].includes(item.name)){workspaceTree.zone=null;state.zone=null;state.zoneId=null;}activateWorkspaceEditor('empty');}
    if(item.zone_id){
      state.zoneId=item.zone_id;
      workspaceTree.zone={...(workspaceTree.zone||{}),relative_path:item.relative_path||workspaceTree.zone?.relative_path,
        zone_id:item.zone_id,inventory_cached:true};state.zone=workspaceTree.zone;
      openZone(workspaceTree.zone);activateWorkspaceEditor('zone');
      if(item.editor_status)$('zone-status').textContent=`${Number(item.count||0).toLocaleString()} ${item.name} rows · ${item.editor_status}. Select a row to open its verified editor.`;
    }
    await navigateWorkspaceFolder(action.node);return;
  }
  if(action.type==='zone'){
    if(!same&&!canLeave())return;
    if(!same)clearWorkspaceSelection();
    workspaceTree.active=`zone:${item.id}`;workspaceTree.zone=item;
    openZone({...item,relative_path:item.relative_path,status:item.source_status,source_xfile_version:item.source_xfile_version});
    activateWorkspaceEditor('zone');
    const children=await navigateWorkspaceFolder(action.node);
    if(children?.extract_required){
      const cachedInventory=item.inventory_cached===true||item.inventory_state==='ready';
      workspaceTree.zone={...item,inventory_cached:cachedInventory,zone_id:item.zone_id||null};state.zone=workspaceTree.zone;state.zoneId=item.zone_id||null;
      $('zone-extract').disabled=cachedInventory||(item.source_status||item.status)!=='source-header-checked';
      $('zone-status').textContent=cachedInventory?'This fastfile is marked as having cached native metadata, but its folder rows were not returned. Search results remain available and each asset is checked before editing.':(item.source_status||item.status)==='source-header-checked'?'Fastfile source header is available, but no native asset inventory is ready for folder navigation. Extract it to build the type folders; selected search results are still checked before editing.':'Native asset folders are not available in this result yet. Source identity is checked when an asset is opened.';
    }
    else if(children?.zone_id){workspaceTree.zone={...item,inventory_cached:children.inventory_cached===true,inventory_state:children.inventory_state,zone_id:children.zone_id};state.zone=workspaceTree.zone;state.zoneId=children.zone_id;$('zone-extract').disabled=children.inventory_state==='ready'||children.inventory_state==='building'||item.source_status!=='source-header-checked';$('new-asset').disabled=state.buildActive||state.buildStarting;$('zone-status').textContent=children.inventory_state==='building'?'Native metadata catalog is updating. Cached rows are display-only until each asset is checked on open.':children.inventory_state==='stale'?'Cached native metadata is refreshing. Rows remain display-only; extract again to rebuild for the current source.':'Cached native metadata is available. Each selected asset is checked before editing.';}
    return;
  }
  if(!same&&!canLeave())return;
  if(!same)clearWorkspaceSelection();
  workspaceTree.active=`${item.kind}:${item.id}`;
  if(action.type==='source'){
    activateWorkspaceEditor('source');await openSource(action.id,action.variant);
    if(item.match&&state.source?.id===action.id)revealCodeMatch('source',item.match);return;
  }
  if(action.type==='file'){
    activateWorkspaceEditor('file');await openFile(action.path);
    if(item.match&&state.file?.path===action.path)revealCodeMatch('file',item.match);return;
  }
  const zone=workspaceTree.zone||{};
  state.zoneId=item.zone_id||zone.zone_id||state.zoneId;
  if(item.relative_path){
    state.zone={...zone,relative_path:item.relative_path,zone_id:item.zone_id||zone.zone_id};workspaceTree.zone=state.zone;
    $('zone-name').textContent=item.relative_path.split('/').pop();$('zone-detail').textContent=item.relative_path;
  }
  else if(zone.relative_path)state.zone=zone;
  if(state.zone)activateWorkspaceEditor('asset');
  await openAsset(action.assetId,false,item);
}
async function openWorkspaceFile(path){
  if(!canLeave())return false;
  clearWorkspaceSelection();workspaceTree.active=null;activateWorkspaceEditor('file');
  await openFile(path);return true;
}
async function revealCreatedSource(source){
  $('source-search').value='';
  const root=await loadWorkspaceTree(null,0),code=root.items.find(item=>item.name==='Code');
  if(!code)return;
  const codePage=await loadWorkspaceTree(code.id,0),functions=codePage.items.find(item=>item.name==='Functions');
  if(!functions)return;
  const prefixMatch=source.name.match(/^([A-Za-z0-9]+_)/),prefix=prefixMatch?prefixMatch[1]:'Other';
  const groups=await loadWorkspaceTree(functions.id,0),group=groups.items.find(item=>item.name===prefix);
  if(!group)return;
  $('source-search').value=source.name;
  const leaves=await loadWorkspaceTree(group.id,0),leaf=leaves.items.find(item=>item.target?.id===source.id);
  if(leaf){workspaceTree.active=`source:${leaf.id}`;renderWorkspaceTree(leaves);}
}
async function loadSources() {
  return loadWorkspaceTree(workspaceTree.node,workspaceTree.offset);
}
let sourceRequest=0,sourceCompilationReceipt=null;
async function openSource(id,variant,retrying=false,cached=null) {
  if(variant!=='global-initializer')variant='cpp';
  if(!retrying&&dirty('source')&&!canLeave())return;
  activateWorkspaceEditor('source');
  const request=++sourceRequest;
  const load=beginWorkspaceContentLoad('Loading checked source…',()=>openSource(id,variant,true));
  $('source-basis').textContent='Reading compiler source…';
  let source;
  try{source=cached||await api(`/api/source?id=${encodeURIComponent(id)}&variant=${variant}`);}
  catch(error){if(request===sourceRequest)failWorkspaceContentLoad(load,error.message);throw error;}
  if(request!==sourceRequest){globalThis.ReplayStudio?.cacheLoaded('source',source);return;}
  state.source=source;sourceCompilationReceipt=null; $('source-empty').hidden=true; $('source-editor').hidden=false;
  $('source-name').textContent=source.name; $('source-identity').textContent=source.symbol||source.id;
  const language=source.language||(variant==='global-initializer'?'json':'plaintext');
  setEditor('source',source.content,language,!source.editable);
  $('source-language').textContent=`${language==='cpp'?'C++':language} · ${source.compilable?'Compiler input':source.editable?'Recovery draft':'Reference text'}`;
  showSourceBasis(source);
  showSourceRecovery(source);
  $('source-save').disabled=!source.editable; $('source-remove').disabled=!(source.provenance?.basis||'').startsWith('user-authored');
  sourceCheck.disabled=!source.editable||variant==='global-initializer';
  $('source-restore').hidden=variant!=='global-initializer';
  for(const b of $('source-tabs').querySelectorAll('button')){b.classList.toggle('active',b.dataset.variant===variant);b.hidden=variant==='global-initializer'?b.dataset.variant!==variant:source.id.startsWith('sym_')?b.dataset.variant!=='assembly':b.dataset.variant==='global-initializer'||source.id.startsWith('user_')&&b.dataset.variant!=='cpp';}
  editorChanged('source');
  finishWorkspaceContentLoad(load);
}
function editorChanged(kind) {
  const editor=$(`${kind}-content`), text=editor.value;
  if(kind==='source'&&sourceCompilationReceipt&&sourceCompilationReceipt.content!==text){
    sourceCompilationReceipt=null;
    sourceDiagnosticsTitle.textContent='Buffer changed; check compilation again';
    sourceDiagnosticsText.textContent='The previous compilation result applies to the previous buffer.';
  }
  const lines=text.split('\n').length;
  $(`${kind}-lines`).textContent=Array.from({length:lines},(_,i)=>i+1).join('\n');
  $(`${kind}-dirty`).textContent=dirty(kind)?'Unsaved changes':'Saved';
  const position=editors[kind]?.getPosition?.();
  const prefix=text.slice(0,editor.selectionStart), line=prefix.split('\n').length,col=prefix.length-prefix.lastIndexOf('\n');
  $(`${kind}-location`).textContent=`Ln ${position?.lineNumber??line}, Col ${position?.column??col}`;
  window.ReplayStudio?.changed(kind);
}
function revealCodeMatch(kind,match){
  const text=$(`${kind}-content`).value;
  const escaped=match.query.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');
  const found=new RegExp(escaped,'iu').exec(text);
  const line=found?text.slice(0,found.index).split('\n').length:match.line;
  const column=found?found.index-text.lastIndexOf('\n',found.index-1):match.column;
  const editor=editors[kind];
  if(editor){const model=editor.getModel(),position=model.validatePosition({lineNumber:line,column});
    editor.setPosition(position);editor.revealPositionInCenter(position);editor.focus();
  }else{const input=$(`${kind}-content`),at=found?.index??text.split('\n').slice(0,line-1).join('\n').length;
    input.focus();input.setSelectionRange(at,at+(found?.[0].length||0));input.scrollTop=Math.max(0,line-3)*20;}
}
async function saveSource() {
  if(!state.source)return;
  globalThis.ReplayStudio?.assertCanSave('source');
  const selected=state.source,content=$('source-content').value,request=sourceRequest;
  const saved=await api('/api/source/save',{id:selected.id,variant:selected.variant,content,revision:selected.revision});
  globalThis.ReplayStudio?.accepted('source',saved,content);
  if(request!==sourceRequest)return;
  state.source=saved;
  if($('source-content').value===content)setEditor('source',saved.content,saved.language,!saved.editable);
  showSourceBasis(state.source);showSourceRecovery(state.source);editorChanged('source');await loadWorkspaceTree(workspaceTree.node,workspaceTree.offset);toast('Source saved. It will be compiled in the next build.');
}
function showSourceBasis(source){
  const growth=source.estimated_file_growth_bytes||0;
  $('source-basis').textContent=(source.provenance?.basis||'Recovered Replay source')+(growth?` · Executable file growth: +${(growth/1048576).toFixed(1)} MiB (native storage preserved)`:'');
}
const sourceDiagnostics=element('details',undefined,'source-recovery');
const sourceDiagnosticsTitle=element('summary'),sourceDiagnosticsText=element('pre');
sourceDiagnostics.append(sourceDiagnosticsTitle,sourceDiagnosticsText);$('source-editor').querySelector('.editor-toolbar').after(sourceDiagnostics);sourceDiagnostics.hidden=true;
function showSourceRecovery(source){
  refreshCIndexStatus();
  const recovery=source.recovery;sourceDiagnostics.hidden=!recovery;
  if(!recovery)return;
  sourceDiagnosticsTitle.textContent=recovery.status.endsWith('equivalent-leaf')?'C++ compiled to verified native leaf behavior':'C++ recovery requires completion';
  sourceDiagnosticsText.textContent=(recovery.diagnostics||[]).join('\n');sourceDiagnostics.open=false;
}
const sourceCheck=element('button','Check compilation');sourceCheck.id='source-check';$('source-save').before(sourceCheck);
sourceCheck.onclick=guard(async()=>{
  const source=state.source;if(!source||source.variant==='global-initializer'||!source.editable)return;
  const request=sourceRequest,content=$('source-content').value;sourceCheck.disabled=true;
  try{
    const checked=await api('/api/source/check',{id:source.id,revision:source.revision,content});
    if(request!==sourceRequest||state.source?.id!==source.id||$('source-content').value!==content)return;
    sourceCompilationReceipt={id:source.id,content};
    sourceDiagnostics.hidden=false;sourceDiagnostics.open=true;
    sourceDiagnosticsTitle.textContent=checked.compiled?'C++ AMD64 object compilation passed':'Compilation needs corrections';
    sourceDiagnosticsText.textContent=checked.diagnostics||checked.note||'Compilation passed.';
    globalThis.ReplaySourceErrors?.checked('source',content,checked);
  }finally{sourceCheck.disabled=!state.source?.editable||state.source?.variant==='global-initializer';}
});
const cIndexStatus=element('div','C++ cache starting…','catalog-status');cIndexStatus.id='source-cpp-index-status';cIndexStatus.setAttribute('role','status');$('workspace-catalog-status').before(cIndexStatus);
async function refreshCIndexStatus(){
  if(state.page!=='sources')return;
  try{const status=await api('/api/source-index');cIndexStatus.textContent=status.error?'C++ cache: '+status.error:`C++ cache ${status.indexed.toLocaleString()}/${status.total.toLocaleString()} · ${((status.counts['byte-equivalent-leaf']||0)+(status.counts['instruction-equivalent-leaf']||0)).toLocaleString()} native leaf checks passed · ${status.state}`;
    cIndexStatus.title=`Generated inputs are checked every ${status.poll_seconds} seconds. Recovered code needing completion stays editable; saved edits are preserved.`;
  }catch{cIndexStatus.textContent='C++ cache status unavailable';}
}
setInterval(refreshCIndexStatus,10000);
async function loadFiles() {
  state.files=(await api('/api/files')).items;renderFiles();
}
function renderFiles() {
  const query=$('file-search').value.toLowerCase(),files=state.files.filter(f=>f.path.toLowerCase().includes(query));
  $('file-count').textContent=String(files.length);
  $('file-list').replaceChildren(...files.map(f=>entry(f.name,f.path,state.file?.path===f.path,()=>openFile(f.path))));
}
async function openFile(path,retrying=false,cached=null) {
  if(!retrying&&dirty('file')&&!canLeave())return;
  activateWorkspaceEditor('file');
  const request=++fileRequest,load=beginWorkspaceContentLoad('Loading current project file…',()=>openFile(path,true));
  let file;
  try{file=cached||await api(`/api/file?path=${encodeURIComponent(path)}`);}
  catch(error){if(request===fileRequest)failWorkspaceContentLoad(load,error.message);throw error;}
  if(request!==fileRequest){globalThis.ReplayStudio?.cacheLoaded('file',file);return;}
  state.file=file;
  $('file-empty').hidden=true;$('file-editor').hidden=false;$('file-name').textContent=state.file.name;$('file-path').textContent=state.file.path;setEditor('file',state.file.content,state.file.language,file.editable===false);
  $('file-save').disabled=file.editable===false;
  editorChanged('file');renderFiles();finishWorkspaceContentLoad(load);
}
async function saveFile() {
  if(!state.file||state.file.editable===false)return;
  globalThis.ReplayStudio?.assertCanSave('file');
  const selected=state.file,content=$('file-content').value,request=fileRequest;
  const saved=await api('/api/file/save',{path:selected.path,content,revision:selected.revision});
  globalThis.ReplayStudio?.accepted('file',saved,content);
  if(request!==fileRequest)return;
  state.file=saved;
  if($('file-content').value===content)setEditor('file',saved.content,saved.language,!saved.editable);
  editorChanged('file');await loadWorkspaceTree(workspaceTree.node,workspaceTree.offset);toast('Source file saved; previous revision archived locally.');
}
async function loadZones() {
  const request=++zoneListRequest;
  const data=await api(`/api/fastfiles?q=${encodeURIComponent($('zone-search').value)}&offset=${state.zoneOffset}&limit=100`);
  if(request!==zoneListRequest)return;
  state.zoneTotal=data.total;
  $('zone-list').replaceChildren(...data.items.map(z=>entry(z.relative_path.split('/').pop(),`v${z.source_xfile_version||'?'} · ${(z.bytes/1048576).toFixed(1)} MiB`,state.zone?.relative_path===z.relative_path,()=>openZone(z))));
  $('zone-range').textContent=`${data.total?state.zoneOffset+1:0}–${Math.min(state.zoneOffset+100,data.total)} of ${data.total.toLocaleString()}`;
  $('zone-prev').disabled=state.zoneOffset===0;$('zone-next').disabled=state.zoneOffset+100>=data.total;
}
function openZone(zone) {
  if(dirty('asset')&&!window.confirm('Discard unsaved asset changes?'))return;
  resetSoundEditor();
  ++assetRequest;++assetListRequest;
  state.zone=zone;state.zoneId=zone.zone_id||null;state.asset=null;state.assetOffset=0;
  workspaceTree.zone=zone;
  $('new-asset').disabled=state.buildActive||state.buildStarting||!state.zoneId;
  activateWorkspaceEditor('zone');
  const sourceStatus=zone.source_status||zone.status;
  const catalogDetail={building:'catalog updating',ready:'cached metadata available',stale:'cached metadata · refreshing',unavailable:'catalog unavailable'}[zone.inventory_state];
  const sourceLabel=sourceStatus==='source-header-checked'?'source header checked':sourceStatus||'source will be checked on selection';
  $('zone-name').textContent=zone.relative_path;$('zone-detail').textContent=`Source XFile version ${zone.source_xfile_version||'?'} · ${catalogDetail||(zone.inventory_cached?'metadata cache candidate':sourceLabel)}`;
  $('zone-extract').disabled=!!zone.inventory_cached||sourceStatus!=='source-header-checked';$('asset-details').textContent='';$('asset-details').hidden=true;$('asset-list').replaceChildren();$('asset-browser').hidden=true;$('asset-editor').hidden=true;
  $('zone-status').textContent=zone.inventory_state==='ready'?'Cached native metadata is available. Each selected asset is checked before editing.':zone.inventory_state==='building'?'Native metadata is being cataloged. Folder contents may be incomplete while the catalog updates.':zone.inventory_state==='stale'?'Cached native metadata is being refreshed. Selected assets still require a current source check.':zone.inventory_cached?'A metadata cache candidate exists; current source identity is being checked.':zone.error||(sourceStatus==='source-header-checked'?'Fastfile source header is available. Native asset folders appear when a validated inventory is ready; selected assets are checked before editing.':'Fastfile source status is not present in this result. Current source identity is checked when an asset is opened.');
}
async function extractZone() {
  if(!state.zone)return;
  const selected=state.zone.relative_path; $('zone-extract').disabled=true;$('zone-status').textContent='Decoding source and patch into the persistent cache…';
  try{
    const receipt=await api('/api/fastfile/extract',{path:selected});
    if(state.zone.relative_path!==selected)return;
    state.zoneId=receipt.zone_id;state.zone={...state.zone,zone_id:receipt.zone_id,inventory_cached:true};workspaceTree.zone=state.zone;state.assetOffset=0;$('asset-search').value='';const rows=await loadAssets();$('asset-browser').hidden=true;
    $('zone-status').textContent=rows.typed_graph_ready?'Typed asset graph ready for editing.':`Native inventory validated: ${rows.total.toLocaleString()} assets. Verified semantic editors are available; complete archive packaging is still being implemented.`;
    $('asset-details').textContent=JSON.stringify({cache_hit:receipt.cache_hit,zone_id:receipt.zone_id,coverage:rows.coverage,source:receipt.source,outputs:receipt.outputs},null,2);
    if(workspaceTree.node)await loadWorkspaceTree(workspaceTree.node,0);
  }catch(error){if(state.zone?.relative_path===selected)$('zone-status').textContent=error.message;throw error;}
  finally{if(state.zone?.relative_path===selected)$('zone-extract').disabled=!!state.zone.inventory_cached||(state.zone.source_status!=='source-header-checked'&&state.zone.status!=='source-header-checked');}
}
async function loadAssets() {
  if(!state.zoneId)return;
  const request=++assetListRequest;
  const zoneId=state.zoneId,rows=await api(`/api/assets?zone=${encodeURIComponent(zoneId)}&q=${encodeURIComponent($('asset-search').value)}&offset=${state.assetOffset}&limit=60`);
  if(state.zoneId!==zoneId||request!==assetListRequest)return rows;
  $('asset-browser').hidden=false;
  $('new-asset').disabled=state.buildActive||state.buildStarting;
  $('asset-list').replaceChildren(...rows.items.map(a=>entry(a.name||`Asset ${a.index}`,`${a.type||a.native_type_name||`Type ${a.type_id}`} · ${a.index??'new'}${a.operation==='remove'?' · removal queued':a.operation==='append'?' · creation queued':a.editable?' · editor available':''}`,state.asset?.asset_id===a.asset_id,()=>openAsset(a.asset_id))));
  $('asset-range').textContent=`${rows.total?state.assetOffset+1:0}–${Math.min(state.assetOffset+60,rows.total)} of ${rows.total.toLocaleString()}`;
  $('asset-prev').disabled=state.assetOffset===0;$('asset-next').disabled=state.assetOffset+60>=rows.total;
  return rows;
}
let assetRequest=0;
let assetSaveInFlight=false;
let assetLifecycleBusy=false;
let assetSaveOwner=0,assetLifecycleOwner=0;
function invalidateWorkspaceMutationGuards(){
  assetSaveOwner++;assetSaveInFlight=false;
  assetLifecycleOwner++;assetLifecycleBusy=false;
  soundMutationOwner++;soundBusy=false;
}
async function openAsset(id,retrying=false,metadata=null,cached=null) {
  if(!retrying&&dirty('asset')&&!canLeave())return;
  invalidateWorkspaceMutationGuards();
  activateWorkspaceEditor('asset');
  resetSoundEditor();
  const request=++assetRequest,load=beginWorkspaceContentLoad('Loading and checking native asset…',()=>openAsset(id,true,metadata));
  $('zone-status').textContent='Loading checked asset source from the local cache…';
  let loadedAsset=null,loadError=null;
  try {
    let asset;
    try{asset=cached||await api(`/api/asset?id=${encodeURIComponent(id)}`);}
    catch(error){
      const canAcquire=error?.code==='asset_payload_cache_missing'&&metadata?.metadata_only===true&&
        typeof metadata.relative_path==='string'&&metadata.relative_path&&typeof metadata.zone_id==='string'&&
        /^[0-9a-f]{64}$/.test(metadata.zone_id)&&Number.isSafeInteger(metadata.index)&&metadata.index>=0&&
        Number.isSafeInteger(metadata.type_id)&&metadata.type_id>=0&&id===`${metadata.zone_id}:${metadata.index}`;
      if(!canAcquire)throw error;
      const receipt=await api('/api/fastfile/extract',{path:metadata.relative_path});
      if(request!==assetRequest)return;
      if(receipt.zone_id!==metadata.zone_id)throw new Error('The fastfile identity changed since this search result was indexed. Search again before opening the asset.');
      asset=await api(`/api/asset?id=${encodeURIComponent(id)}`);
    }
    asset=ReplayWorkspaceTree.checkedAsset(asset,id,metadata);
    if(request!==assetRequest){globalThis.ReplayStudio?.cacheLoaded('asset',asset);return;}
    loadedAsset=asset;showAsset(asset);
    finishWorkspaceContentLoad(load);
  } catch(error) {
    loadError=error;
    if(request===assetRequest)failWorkspaceContentLoad(load,error.message);
    throw error;
  } finally {
    if(request===assetRequest)$('zone-status').textContent=(loadedAsset?.reader_scope==='xasset-table-only'||loadedAsset?.payload_format==='Native XAsset table identity only')?
      'This fastfile row is available as read-only metadata; a native payload editor is unavailable.':
      loadedAsset?'Selected asset is checked against its current fastfile before editing.':
      `Asset check did not complete${loadError?.message?`: ${loadError.message}`:''}.`;
  }
}
function showAsset(asset,replaceContent=true) {
  invalidateImageRender();
  resetSoundEditor();
  state.asset=asset;$('asset-editor').hidden=false;$('asset-name').textContent=asset.name;$('asset-identity').textContent=asset.asset_id;
  const rawfile=asset.type_id===51&&asset.reader_scope!=='xasset-table-only',rawfileMode=asset.editor_mode||asset.source?.typed_layout?.editor_mode;
  const language=asset.language||'plaintext';
  const editorLanguage=rawfile&&((rawfileMode==='base64')||language==='binary/base64')?'plaintext':language;
  if(replaceContent)setEditor('asset',asset.content??'',editorLanguage,!asset.editable);
  $('asset-save').disabled=!asset.editable;$('asset-format').textContent=`${asset.type} · ${asset.payload_format||'Native asset'}`;
  $('asset-discard').hidden=!asset.pending_path;
  $('asset-recompile').hidden=!asset.pending_path||!asset.stale||!!asset.operation;
  $('asset-recompile').disabled=state.buildActive||state.buildStarting;
  $('asset-discard').textContent=asset.operation==='append'?'Cancel creation':asset.operation==='remove'?'Cancel removal':'Restore original';
  $('asset-remove').hidden=!canRemoveAsset(asset)||!!asset.operation;
  $('asset-remove').disabled=state.buildActive||state.buildStarting||!!asset.pending_path;
  $('asset-language').textContent=rawfile?(rawfileMode==='base64'||language==='binary/base64'?'Base64 · Lossless RawFile bytes':`${language==='ini'?'INI':language} · RawFile source`):asset.editable?`${asset.language} · Semantic source`:'Native asset metadata';
  $('asset-package-status').textContent=asset.codec_error||asset.package_status|| (asset.archive_writable?'Native archive packaging available':asset.pending_path?'Compiled edit saved in the local cache. Compile game checks its native packaging plan before publication.':'Compile and save validates the asset payload. Compile game checks the native packaging plan before publication.');
  const image=asset.language==='image/png-base64'||asset.language==='image/dds-base64';
  const ddsImage=asset.language==='image/dds-base64';
  $('asset-image-editor').hidden=!image;$('asset-content').parentElement.hidden=image;
  $('asset-image-import').disabled=!asset.editable;$('asset-dds-import').disabled=!asset.editable;
  $('asset-image-mips').disabled=!asset.editable;
  $('asset-image-mips').parentElement.hidden=!state.assetCodecs.image?.mip_editing;
  for(const node of imagePngControls)node.hidden=ddsImage;
  for(const node of imageDdsControls)node.hidden=!ddsImage;
  if(replaceContent){imageStroke=null;imageUndoContent=null;$('asset-image-undo').disabled=true;}
  if(image&&!ddsImage&&replaceContent)renderAssetImage(asset.content);
  if(ddsImage&&replaceContent){
    const token=beginImagePanelLoad('Loading resident DDS resource…');
    const layout=asset.source?.typed_layout||{},dims=layout.dimensions||[];
    imageDdsMetadata.textContent=`${layout.resource_kind||'resident resource'} · ${dims[0]||'?'} × ${dims[1]||'?'} · depth ${dims[2]||1} · array ${dims[3]||1} · ${layout.level_count||'?'} mip levels · format ${layout.format??'?'} · cube status: ${layout.cube_status||'unverified'}`;
    imageDdsDownload.href=asset.content||'';imageDdsDownload.download=(asset.name.replace(/[^a-zA-Z0-9_.-]/g,'_')||'image')+'.dds';
    finishImagePanelLoad(token);
  }
  $('asset-details').textContent=JSON.stringify({...asset,content:undefined},null,2);editorChanged('asset');
  if(asset.type_id===21&&asset.reader_scope!=='xasset-table-only')guard(loadSoundEntries)(asset,assetRequest);
}
function canRemoveAsset(asset){return asset?.type_id===41||(asset?.type_id===51&&asset?.row_remove_supported===true&&state.assetCodecs.rawfile?.row_remove===true)||(asset?.type_id===54&&asset?.row_remove_supported===true&&state.assetCodecs.stringtable?.row_remove===true)||(asset?.type_id===62&&state.assetCodecs.lua?.row_remove===true)||(asset?.type_id===52&&state.assetCodecs.gsc?.row_remove===true)||([12,14,15,16,17].includes(asset?.type_id)&&asset?.row_remove_supported===true&&state.assetCodecs.shader?.row_remove===true&&state.assetCodecs.shader?.row_remove_types?.includes(asset.type_id)===true)||(asset?.type_id===19&&asset?.row_remove_supported===true&&state.assetCodecs.image?.row_remove===true);}
function imageLoadCurrent(token){return !!token&&token===imageRenderToken&&token.sequence===imageRenderSequence&&token.request===assetRequest&&token.assetId===state.asset?.asset_id;}
function imageSaveDisabled(){return !state.asset?.editable||state.backendRestart||state.buildActive||state.buildStarting||assetSaveInFlight||assetLifecycleBusy;}
function invalidateImageRender(){
  imageRenderSequence++;imageRenderToken=null;imageRenderBusy=false;imageStroke=null;
  imageLoadRetry.onclick=null;imageLoadMask.hidden=true;imagePanel.removeAttribute('aria-busy');
  for(const child of imagePanel.children)child.inert=false;
  imageCanvas.width=0;imageCanvas.height=0;imageDownload.removeAttribute('href');imageDdsDownload.removeAttribute('href');$('asset-save').disabled=imageSaveDisabled();
}
function beginImagePanelLoad(message){
  const token={sequence:++imageRenderSequence,request:assetRequest,assetId:state.asset?.asset_id};
  imageRenderToken=token;imageRenderBusy=true;imageStroke=null;imagePanel.setAttribute('aria-busy','true');
  for(const child of imagePanel.children)if(child!==imageLoadMask)child.inert=true;
  imageLoadMask.hidden=false;imageLoadMask.dataset.failed='false';imageLoadTitle.textContent=message||'Loading image preview…';
  imageLoadDetail.textContent='The image editor will be available when its pixels and dimensions are ready.';
  imageLoadRetry.hidden=true;imageLoadRetry.onclick=null;imageCanvas.width=0;imageCanvas.height=0;
  imageDownload.removeAttribute('href');$('asset-save').disabled=true;
  return token;
}
function finishImagePanelLoad(token){
  if(!imageLoadCurrent(token))return false;
  imageRenderBusy=false;imageLoadRetry.onclick=null;imageLoadMask.hidden=true;imagePanel.removeAttribute('aria-busy');
  for(const child of imagePanel.children)child.inert=false;
  $('asset-save').disabled=imageSaveDisabled();return true;
}
function failImagePanelLoad(token,error,retry){
  if(!imageLoadCurrent(token))return false;
  imageRenderBusy=true;imageLoadMask.hidden=false;imageLoadMask.dataset.failed='true';
  imageCanvas.width=0;imageCanvas.height=0;imageDownload.removeAttribute('href');
  imageLoadTitle.textContent='Image preview could not be loaded';imageLoadDetail.textContent=String(error?.message||error||'The PNG could not be decoded.');
  imageLoadRetry.hidden=false;imageLoadRetry.onclick=guard(()=>{if(!imageLoadCurrent(token))return;return retry();});
  imageLoadRetry.focus?.();return true;
}
function decodeImage(content){return new Promise((resolve,reject)=>{const image=new Image();image.onload=()=>resolve(image);image.onerror=()=>reject(new Error('The PNG could not be decoded.'));image.src=imagePngData(content);});}
function drawImageContent(content,image,token,commit){
  if(!imageLoadCurrent(token))return false;
  if(!commit&&$('asset-content').value!==content){failImagePanelLoad(token,new Error('Image content changed while the preview was loading.'),()=>renderAssetImage($('asset-content').value));return false;}
  try{
    imageCanvas.width=image.width;imageCanvas.height=image.height;imageCanvas.getContext('2d').drawImage(image,0,0);
    const levels=imageMipCount(content);imageMips.max=1+Math.floor(Math.log2(Math.max(image.width,image.height)));imageMips.value=levels;
    imageSize.textContent=`${image.width} × ${image.height} · ${levels} mip level${levels===1?'':'s'} · original format retained`;
    imageDownload.href=imagePngData(content);imageDownload.download=(state.asset.name.replace(/[^a-zA-Z0-9_.-]/g,'_')||'image')+'.png';
    commit?.();return finishImagePanelLoad(token);
  }catch(error){failImagePanelLoad(token,error,()=>renderAssetImage(content,{message:'Loading image preview…',commit}));return false;}
}
function renderAssetImage(content,options={}){
  const token=options.token||beginImagePanelLoad(options.message||'Loading image preview…');
  const retry=options.retry||(()=>renderAssetImage(content,{message:options.message||'Loading image preview…',commit:options.commit}));
  const ready=image=>{if(!imageLoadCurrent(token))return false;return drawImageContent(content,image,token,options.commit);};
  const failed=error=>{failImagePanelLoad(token,error,retry);return false;};
  if(options.decodedImage)return Promise.resolve(ready(options.decodedImage));
  return decodeImage(content).then(ready,failed);
}
function imagePngData(content) {return content.replace(/^data:image\/png;mips=[1-9][0-9]*;base64,/, 'data:image/png;base64,');}
function imageMipCount(content) {return Number(content.match(/^data:image\/png;mips=([1-9][0-9]*);base64,/)?.[1]||state.asset?.source?.typed_layout?.level_count||1);}
function imageWithMips(content,levels) {return state.assetCodecs.image?.mip_editing?imagePngData(content).replace(/^data:image\/png;base64,/,`data:image/png;mips=${levels};base64,`):imagePngData(content);}
async function saveAsset() {
  if(!state.asset?.editable||assetSaveInFlight||imageRenderBusy)return;
  globalThis.ReplayStudio?.assertCanSave('asset');
  const selected=state.asset,assetId=selected.asset_id,zoneId=state.zoneId,sourceRevision=selected.revision;
  const content=$('asset-content').value,request=assetRequest,saveOwner=++assetSaveOwner;
  const releaseSave=()=>{if(assetSaveOwner===saveOwner)assetSaveInFlight=false;};
  let accepted=false,saveResult=null,load=0;
  const stillSelected=()=>assetSaveOwner===saveOwner&&request===assetRequest&&state.asset?.asset_id===assetId&&state.zoneId===zoneId&&state.asset?.revision===sourceRevision;
  const readBack=async()=>{
    if(!stillSelected()){releaseSave();return;}
    try{
      const saved=await api(`/api/asset?id=${encodeURIComponent(assetId)}`);
      if(!stillSelected()||load!==workspaceContentLoadRequest){releaseSave();return;}
      if(saved.asset_id!==assetId||saved.zone_id&&saved.zone_id!==zoneId)throw new Error('The checked asset identity changed during save.');
      if(saveResult?.revision&&saved.revision!==saveResult.revision)throw new Error('The saved asset revision does not match the checked readback.');
      if(saved.content!==content)throw new Error('The checked readback differs from the submitted text; the editor buffer was kept.');
      globalThis.ReplayStudio?.accepted('asset',saved,content);
      showAsset(saved);
      finishWorkspaceContentLoad(load);releaseSave();
      try{await loadWorkspaceTree(workspaceTree.node,workspaceTree.offset);}catch{}
      toast(saved.archive_writable?'Asset compiled and saved.':'Asset compiled and cached. Compile game verifies its native package.');
    }catch(error){
      if(!stillSelected()||load!==workspaceContentLoadRequest){releaseSave();return;}
      failWorkspaceContentLoad(load,error.message);
      throw error;
    }
  };
  assetSaveInFlight=true;
  load=beginWorkspaceContentLoad('Saving asset…',readBack);
  try{
    saveResult=await api('/api/asset/save',{asset_id:assetId,content,revision:sourceRevision});
    accepted=true;
    if(!stillSelected()||load!==workspaceContentLoadRequest){releaseSave();return;}
    await readBack();
  }catch(error){
    if(!accepted){
      if(load===workspaceContentLoadRequest)finishWorkspaceContentLoad(load);
      releaseSave();
    }
    throw error;
  }
}
async function runScopedAssetMutation({message,selected,request,zoneId,postPath,body,readBack,refresh,apply,success}){
  if(assetLifecycleBusy||assetSaveInFlight)return;
  const assetId=selected.asset_id,revision=selected.revision;
  const owner=++assetLifecycleOwner;
  const release=()=>{if(assetLifecycleOwner===owner)assetLifecycleBusy=false;};
  const isCurrent=()=>request===assetRequest&&state.asset?.asset_id===assetId&&
    state.zoneId===zoneId&&state.asset?.revision===revision&&assetLifecycleOwner===owner;
  let accepted=false,mutation=null,load=0;
  const continueMutation=async()=>{
    if(!isCurrent()||load!==workspaceContentLoadRequest){release();return;}
    try{
      if(!accepted){
        mutation=await api(postPath,body);
        accepted=true;
      }
      if(!isCurrent()||load!==workspaceContentLoadRequest){release();return;}
      if(mutation?.asset_id&&mutation.asset_id!==assetId)throw new Error('The mutation returned a different asset identity.');
      const value=await readBack(mutation);
      if(!isCurrent()||load!==workspaceContentLoadRequest){release();return;}
      if(value?.asset_id&&value.asset_id!==assetId)throw new Error('The checked readback returned a different asset identity.');
      if(value?.zone_id&&value.zone_id!==zoneId)throw new Error('The checked readback belongs to a different fastfile.');
      if(mutation?.discarded===true){
        if(mutation.revision!==revision)throw new Error('The discard acknowledgement does not match the submitted revision.');
        if(value&&(value.operation||value.pending_path))throw new Error('The checked readback still contains a pending asset operation.');
      }else if(mutation?.revision&&value?.revision!==mutation.revision){
        throw new Error('The checked readback does not match the accepted revision.');
      }
      await refresh?.(value,mutation);
      if(!isCurrent()||load!==workspaceContentLoadRequest){release();return;}
      if(value)globalThis.ReplayStudio?.accepted('asset',value);
      apply?.(value,mutation);
      finishWorkspaceContentLoad(load);release();
      if(success)toast(success(value,mutation));
    }catch(error){
      if(!isCurrent()||load!==workspaceContentLoadRequest){release();return;}
      if(accepted)failWorkspaceContentLoad(load,error.message);
      else{finishWorkspaceContentLoad(load);release();}
      throw error;
    }
  };
  assetLifecycleBusy=true;
  load=beginWorkspaceContentLoad(message,continueMutation);
  await continueMutation();
}
async function loadJobs() {
  const jobs=(await api('/api/jobs')).items;
  renderJobList(jobs);
  if(!state.job&&jobs.length)await openJob(jobs[0].id);
}
function renderJobList(jobs) {
  const signature=JSON.stringify(jobs.map(j=>[j.id,j.created,j.profile,j.status]));
  if(signature===jobsSignature)return;
  jobsSignature=signature;
  $('build-list').replaceChildren(...jobs.map(j=>entry(new Date(j.created*1000).toLocaleString(),`${j.profile} · ${j.status}`,state.job?.id===j.id,()=>openJob(j.id))));
  if(!jobs.length)$('build-list').append(element('p','No compilation jobs yet. Use Compile game to create a fresh verified build.','muted'));
}
async function openJob(id) {
  const request=++jobRequest,job=await api(`/api/job?id=${id}`);
  if(request!==jobRequest)return;
  if(state.job?.id!==id){state.logOffset=0;$('build-log').textContent='';}
  state.job=job;renderJob();await readLog();
}
function renderJob() {
  const j=state.job;$('build-title').textContent=`Build ${j.id.slice(0,8)}`;$('build-status').textContent=j.status;$('build-phase').textContent=j.error||j.phase;
  const nodes=[];
  for(const a of j.artifacts||[]){const div=element('div',undefined,'artifact'),aLink=element('a',`Download ${a.name}`);aLink.href=`/api/download?job=${j.id}&name=${encodeURIComponent(a.name)}`;div.append(aLink,element('small',a.path),element('small',`SHA256 ${a.sha256}`));nodes.push(div);}
  if(j.asset_packaging)nodes.push(element('div',j.asset_packaging,'notice'));
  $('build-artifacts').replaceChildren(...nodes);
}
async function readLog() {
  if(!state.job||state.loadingLog)return;
  state.loadingLog=true;const id=state.job.id;
  try{const data=await api(`/api/log?id=${id}&offset=${state.logOffset}`);if(state.job?.id!==id)return;const log=$('build-log'),bottom=log.scrollHeight-log.scrollTop-log.clientHeight<35;log.textContent+=data.text;state.logOffset=data.offset;if(bottom)log.scrollTop=log.scrollHeight;}finally{state.loadingLog=false;}
}
async function compile() {
  if(state.buildStarting||state.buildActive||state.backendRestart)return;
  if(window.ReplayStudio?.hasUnsaved())throw new Error('Save or close the unsaved working tabs before compiling.');
  if(dirty('source')||dirty('file')||dirty('asset'))throw new Error('Save edits before compiling.');
  state.buildStarting=true;$('compile').disabled=true;$('compile').textContent='Checking package plan…';$('job-badge').textContent='Checking native asset placement';
  toast('Checking saved sources and the native fastfile package plan…');
  try {
    const job=await api('/api/build',{profile:$('build-profile').value});state.buildActive=true;toast('Compilation started. Source saves are held until this build finishes.');await page('builds');await openJob(job.id);
  } finally {
    state.buildStarting=false;$('compile').textContent='Compile game ↵';$('compile').disabled=!state.csrf||state.buildActive||state.backendRestart;
  }
}
function debounce(fn,delay=250){let timer;return(...a)=>{clearTimeout(timer);timer=setTimeout(()=>guard(fn)(...a),delay);};}
// Workspace navigation stays local; catalog queries use the existing list pages.
const workspacePages = [
  ['overview','Overview','Workspace summary and shortcuts'],
  ['sources','Game source','Functions, globals, engine files, fastfiles and assets'],
  ['builds','Builds & output','Compiler jobs, logs and verified artifacts'],
  ['settings','Project details','Paths, cache and executable identity'],
];
let workspaceSearchRequest=0,workspaceSearchOffset=0,workspaceSearchTotal=0,workspaceSearchLastQuery='';
function workspaceSearchStatus(message,state='ready',busy=false,retry){
  const status=$('workspace-search-status'),results=$('workspace-results');
  status.hidden=false;status.dataset.state=state;status.textContent=message;
  status.setAttribute('aria-busy',String(busy));results.setAttribute('aria-busy',String(busy));results.inert=busy;
  $('workspace-search-close').disabled=busy||state==='error'||state==='unavailable';
  $('workspace-query').disabled=state==='error'||state==='unavailable';
  const retryButton=element('button','Retry','primary');retryButton.type='button';retryButton.hidden=!retry;
  if(retry){retryButton.onclick=guard(retry);status.append(retryButton);}
}
function workspaceSearchResult(item){
  const target=item.target||{};
  const kind=item.kind|| (target.asset_id?'asset':target.path?'file':target.variant?'source':null);
  const id=item.id||item.node;
  if(!id||!kind)throw new Error('A workspace search result is missing its canonical target.');
  const normalized={...item,id,kind,target:{...target}};
  if(kind==='zone'){
    if(normalized.source_status===undefined&&typeof item.status==='string')normalized.source_status=item.status;
    if(normalized.extract_target===undefined&&typeof item.relative_path==='string')normalized.extract_target=item.relative_path;
  }
  if(!['folder','source','global','file','asset','zone'].includes(kind))throw new Error('A workspace search result has an unsupported target kind.');
  for(const key of ['relative_path','zone_id','type_id','index','metadata_only','type_name'])
    if(normalized[key]===undefined&&target[key]!==undefined)normalized[key]=target[key];
  ReplayWorkspaceTree.action(normalized);
  return normalized;
}
async function searchWorkspace(query=$('workspace-query').value.trim(),offset=workspaceSearchOffset){
  const request=++workspaceSearchRequest,results=$('workspace-results');
  results.replaceChildren();workspaceSearchStatus('Searching the workspace index…','building',true);
  try{
    const data=await api(`/api/workspace/search?q=${encodeURIComponent(query)}&offset=${offset}&limit=100`);
    if(request!==workspaceSearchRequest||$('workspace-query').value.trim()!==query)return;
    if(!data||!Array.isArray(data.items)||!data.search_status||
       !Number.isSafeInteger(data.total)||data.total<0||!Number.isSafeInteger(data.offset)||data.offset<0||
       !Number.isSafeInteger(data.limit)||data.limit<1||data.items.length>data.limit||
       data.offset+data.items.length>data.total||typeof data.search_status.state!=='string'||
       typeof data.search_status.complete!=='boolean')throw new Error('The workspace search response is incomplete.');
    const rows=data.items.map(workspaceSearchResult);
    workspaceSearchOffset=data.offset;workspaceSearchTotal=data.total;
    const pages=workspacePages.filter(([id,label,description])=>!query||`${id} ${label} ${description}`.toLowerCase().includes(query.toLowerCase()))
      .map(([id,label,description])=>entry(label,description,false,async()=>{$('workspace-search-dialog').close();await page(id);}));
    results.replaceChildren(...pages,...rows.map(item=>{
      const button=element('button');button.type='button';button.dataset.kind=item.kind;button.dataset.itemId=item.id;
      button.append(element('strong',item.name),element('small',`${item.area||'Workspace'}${item.relative_path?` · ${item.relative_path}`:item.path?` · ${item.path}`:''}`));
      button.onclick=guard(async()=>{
        $('workspace-search-dialog').close();
        if(!await page('sources'))return;
        await selectWorkspaceItem(item);
      });
      return button;
    }));
    const pagination=$('workspace-search-pagination');
    pagination.hidden=data.total<=data.limit;
    $('workspace-search-range').textContent=ReplayWorkspaceTree.range(data);
    $('workspace-search-prev').disabled=data.offset===0;
    $('workspace-search-next').disabled=data.offset+data.items.length>=data.total;
    const coverage=data.search_status;
    if(['unavailable','error'].includes(coverage.state)||coverage.error){
      workspaceSearchStatus(`${workspaceSearchProgress(coverage,data.total)} Retry to continue searching.`,'unavailable',false,()=>searchWorkspace(query,workspaceSearchOffset));
      return data;
    }
    if(coverage.complete===true&&coverage.validation_scope==='display-only-metadata'){
      workspaceSearchStatus(rows.length?workspaceSearchProgress(coverage,data.total):`No workspace matches. ${workspaceSearchProgress(coverage,data.total)}`,'ready');
    }else if(coverage.complete===true){
      workspaceSearchStatus('Matches are available, but search coverage could not be verified.','stale');
    }else{
      workspaceSearchStatus(workspaceSearchProgress(coverage,data.total),'building');
    }
    return data;
  }catch(error){
    if(request!==workspaceSearchRequest||$('workspace-query').value.trim()!==query)return;
    results.replaceChildren();
    workspaceSearchStatus(`${error.message} Retry to search again.`,'error',false,()=>searchWorkspace(query));
    throw error;
  }
}
function renderWorkspaceSearch() {
  const query=$('workspace-query').value.trim(), needle=query.toLowerCase();
  if(query!==workspaceSearchLastQuery){workspaceSearchLastQuery=query;workspaceSearchOffset=0;}
  const results=[];
  for(const [id,label,description] of workspacePages){
    if(!needle||`${label} ${description}`.toLowerCase().includes(needle))
      results.push(entry(label,description,false,async()=>{ $('workspace-search-dialog').close(); await page(id); }));
  }
  if(needle)searchWorkspace(query).catch(error=>console.warn('Workspace search failed.',error));
  else{workspaceSearchRequest++;$('workspace-search-status').hidden=true;$('workspace-search-status').removeAttribute('aria-busy');$('workspace-results').removeAttribute('aria-busy');$('workspace-results').inert=false;$('workspace-search-close').disabled=false;$('workspace-query').disabled=false;}
  $('workspace-results').replaceChildren(...results);
}
function openWorkspaceSearch() {
  if(document.querySelector('dialog[open]'))return;
  $('workspace-query').value='';workspaceSearchLastQuery='';workspaceSearchOffset=0;renderWorkspaceSearch();
  $('workspace-search-dialog').showModal();$('workspace-query').focus();
}
$('workspace-search').onclick=openWorkspaceSearch;
$('workspace-search-close').onclick=()=>{if(!$('workspace-search-close').disabled)$('workspace-search-dialog').close();};
$('workspace-query').oninput=debounce(renderWorkspaceSearch,180);
$('workspace-search-prev').onclick=guard(()=>searchWorkspace($('workspace-query').value.trim(),Math.max(0,workspaceSearchOffset-100)));
$('workspace-search-next').onclick=guard(()=>searchWorkspace($('workspace-query').value.trim(),workspaceSearchOffset+100));
$('workspace-search-dialog').addEventListener('keydown',e=>{
  if(e.key==='Escape'&&$('workspace-search-close').disabled){e.preventDefault();e.stopPropagation();return;}
  const buttons=[...$('workspace-results').children],index=buttons.indexOf(document.activeElement);
  if(e.key==='ArrowDown'||e.key==='ArrowUp'){
    e.preventDefault();
    const next=index<0?(e.key==='ArrowDown'?0:buttons.length-1):(index+(e.key==='ArrowDown'?1:-1)+buttons.length)%buttons.length;
    buttons[next]?.focus();
  }else if(e.key==='Enter'&&document.activeElement===$('workspace-query')){
    e.preventDefault();buttons[0]?.click();
  }
});
$('workspace-search-dialog').addEventListener('cancel',e=>{
  if($('workspace-search-close').disabled)e.preventDefault();
});
document.addEventListener('keydown',e=>{
  if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){
    e.preventDefault();e.stopPropagation();openWorkspaceSearch();
  }
},true);
function setSidebarCollapsed(collapsed) {
  document.body.classList.toggle('sidebar-collapsed',collapsed);
  $('sidebar-toggle').setAttribute('aria-expanded',String(!collapsed));
  $('sidebar-toggle').setAttribute('aria-label',collapsed?'Expand sidebar':'Collapse sidebar');
  $('sidebar-toggle').title=collapsed?'Expand sidebar':'Collapse sidebar';
}
try{setSidebarCollapsed(localStorage.getItem('replay.sidebarCollapsed')==='true');}catch{/* Browser storage may be disabled. */}
for(const button of document.querySelectorAll('.workspace-shortcuts button')){
  const icon=document.querySelector(`nav button[data-page="${button.dataset.openPage}"] svg`).cloneNode(true);
  icon.classList.remove('nav-icon');button.querySelector('.shortcut-icon').replaceChildren(icon);
}
for(const kind of ['source','zone','asset'])for(const direction of ['prev','next'])
  $(`${kind}-${direction}`).setAttribute('aria-label',`${direction==='prev'?'Previous':'Next'} ${kind==='source'?'workspace items':kind==='zone'?'fastfiles':'assets'}`);
for(const b of document.querySelectorAll('[data-page]'))b.onclick=guard(()=>page(b.dataset.page));
for(const b of document.querySelectorAll('[data-open-page]'))b.onclick=guard(e=>{e.preventDefault();return page(b.dataset.openPage);});
$('sidebar-toggle').onclick=()=>{
  const collapsed=!document.body.classList.contains('sidebar-collapsed');
  setSidebarCollapsed(collapsed);
  try{localStorage.setItem('replay.sidebarCollapsed',String(collapsed));}catch{/* Optional preference. */}
};
$('compile').onclick=guard(compile);
$('source-search').oninput=debounce(searchFromGameSource);
$('source-search-mode').onchange=guard(()=>{const mode=$('source-search-mode').value;$('source-search').placeholder=mode==='code'?'Find text in all C++…':'Search all IW8…';return searchFromGameSource();});
$('source-prev').onclick=guard(()=>loadWorkspaceResultsPage(workspaceGlobalSearchActive?workspaceGlobalSearchOffset-workspaceTree.limit:workspaceTree.offset-workspaceTree.limit));$('source-next').onclick=guard(()=>loadWorkspaceResultsPage(workspaceGlobalSearchActive?workspaceGlobalSearchOffset+workspaceTree.limit:workspaceTree.offset+workspaceTree.limit));
const globalTab=element('button','Initializer');globalTab.dataset.variant='global-initializer';globalTab.hidden=true;$('source-tabs').append(globalTab);
for(const b of $('source-tabs').children)b.onclick=guard(()=>state.source&&openSource(state.source.id,b.dataset.variant));
$('source-save').onclick=guard(saveSource);$('source-reset').onclick=guard(()=>state.source&&openSource(state.source.id,state.source.variant));
const sourceRestore=element('button','Restore initializer');sourceRestore.id='source-restore';sourceRestore.hidden=true;$('source-reset').after(sourceRestore);
sourceRestore.onclick=guard(async()=>{if(state.source?.variant!=='global-initializer')return;if(dirty('source')&&!window.confirm('There are unsaved initializer changes. Discard them and restore the native initializer?'))return;const source=state.source,content=$('source-content').value,request=sourceRequest;const restored=await api('/api/source/remove',{id:source.id,revision:source.revision,variant:source.variant});if(request!==sourceRequest||state.source?.id!==source.id||state.source?.variant!==source.variant)return;state.source=restored;if($('source-content').value===content)setEditor('source',restored.content,restored.language,!restored.editable);showSourceBasis(restored);editorChanged('source');toast('Native initializer restored; the edited revision remains archived.');});
$('source-remove').onclick=guard(async()=>{if(!state.source||!window.confirm('Remove this active source edit and restore its native implementation? The edited revision will remain archived.'))return;const source=state.source;await api('/api/source/remove',{id:source.id,revision:source.revision,variant:source.variant});state.source=null;workspaceTree.active=null;activateWorkspaceEditor('empty');$('source-editor').hidden=true;$('source-empty').hidden=false;await loadWorkspaceTree(workspaceTree.node,workspaceTree.offset);toast('Active source edit removed.');});
$('file-save').onclick=guard(saveFile);$('file-reset').onclick=guard(()=>state.file&&openFile(state.file.path));$('file-search').oninput=renderFiles;
for(const kind of ['source','file','asset']){const editor=$(`${kind}-content`);editor.oninput=()=>editorChanged(kind);editor.onkeyup=()=>editorChanged(kind);editor.onclick=()=>editorChanged(kind);editor.onscroll=()=>$(`${kind}-lines`).scrollTop=editor.scrollTop;editor.onkeydown=e=>{if(e.key==='Tab'&&!editor.readOnly){e.preventDefault();const start=editor.selectionStart,end=editor.selectionEnd;editor.setRangeText('    ',start,end,'end');editorChanged(kind);}};}
$('zone-search').oninput=debounce(()=>{workspaceTree.node=null;$('source-search').value=$('zone-search').value;return loadWorkspaceTree(null,0);});$('zone-prev').onclick=guard(()=>loadWorkspaceTree(workspaceTree.node,Math.max(0,workspaceTree.offset-workspaceTree.limit)));$('zone-next').onclick=guard(()=>loadWorkspaceTree(workspaceTree.node,workspaceTree.offset+workspaceTree.limit));$('zone-extract').onclick=guard(extractZone);
const zoneReceipt=element('button','Source receipt');zoneReceipt.id='zone-receipt';$('zone-detail').after(zoneReceipt);$('asset-details').hidden=true;zoneReceipt.onclick=()=>$('asset-details').hidden=!$('asset-details').hidden;
$('asset-search').oninput=debounce(()=>{state.assetOffset=0;return loadAssets();});$('asset-prev').onclick=guard(()=>{state.assetOffset=Math.max(0,state.assetOffset-60);return loadAssets();});$('asset-next').onclick=guard(()=>{state.assetOffset+=60;return loadAssets();});$('asset-save').onclick=guard(saveAsset);$('asset-reset').onclick=guard(()=>state.asset&&openAsset(state.asset.asset_id));
const assetDiscard=element('button','Restore original');assetDiscard.id='asset-discard';assetDiscard.hidden=true;$('asset-reset').after(assetDiscard);
const assetRecompile=element('button','Recompile draft');assetRecompile.id='asset-recompile';assetRecompile.hidden=true;assetDiscard.after(assetRecompile);
assetRecompile.onclick=guard(async()=>{
  const selected=state.asset,request=assetRequest,zoneId=state.zoneId;
  if(!selected?.pending_path)return;
  await runScopedAssetMutation({message:'Recompiling asset draft…',selected,request,zoneId,
    postPath:'/api/asset/recompile',body:{asset_id:selected.asset_id,revision:selected.revision},
    readBack:()=>api(`/api/asset?id=${encodeURIComponent(selected.asset_id)}`),
    refresh:async()=>{await loadWorkspaceTree(workspaceTree.node,workspaceTree.offset);},
    apply:compiled=>showAsset(compiled),
    success:()=>'Draft recompiled. Its source and previous revision are preserved.'});
});
const assetRemove=element('button','Remove asset');assetRemove.id='asset-remove';assetRemove.hidden=true;assetDiscard.after(assetRemove);
const newAsset=element('button','Add asset');newAsset.id='new-asset';newAsset.disabled=true;$('zone-extract').before(newAsset);
const assetCreateType=element('select');assetCreateType.id='asset-create-type';assetCreateType.setAttribute('aria-label','New asset type');
let residentImageCreateDataUrl=null,residentImageCreateBusy=false,residentImageCreateReadToken=0,residentImageCreateReader=null;
const assetCreateDefinitions=[
  {value:'localize',label:'Localize text',title:'Localize asset',nameLabel:'Key',namePlaceholder:'custom/menu_message',contentLabel:'New Localize text',submitLabel:'Create Localize',description:'The new text entry is staged in this fastfile. Compile game inserts its native row and checks every retained string.'},
  {value:'rawfile',label:'RawFile text',title:'RawFile text',nameLabel:'Filename',namePlaceholder:'custom/frontend.cfg',contentLabel:'New RawFile text',submitLabel:'Create RawFile',description:'Adds a text file to this fastfile. Compile game includes the saved file in the build.',capability:'rawfile'},
  {value:'rawfile-base64',type:'rawfile',editorMode:'base64',label:'RawFile binary (Base64)',title:'RawFile binary',nameLabel:'Filename',namePlaceholder:'custom/data.bin',contentLabel:'New RawFile Base64 data',submitLabel:'Create RawFile',description:'Paste Base64 for a binary file. Its decoded bytes are saved without text conversion and included in this fastfile when compiled.',capability:'rawfile'},
  {value:'stringtable',label:'StringTable CSV',title:'StringTable',nameLabel:'Filename',namePlaceholder:'custom/frontend.csv',contentLabel:'New StringTable CSV',submitLabel:'Create StringTable',description:'Adds a CSV table to this fastfile. Compile game includes the saved table and checks its cells and retained assets.',capability:'stringtable'},
  {value:'image',label:'Resident 2D image (DDS)',title:'Resident image',nameLabel:'Asset name',namePlaceholder:'images/custom_texture',contentLabel:'Resident image DDS file',submitLabel:'Create resident image',description:'Adds one native 2D image from a strict DDS up to 23 MiB using a same-format traced template. Arrays, volumes, cubes and streamed roots are not supported for creation.',capability:'image',nativeType:19},
  {value:'luafile',label:'Lua source',title:'Lua asset',nameLabel:'Filename',namePlaceholder:'custom/frontend.lua',contentLabel:'New Lua source',submitLabel:'Compile and create Lua',description:'The source compiles with Replay’s Lua compiler. Compile game inserts the new asset and verifies every retained asset and Lua payload.',capability:'lua'},
  {value:'scriptfile',label:'GSC ScriptFile',title:'GSC ScriptFile',nameLabel:'Filename',namePlaceholder:'custom/frontend.gsc',contentLabel:'New GSC ScriptFile source',submitLabel:'Create GSC ScriptFile',description:'GSC source is staged in this fastfile. Compile game validates the ScriptFile row and retained references.',capability:'gsc'},
  {value:'computeshader',label:'Compute shader assembly',title:'Compute shader',nameLabel:'Filename',namePlaceholder:'custom/compute.hlsl',contentLabel:'New compute shader assembly',submitLabel:'Assemble and create compute shader',description:'Adds a native type-12 compute shader from DXBC assembly. Compile game inserts and rereads the row.',capability:'shader',nativeType:12},
  {value:'vertexshader',label:'Vertex shader assembly',title:'Vertex shader',nameLabel:'Filename',namePlaceholder:'custom/vertex.hlsl',contentLabel:'New vertex shader assembly',submitLabel:'Assemble and create vertex shader',description:'Adds a native type-14 vertex shader from DXBC assembly. Compile game inserts and rereads the row.',capability:'shader',nativeType:14},
  {value:'hullshader',label:'Hull shader assembly',title:'Hull shader',nameLabel:'Filename',namePlaceholder:'custom/hull.hlsl',contentLabel:'New hull shader assembly',submitLabel:'Assemble and create hull shader',description:'Adds a native type-15 hull shader from DXBC assembly. Compile game inserts and rereads the row.',capability:'shader',nativeType:15},
  {value:'domainshader',label:'Domain shader assembly',title:'Domain shader',nameLabel:'Filename',namePlaceholder:'custom/domain.hlsl',contentLabel:'New domain shader assembly',submitLabel:'Assemble and create domain shader',description:'Adds a native type-16 domain shader from DXBC assembly. Compile game inserts and rereads the row.',capability:'shader',nativeType:16},
  {value:'pixelshader',label:'Pixel shader assembly',title:'Pixel shader',nameLabel:'Filename',namePlaceholder:'custom/menu_effect.hlsl',contentLabel:'New pixel shader assembly',submitLabel:'Assemble and create pixel shader',description:'Adds one native type-17 pixel shader from DXBC assembly. Compile game inserts and rereads the new row.',capability:'shader',nativeType:17},
];
for(const definition of assetCreateDefinitions){const option=element('option',definition.label);option.value=definition.value;assetCreateType.append(option);}
const assetCreateTypeLabel=element('label','Asset type');assetCreateTypeLabel.append(assetCreateType);$('asset-create-form').querySelector('label').before(assetCreateTypeLabel);
function assetCreateAllowed(definition){if(!definition.capability)return true;const capability=state.assetCodecs[definition.capability];return capability?.row_create===true&&(!definition.nativeType||capability.row_create_types?.includes(definition.nativeType)===true)&&(!definition.editorMode||capability.row_create_modes?.includes(definition.editorMode)===true);}
function updateAssetCreateType(){const definition=assetCreateDefinitions.find(item=>item.value===assetCreateType.value)||assetCreateDefinitions[0],isImage=definition.value==='image';$('asset-create-form').querySelector('h3').textContent=`Add ${definition.title}`;$('asset-create-close').setAttribute('aria-label',`Close ${definition.title} creation`);$('asset-create-name').parentElement.firstChild.textContent=definition.nameLabel;$('asset-create-name').placeholder=definition.namePlaceholder;$('asset-create-name').setAttribute('aria-label',`New ${definition.nameLabel.toLowerCase()}`);$('asset-create-content').setAttribute('aria-label',definition.contentLabel);$('asset-create-content').closest('label').hidden=isImage;$('asset-create-content').required=!isImage;$('asset-create-image-file-label').hidden=!isImage;$('asset-create-image-file-status').hidden=!isImage;$('asset-create-submit').textContent=definition.submitLabel;$('asset-create-form').querySelector('p').textContent=definition.description;$('asset-create-type').disabled=residentImageCreateBusy;$('asset-create-image-file').disabled=residentImageCreateBusy;$('asset-create-close').disabled=residentImageCreateBusy;}
function resetResidentImageCreateFile(){residentImageCreateReadToken++;if(residentImageCreateReader&&residentImageCreateReader.readyState===FileReader.LOADING)residentImageCreateReader.abort();residentImageCreateReader=null;residentImageCreateDataUrl=null;residentImageCreateBusy=false;$('asset-create-image-file').disabled=false;$('asset-create-type').disabled=false;$('asset-create-close').disabled=false;$('asset-create-image-file').value='';$('asset-create-image-file-status').textContent='';$('asset-create-image-file-status').hidden=true;$('asset-create-submit').disabled=false;}
assetCreateType.onchange=updateAssetCreateType;
newAsset.onclick=()=>{if(!state.zoneId)return;$('asset-create-form').reset();resetResidentImageCreateFile();for(const option of assetCreateType.options){const definition=assetCreateDefinitions.find(item=>item.value===option.value);option.hidden=option.disabled=!assetCreateAllowed(definition);}updateAssetCreateType();$('asset-create-dialog').showModal();$('asset-create-name').focus();};
$('asset-create-image-file').onchange=guard(async()=>{const token=++residentImageCreateReadToken,file=$('asset-create-image-file').files?.[0];residentImageCreateDataUrl=null;if(!file){$('asset-create-image-file-status').textContent='Choose one DDS file.';return;}if(!file.name.toLowerCase().endsWith('.dds'))throw new Error('Choose a .dds file.');if(file.size<148||file.size>23*1024*1024)throw new Error('Choose a complete DDS between 148 bytes and 23 MiB.');residentImageCreateBusy=true;$('asset-create-submit').disabled=true;$('asset-create-image-file').disabled=true;$('asset-create-type').disabled=true;$('asset-create-close').disabled=true;$('asset-create-image-file-status').hidden=false;$('asset-create-image-file-status').textContent=`Reading ${file.name}…`;try{const data=await new Promise((resolve,reject)=>{const reader=new FileReader();residentImageCreateReader=reader;reader.onload=()=>resolve(String(reader.result||''));reader.onerror=()=>reject(new Error('DDS import failed.'));reader.onabort=()=>reject(new Error('DDS import was cancelled.'));reader.readAsDataURL(file);});if(token!==residentImageCreateReadToken)return;const comma=data.indexOf(',');const encoded=comma>=0?data.slice(comma+1):'';if(!encoded||atob(encoded.slice(0,12)).slice(0,4)!=='DDS ')throw new Error('The selected file is not a DDS resource.');residentImageCreateDataUrl=`data:application/octet-stream;base64,${encoded}`;$('asset-create-image-file-status').textContent=`${file.name} · ${file.size.toLocaleString()} bytes ready`;}finally{if(token===residentImageCreateReadToken){residentImageCreateReader=null;residentImageCreateBusy=false;$('asset-create-submit').disabled=false;$('asset-create-image-file').disabled=false;$('asset-create-type').disabled=false;$('asset-create-close').disabled=false;}}});
$('asset-create-close').onclick=()=>$('asset-create-dialog').close();
$('asset-create-dialog').addEventListener('cancel',event=>{if(residentImageCreateBusy)event.preventDefault();});
$('asset-create-form').onsubmit=guard(async event=>{
  event.preventDefault();if(!state.zoneId)return;
  const zoneId=state.zoneId,button=$('asset-create-submit'),dialog=$('asset-create-dialog');button.disabled=true;
  let created=null,load=0;
  try{
    const definition=assetCreateDefinitions.find(item=>item.value===assetCreateType.value)||assetCreateDefinitions[0];
    if(!assetCreateAllowed(definition))throw new Error(`${definition.label} creation is not supported by this backend.`);
    if(residentImageCreateBusy)throw new Error('Wait for DDS file loading to finish.');
    if(definition.value==='image'&&!residentImageCreateDataUrl)throw new Error('Choose a DDS file before creating the image.');
    const payload={zone_id:zoneId,type:definition.type||definition.value,name:$('asset-create-name').value,content:definition.value==='image'?residentImageCreateDataUrl:$('asset-create-content').value};
    if(definition.editorMode)payload.editor_mode=definition.editorMode;
    const current=()=>load===workspaceContentLoadRequest&&state.page==='sources'&&state.zoneId===zoneId;
    const continueCreate=async()=>{
      if(!current())return;
      try{
        if(!created)created=await api('/api/asset/create',payload);
        if(!current())return;
        $('asset-search').value=created.name;state.assetOffset=0;
        await loadAssets();if(!current())return;
        await refreshWorkspaceTree();if(!current())return;
        finishWorkspaceContentLoad(load);
        await openAsset(created.asset_id);
        toast('Asset creation queued. Compile game builds and verifies the native row and shifted references.');
      }catch(error){
        if(!current())return;
        if(created)failWorkspaceContentLoad(load,error.message,continueCreate);
        else{finishWorkspaceContentLoad(load);dialog.showModal();$('asset-create-name').focus();}
        throw error;
      }
    };
    dialog.close();
    load=beginWorkspaceContentLoad(`Adding ${definition.label}…`,continueCreate);
    await continueCreate();
  }finally{button.disabled=false;}
});
assetRemove.onclick=guard(async()=>{
  if(!canRemoveAsset(state.asset)||state.asset.operation||state.asset.pending_path)return;
  if(dirty('asset')&&!window.confirm('Discard unsaved asset changes and remove this asset row?'))return;
  const selected=state.asset,request=assetRequest,zoneId=state.zoneId;assetRemove.disabled=true;
  try{
    await runScopedAssetMutation({message:'Removing asset…',selected,request,zoneId,
      postPath:'/api/asset/remove',body:{asset_id:selected.asset_id,revision:selected.revision},
      readBack:()=>api(`/api/asset?id=${encodeURIComponent(selected.asset_id)}`),
      refresh:async()=>{await loadAssets();await refreshWorkspaceTree();},
      apply:removed=>showAsset(removed),
      success:()=>'Removal queued. Cancel removal restores the source row; revision history is retained.'});
  }finally{assetRemove.disabled=state.buildActive||state.buildStarting||!!state.asset?.pending_path||assetLifecycleBusy;}
});
const imagePanel=element('div',undefined,'asset-image-editor');imagePanel.id='asset-image-editor';imagePanel.hidden=true;imagePanel.style.position='relative';imagePanel.style.minHeight='220px';
const imageTools=element('div',undefined,'image-tools'),imageImportLabel=element('label','Import PNG','image-import'),imageImport=element('input');
imageImport.type='file';imageImport.accept='image/png';imageImport.id='asset-image-import';imageImport.setAttribute('aria-label','Import PNG image');imageImportLabel.append(imageImport);
const imageDownload=element('a','Export PNG');imageDownload.id='asset-image-download';
const brushLabel=element('label','Paint color'),brushColor=element('input');brushColor.type='color';brushColor.value='#b47cdb';brushColor.id='asset-image-color';brushColor.setAttribute('aria-label','Paint color');brushLabel.append(brushColor);
const brushRadiusLabel=element('label','Brush'),brushRadius=element('input');brushRadius.type='range';brushRadius.min='1';brushRadius.max='64';brushRadius.value='4';brushRadius.id='asset-image-radius';brushRadius.setAttribute('aria-label','Brush size');brushRadiusLabel.append(brushRadius);
const imageUndo=element('button','Undo image edit'),imageSize=element('small');imageUndo.id='asset-image-undo';imageUndo.disabled=true;imageSize.id='asset-image-size';
const imageMipLabel=element('label','Mip levels'),imageMips=element('input');imageMips.type='number';imageMips.min='1';imageMips.max='16';imageMips.step='1';imageMips.value='1';imageMips.style.width='65px';imageMips.id='asset-image-mips';imageMips.setAttribute('aria-label','Image mip levels');imageMipLabel.append(imageMips);
const imageDdsImportLabel=element('label','Import whole-resource DDS','image-import'),imageDdsImport=element('input');imageDdsImport.type='file';imageDdsImport.accept='.dds,application/octet-stream';imageDdsImport.id='asset-dds-import';imageDdsImport.setAttribute('aria-label','Import whole-resource DDS');imageDdsImportLabel.append(imageDdsImport);
const imageDdsDownload=element('a','Export whole-resource DDS');imageDdsDownload.id='asset-dds-download';
const imageDdsMetadata=element('small');imageDdsMetadata.id='asset-dds-metadata';
const imagePngControls=[imageImportLabel,imageDownload,imageMipLabel,brushLabel,brushRadiusLabel,imageUndo,imageSize];
const imageDdsControls=[imageDdsImportLabel,imageDdsDownload,imageDdsMetadata];
imageTools.append(...imagePngControls,...imageDdsControls);
const imageCanvas=element('canvas');imageCanvas.id='asset-image-canvas';imageCanvas.setAttribute('aria-label','Editable image preview');
const imageView=element('div',undefined,'image-view');imageView.append(imageCanvas);
const imageLoadMask=element('div',undefined,'content-load-overlay'),imageLoadCard=element('div'),imageLoadSpinner=element('span',undefined,'content-load-spinner');
const imageLoadTitle=element('strong'),imageLoadDetail=element('p','The image editor will be available when its pixels and dimensions are ready.','muted'),imageLoadRetry=element('button','Retry','primary');
imageLoadMask.id='asset-image-content-load';imageLoadMask.hidden=true;imageLoadMask.tabIndex=-1;imageLoadMask.setAttribute('role','status');imageLoadMask.setAttribute('aria-live','assertive');imageLoadMask.setAttribute('aria-atomic','true');
imageLoadMask.style.cssText='position:absolute;inset:0;z-index:20;display:grid;place-items:center;padding:1rem;background:rgba(12,14,18,.94);color:inherit;text-align:center;';
imageLoadCard.style.cssText='display:grid;gap:.75rem;justify-items:center;max-width:32rem;';imageLoadSpinner.setAttribute('aria-hidden','true');
imageLoadRetry.hidden=true;imageLoadCard.append(imageLoadSpinner,imageLoadTitle,imageLoadDetail,imageLoadRetry);imageLoadMask.append(imageLoadCard);
imagePanel.append(imageTools,imageView,imageLoadMask);$('asset-package-status').after(imagePanel);
const soundPanel=element('div',undefined,'sound-editor');soundPanel.id='asset-sound-editor';soundPanel.hidden=true;soundPanel.style.position='relative';
const soundSelect=element('select');soundSelect.id='sound-entry';soundSelect.setAttribute('aria-label','Resident sound entry');
const soundNotice=element('p','Loading resident audio…','muted'),soundPlayer=element('audio');soundNotice.id='sound-notice';soundPlayer.controls=true;soundPlayer.preload='none';soundPlayer.id='sound-preview';
const soundExport=element('a','Export original PCM16 WAV');soundExport.id='sound-export';
const soundImportLabel=element('label','Replacement PCM16 WAV'),soundImport=element('input');soundImport.type='file';soundImport.accept='.wav,audio/wav';soundImport.id='sound-import';soundImportLabel.append(soundImport);
const soundSave=element('button','Save WAV edit','primary'),soundDiscard=element('button','Restore original audio');soundSave.id='sound-save';soundDiscard.id='sound-discard';soundDiscard.hidden=true;
const soundGainLabel=element('label','Volume (%)'),soundGain=element('input');soundGain.type='number';soundGain.min='0';soundGain.max='400';soundGain.step='5';soundGain.value='100';soundGain.id='sound-gain';soundGainLabel.append(soundGain);
const soundGainSave=element('button','Save volume edit');soundGainSave.id='sound-gain-save';
const soundActions=element('div',undefined,'sound-actions');soundActions.append(soundSave,soundDiscard);
const soundLoadMask=element('div',undefined,'content-load-overlay'),soundLoadCard=element('div'),soundLoadSpinner=element('span',undefined,'content-load-spinner');
const soundLoadTitle=element('strong'),soundLoadDetail=element('p'),soundLoadRetry=element('button','Retry','primary');
soundLoadMask.id='sound-content-load';soundLoadMask.hidden=true;soundLoadMask.tabIndex=-1;soundLoadMask.setAttribute('role','status');soundLoadMask.setAttribute('aria-live','assertive');soundLoadMask.setAttribute('aria-atomic','true');soundLoadSpinner.setAttribute('aria-hidden','true');soundLoadCard.append(soundLoadTitle,soundLoadDetail,soundLoadRetry);soundLoadMask.append(soundLoadSpinner,soundLoadCard);
soundPanel.append(soundSelect,soundNotice,soundPlayer,soundExport,soundImportLabel,soundActions,soundGainLabel,soundGainSave,soundLoadMask);$('asset-package-status').after(soundPanel);
let soundEntries=[],soundDrafts=[],soundSelection=null,soundBusy=false,soundMutationOwner=0,soundLoadOwner=0;
function resetSoundEditor(){soundLoadOwner++;soundLoadMask.hidden=true;soundLoadRetry.onclick=null;soundPanel.removeAttribute('aria-busy');for(const child of soundPanel.children)child.inert=false;soundSelection=null;soundEntries=[];soundDrafts=[];soundImport.value='';soundPanel.hidden=true;soundPlayer.pause();soundPlayer.removeAttribute('src');soundPlayer.load();}
function soundQuery(row){return `zone=${encodeURIComponent(row.zone_id)}&asset=${encodeURIComponent(row.asset_id)}&file=${row.file_id}`;}
function selectSound(){
  const row=soundEntries.find(item=>String(item.file_id)===soundSelect.value);soundSelection=row||null;
  soundImport.value='';soundPlayer.pause();soundPlayer.removeAttribute('src');soundPlayer.load();
  if(!row)return;
  const draft=soundDrafts.find(item=>item.file_id===row.file_id);row.revision=draft?.revision||null;
  const dimensions=draft?.authored_dimensions||row;
  soundNotice.textContent=`${dimensions.rate.toLocaleString()} Hz · ${dimensions.channels} channel${dimensions.channels===1?'':'s'} · ${(dimensions.frames/dimensions.rate).toFixed(2)} s. ${draft?'WAV edit saved; Compile game packages the replacement bank.':'Import a mono or stereo PCM16 WAV; its duration, sample rate and channel count will update the bank entry.'}`;
  const original=`/api/sound/wav?${soundQuery(row)}`;
  soundPlayer.src=original+(draft?`&draft=1&revision=${encodeURIComponent(draft.revision)}`:'');soundExport.href=soundPlayer.src+'&download=1';soundExport.download='';soundDiscard.hidden=!draft;
}
async function loadSoundEntries(asset,request){
  const owner=++soundLoadOwner;
  const isCurrent=()=>owner===soundLoadOwner&&request===assetRequest&&state.asset?.asset_id===asset.asset_id;
  soundPanel.hidden=false;$('asset-content').parentElement.hidden=!asset.editable;
  soundPanel.setAttribute('aria-busy','true');for(const child of soundPanel.children)if(child!==soundLoadMask)child.inert=true;
  soundLoadMask.hidden=false;soundLoadMask.dataset.failed='false';soundLoadTitle.textContent='Loading resident audio…';soundLoadDetail.textContent='The audio controls are unavailable until their checked entries load.';soundLoadRetry.hidden=true;soundLoadRetry.onclick=null;
  if(!asset.editable)soundLoadMask.focus?.();
  soundNotice.textContent='Checking the bank’s resident audio entries…';soundSelect.replaceChildren();
  try{
    const result=await api(`/api/sounds?path=${encodeURIComponent(state.zone.relative_path)}`);
    if(!isCurrent())return;
    if(!Array.isArray(result.entries)||!Array.isArray(result.drafts))throw new Error('The checked resident audio inventory is unavailable.');
    soundEntries=result.entries.filter(row=>row.asset_id===asset.asset_id);soundDrafts=result.drafts;
    soundSelect.replaceChildren(...soundEntries.map(row=>{const option=element('option',row.alias_name||row.asset_file_name);option.value=String(row.file_id);return option;}));
    if(!soundEntries.length){soundNotice.textContent='This bank has no resident codec-8 entries with an unambiguous editable alias.';soundExport.removeAttribute('href');soundSave.disabled=true;soundGainSave.disabled=true;}
    else{soundSave.disabled=false;soundGainSave.disabled=false;selectSound();}
    soundLoadMask.hidden=true;soundLoadRetry.onclick=null;soundPanel.removeAttribute('aria-busy');for(const child of soundPanel.children)child.inert=false;
  }catch(error){
    if(!isCurrent())return;
    soundLoadMask.dataset.failed='true';soundLoadTitle.textContent='Resident audio could not be loaded';soundLoadDetail.textContent=error.message;soundLoadRetry.hidden=false;soundLoadRetry.onclick=guard(()=>isCurrent()?loadSoundEntries(asset,request):undefined);if(!asset.editable)soundLoadRetry.focus?.();throw error;
  }
}
async function saveSound(action){
  if(!soundSelection||soundBusy||assetLifecycleBusy||assetSaveInFlight)return;
  const row=soundSelection,request=assetRequest,zoneId=state.zoneId,revision=row.revision;
  const owner=++soundMutationOwner;
  const body={zone_id:row.zone_id,asset_id:row.asset_id,file_id:row.file_id,revision};
  if(action==='save'){
    const file=soundImport.files[0];if(!file)throw new Error('Choose a replacement PCM16 WAV first.');
    if(file.size>90*1024*1024)throw new Error('Choose a WAV smaller than 90 MiB.');
  }else if(action==='gain')body.gain=Number(soundGain.value)/100;
  const isCurrent=()=>request===assetRequest&&soundSelection===row&&state.zoneId===zoneId&&
    state.asset?.asset_id===row.asset_id&&soundMutationOwner===owner;
  let accepted=false,acknowledgement=null,load=0;
  const release=()=>{if(soundMutationOwner!==owner)return;soundBusy=false;soundSave.disabled=state.buildActive||state.buildStarting||!soundSelection;
    soundGainSave.disabled=state.buildActive||state.buildStarting||!soundSelection;
    soundDiscard.disabled=state.buildActive||state.buildStarting||!soundSelection;};
  const refresh=async()=>{
    if(!isCurrent()||load!==workspaceContentLoadRequest){release();return;}
    try{
      const drafts=await api(`/api/sound/drafts?zone=${encodeURIComponent(row.zone_id)}`);
      if(!isCurrent()||load!==workspaceContentLoadRequest){release();return;}
      if(!Array.isArray(drafts.items))throw new Error('The resident audio draft list is unavailable.');
      if(acknowledgement?.zone_id!==row.zone_id||acknowledgement?.file_id!==row.file_id)
        throw new Error('The audio mutation acknowledgement does not match the selected resident file.');
      const matches=drafts.items.filter(item=>item.zone_id===row.zone_id&&item.file_id===row.file_id);
      if(action==='discard'){
        if(acknowledgement.discarded_revision!==revision||matches.length)
          throw new Error('The checked audio readback still contains the discarded revision.');
      }else if(typeof acknowledgement.revision!=='string'||!acknowledgement.revision||
               acknowledgement.asset_id!==row.asset_id||matches.length!==1||
               matches[0].revision!==acknowledgement.revision){
        throw new Error('The checked audio readback does not match the accepted resident-file revision.');
      }
      soundDrafts=drafts.items;selectSound();finishWorkspaceContentLoad(load);release();
      toast(action==='discard'?'Original audio restored; WAV revision history retained.':'Audio edit saved. Compile game includes its replacement bank.');
    }catch(error){
      if(!isCurrent()||load!==workspaceContentLoadRequest){release();return;}
      failWorkspaceContentLoad(load,error.message);throw error;
    }
  };
  soundBusy=true;soundSave.disabled=true;soundGainSave.disabled=true;soundDiscard.disabled=true;
  load=beginWorkspaceContentLoad(action==='discard'?'Restoring original audio…':'Saving resident audio…',refresh);
  try{
    if(action==='save'){
      const file=soundImport.files[0];
      const data=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=()=>reject(new Error('WAV import failed.'));reader.readAsDataURL(file);});
      if(!isCurrent()||load!==workspaceContentLoadRequest){release();return;}
      body.wav_base64=data.slice(data.indexOf(',')+1);
    }
    acknowledgement=await api('/api/sound/'+action,body);accepted=true;
    if(!isCurrent()||load!==workspaceContentLoadRequest){release();return;}
    await refresh();
  }catch(error){
    if(!accepted&&load===workspaceContentLoadRequest)finishWorkspaceContentLoad(load);
    if(!accepted)release();
    throw error;
  }
}
soundSelect.onchange=selectSound;soundSave.onclick=guard(()=>saveSound('save'));soundGainSave.onclick=guard(()=>saveSound('gain'));soundDiscard.onclick=guard(()=>saveSound('discard'));
let imageStroke=null,imageUndoContent=null;
async function importImageFile(file,selection){
  const token=beginImagePanelLoad('Loading imported PNG…');
  const fail=error=>{if(imageLoadCurrent(token))failImagePanelLoad(token,error,()=>importImageFile(file,selection));};
  try{
    if(!file||file.type!=='image/png'||file.size>32*1024*1024)throw new Error('Choose a PNG image smaller than 32 MiB.');
    const content=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=()=>reject(new Error('PNG import failed.'));reader.readAsDataURL(file);});
    if(!imageLoadCurrent(token)||selection.request!==assetRequest||selection.assetId!==state.asset?.asset_id)return;
    const image=await decodeImage(content);
    if(!imageLoadCurrent(token)||selection.request!==assetRequest||selection.assetId!==state.asset?.asset_id)return;
    if(!Number.isFinite(image.width)||!Number.isFinite(image.height)||image.width<1||image.height<1)throw new Error('The selected PNG has invalid dimensions.');
    const originalDimensions=state.asset.source?.typed_layout?.dimensions;
    if(!state.assetCodecs.image?.resident_resize&&originalDimensions&&(image.width!==originalDimensions[0]||image.height!==originalDimensions[1]))
      throw new Error(`This server supports ${originalDimensions[0]} × ${originalDimensions[1]} imports for this image.`);
    const previousContent=$('asset-content').value,previousLevels=imageMipCount(previousContent);
    const levels=Math.min(previousLevels,1+Math.floor(Math.log2(Math.max(image.width,image.height))));
    const imported=imageWithMips(content,levels);
    const commit=()=>{imageUndoContent=previousContent;imageUndo.disabled=false;setEditor('asset',imported,'plaintext',false);editorChanged('asset');};
    const ready=await renderAssetImage(imported,{token,decodedImage:image,commit,retry:()=>importImageFile(file,selection),message:'Loading imported PNG…'});
    if(ready&&levels!==previousLevels)toast(`Mip levels reduced to ${levels} to fit the imported ${image.width} × ${image.height} image.`);
  }catch(error){fail(error);}
}
imageImport.onchange=guard(()=>{
  const file=imageImport.files[0],selection={assetId:state.asset?.asset_id,request:assetRequest};imageImport.value='';
  if(!file||!state.asset?.editable||imageRenderBusy)return;
  return importImageFile(file,selection);
});
async function importDdsFile(file,selection){
  if(!file||!state.asset?.editable||imageRenderBusy)return;
  const token=beginImagePanelLoad('Loading imported resident DDS…');
  const fail=error=>{if(imageLoadCurrent(token))failImagePanelLoad(token,error,()=>importDdsFile(file,selection));};
  try{
    if(file.size<148||file.size>128*1024*1024)throw new Error('Choose a complete DDS smaller than 128 MiB.');
    const data=await new Promise((resolve,reject)=>{const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=()=>reject(new Error('DDS import failed.'));reader.readAsDataURL(file);});
    if(!imageLoadCurrent(token)||selection.request!==assetRequest||selection.assetId!==state.asset?.asset_id)return;
    const encoded=typeof data==='string'?data.slice(data.indexOf(',')+1):'';
    if(!encoded||atob(encoded.slice(0,12)).slice(0,4)!=='DDS ')
      throw new Error('The selected resource does not have a DDS header.');
    const previousContent=$('asset-content').value;
    const content='data:application/octet-stream;base64,'+encoded;
    setEditor('asset',content,'plaintext',false);editorChanged('asset');
    imageDdsDownload.href=content;imageDdsDownload.download=(state.asset.name.replace(/[^a-zA-Z0-9_.-]/g,'_')||'image')+'.dds';
    imageDdsMetadata.textContent='Imported DDS pending native descriptor validation on save.';
    imageUndoContent=previousContent;imageUndo.disabled=false;
    finishImagePanelLoad(token);
  }catch(error){fail(error);}
}
imageDdsImport.onchange=guard(()=>{
  const file=imageDdsImport.files[0],selection={assetId:state.asset?.asset_id,request:assetRequest};imageDdsImport.value='';
  if(!file||!state.asset?.editable||imageRenderBusy)return;
  return importDdsFile(file,selection);
});
imageMips.onchange=guard(()=>{
  if(!state.asset?.editable||imageRenderBusy)return;
  const previousContent=$('asset-content').value,levels=Number(imageMips.value),maximum=Number(imageMips.max);
  if(!Number.isInteger(levels)||levels<1||levels>maximum){imageMips.value=imageMipCount(previousContent);throw new Error(`Choose 1 to ${maximum} mip levels for this image.`);}
  const content=imageWithMips(previousContent,levels),token=beginImagePanelLoad('Updating image preview…');
  const commit=()=>{imageUndoContent=previousContent;imageUndo.disabled=false;setEditor('asset',content,'plaintext',false);editorChanged('asset');};
  return renderAssetImage(content,{token,commit,retry:()=>renderAssetImage(content,{message:'Updating image preview…',commit}),message:'Updating image preview…'});
});
function paintImage(event) {
  if(imageRenderBusy||!imageLoadCurrent(imageRenderToken)||!imageStroke||imageStroke.sequence!==imageRenderSequence)return;
  const bounds=imageCanvas.getBoundingClientRect(),x=(event.clientX-bounds.left)*imageCanvas.width/bounds.width,y=(event.clientY-bounds.top)*imageCanvas.height/bounds.height;
  const context=imageCanvas.getContext('2d');context.strokeStyle=brushColor.value;context.fillStyle=brushColor.value;context.lineWidth=Number(brushRadius.value)*2;context.lineCap='round';context.lineJoin='round';
  if(imageStroke.last){context.beginPath();context.moveTo(...imageStroke.last);context.lineTo(x,y);context.stroke();}
  else{context.beginPath();context.arc(x,y,Number(brushRadius.value),0,Math.PI*2);context.fill();}
  imageStroke.last=[x,y];
}
imageCanvas.onpointerdown=event=>{if(imageRenderBusy||!imageLoadCurrent(imageRenderToken)||!state.asset?.editable||event.button!==0)return;imageUndoContent=$('asset-content').value;imageUndo.disabled=false;imageStroke={identity:state.asset.asset_id,request:assetRequest,sequence:imageRenderSequence,last:null};imageCanvas.setPointerCapture(event.pointerId);paintImage(event);};
imageCanvas.onpointermove=event=>{if(imageStroke)paintImage(event);};
imageCanvas.onpointerup=imageCanvas.onpointercancel=()=>{if(!imageStroke)return;const stroke=imageStroke;imageStroke=null;if(imageRenderBusy||stroke.sequence!==imageRenderSequence||stroke.request!==assetRequest||state.asset?.asset_id!==stroke.identity)return;const content=imageWithMips(imageCanvas.toDataURL('image/png'),imageMipCount($('asset-content').value));setEditor('asset',content,'plaintext',false);imageDownload.href=imagePngData(content);editorChanged('asset');};
imageUndo.onclick=()=>{if(!imageUndoContent||imageRenderBusy)return;const content=imageUndoContent,token=beginImagePanelLoad('Restoring image edit…');const commit=()=>{imageUndoContent=null;imageUndo.disabled=true;setEditor('asset',content,'plaintext',false);editorChanged('asset');};if(state.asset?.language==='image/dds-base64'){commit();imageDdsDownload.href=content;return finishImagePanelLoad(token);}return renderAssetImage(content,{token,commit,retry:()=>renderAssetImage(content,{message:'Restoring image edit…',commit}),message:'Restoring image edit…'});};
assetDiscard.onclick=guard(async()=>{
  if(!state.asset?.pending_path)return;
  const selected=state.asset,request=assetRequest,zoneId=state.zoneId;
  const append=selected.operation==='append';
  await runScopedAssetMutation({message:append?'Cancelling asset creation…':'Restoring original asset…',
    selected,request,zoneId,postPath:'/api/asset/discard',
    body:{asset_id:selected.asset_id,revision:selected.revision},
    readBack:()=>append?Promise.resolve(null):api(`/api/asset?id=${encodeURIComponent(selected.asset_id)}`),
    refresh:async()=>{if(selected.operation){await loadAssets();await refreshWorkspaceTree();}},
    apply:original=>{if(append){state.asset=null;$('asset-editor').hidden=true;}else showAsset(original);},
    success:()=>append?'Creation cancelled; its source and immutable revision remain archived.':
      'Original asset restored; compiled edit remains in revision history.'});
});
$('new-source').onclick=()=>$('create-dialog').showModal();$('create-close').onclick=()=>$('create-dialog').close();
$('create-form').onsubmit=guard(async e=>{e.preventDefault();if(!canLeave())return;clearWorkspaceSelection();const s=await api('/api/source/create',{name:$('create-name').value,language:'cpp',content:$('create-content').value});$('create-dialog').close();await revealCreatedSource(s);await openSource(s.id,'cpp');toast('New function source added.');});
document.addEventListener('keydown',guard(async e=>{if(e.defaultPrevented||document.querySelector('dialog[open]'))return;if(!$('workspace-content-load').hidden){if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='s'){e.preventDefault();e.stopImmediatePropagation();}return;}if((e.ctrlKey||e.metaKey)&&!e.shiftKey&&e.key.toLowerCase()==='s'){e.preventDefault();e.stopImmediatePropagation();const active=document.querySelector('.workspace-editor-host')?.dataset.activeEditor;if(active==='source')await saveSource();if(active==='file')await saveFile();if(active==='asset')await saveAsset();return;}if(document.activeElement.closest('.monaco-host'))return;if(e.key==='/'&&!['TEXTAREA','INPUT','SELECT'].includes(document.activeElement.tagName)){if(state.page==='sources'){e.preventDefault();$('source-search').focus();}}}),true);
window.addEventListener('beforeunload',e=>{if(dirty('source')||dirty('file')||dirty('asset')){e.preventDefault();e.returnValue='';}});
async function initialize(){
  const navigation=pageRequest;
  const status=await api('/api/status');state.csrf=status.csrf;state.assetCodecs=status.asset_codecs||{};state.backendRestart=typeof status.backend?.restart_required!=='boolean'||status.backend.restart_required;state.buildActive=!!status.active_job;$('compile').disabled=state.buildStarting||state.buildActive||state.backendRestart;$('connection').textContent=state.backendRestart?'Backend restart required':'Local server online';$('function-count').textContent=status.functions.toLocaleString();$('symbol-count').textContent=status.symbols.toLocaleString();
  $('frontend-default').textContent=status.defaults?.frontend||'Not configured';
  $('animation-default').textContent=status.defaults?.animation?`Default motion · ${status.defaults.animation}`:'Project startup configuration';
  $('capabilities').replaceChildren(...Object.entries(status.asset_codecs).map(([name,c])=>{const div=element('div',undefined,'capability');div.append(element('strong',`${name.toUpperCase()} · ${c.status}`),element('span',c.reason||[c.decode,c.encode].filter(Boolean).join('. ')));return div;}));
  const details=[['Compiler project',status.project],['Game files',status.game],['SQLite reference',status.sqlite],['Persistent cache',status.cache],['Original image SHA256',status.image_sha256]];
  $('project-details').replaceChildren(...details.flatMap(([label,value])=>[element('dt',label),element('dd',value)]));
  state.files=(await api('/api/files')).items;
  const quick=state.files.filter(f=>['Dvar_Register','Com_FrontEnd','Com_Debug'].some(s=>f.name.startsWith(s))).slice(0,4);
  $('quick-files').replaceChildren(...quick.map(f=>{const b=element('button',f.name);b.onclick=guard(async()=>{if(await page('sources'))await openWorkspaceFile(f.path);});return b;}));
  const initial=location.hash.slice(1);if(navigation===pageRequest)await page(['overview','sources','files','assets','builds','settings'].includes(initial)?initial:'overview');
}
guard(initialize)();
initializeEditors();
setInterval(guard(async()=>{
  const jobs=(await api('/api/jobs')).items,active=jobs.find(j=>['queued','running'].includes(j.status));
  state.buildActive=!!active;
  const busy=state.buildStarting||state.buildActive||state.backendRestart;
  $('job-badge').textContent=state.buildStarting?'Checking native asset placement':active?active.phase:'Local workspace';$('compile').disabled=!state.csrf||busy;
  $('file-save').disabled=busy||state.file?.editable===false;$('source-save').disabled=busy||!state.source?.editable;$('new-source').disabled=busy;
  $('asset-save').disabled=busy||imageRenderBusy||!state.asset?.editable;
  $('asset-discard').disabled=busy;
  $('asset-recompile').disabled=busy;
  $('asset-remove').disabled=busy||!!state.asset?.pending_path;
  $('new-asset').disabled=busy||!state.zoneId;
  soundSave.disabled=busy||soundBusy||!soundSelection;soundGainSave.disabled=busy||soundBusy||!soundSelection;soundDiscard.disabled=busy||soundBusy;
  if(state.page==='builds'){renderJobList(jobs);if(state.job){const latest=jobs.find(j=>j.id===state.job.id);if(latest){state.job=latest;renderJob();await readLog();}}}
  if(state.page==='sources')await pollWorkspaceCatalog();
}),2200);
