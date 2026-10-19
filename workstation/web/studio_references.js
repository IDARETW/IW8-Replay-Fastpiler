/* Compact source context. All jumps use catalog identities and native open paths. */
(() => {
  'use strict';
  const cache=new Map(),pending=new Map(),registered=new WeakSet();let popupRequest=0;
  const make=(tag,text,className)=>element(tag,text,className);
  function action(text,label,run){const node=make('button',text);node.type='button';node.setAttribute('aria-label',label);node.onclick=guard(run);return node;}
  const popup=make('div',undefined,'studio-reference-popup');popup.id='studio-reference-popup';popup.setAttribute('popover','auto');popup.setAttribute('role','dialog');popup.setAttribute('aria-label','Symbol context');popup.tabIndex=-1;
  const header=make('div',undefined,'studio-reference-heading'),title=make('strong','Symbol context'),body=make('div',undefined,'studio-reference-body');
  header.append(title,action('×','Close symbol context',()=>popup.hidePopover()));popup.append(header,body);document.body.append(popup);
  const toolbar=document.querySelector('.studio-tools > div'),refsButton=action('Refs','Show symbol context and cross-references · Ctrl Shift R',()=>showContext());toolbar.append(refsButton);
  const editorHost=document.querySelector('.workspace-editor-host');
  function updateEnabled(){refsButton.disabled=!['source','file','asset'].includes(editorHost.dataset.activeEditor);}
  new MutationObserver(updateEnabled).observe(editorHost,{attributes:true,attributeFilter:['data-active-editor']});updateEnabled();

  async function context(query){
    const key=query.id?'id:'+query.id:'q:'+query.q,cached=cache.get(key);
    if(cached&&Date.now()-cached.time<30000)return cached.value;
    if(pending.has(key))return pending.get(key);
    const request=api('/api/source/context?'+new URLSearchParams({...query,limit:'12'})).then(value=>{
      cache.set(key,{time:Date.now(),value});if(cache.size>100)cache.delete(cache.keys().next().value);return value;
    }).finally(()=>pending.delete(key));pending.set(key,request);return request;
  }
  function selection(kind){
    const selected=state[kind],editor=editors[kind],word=editor?.getModel()?.getWordAtPosition(editor.getPosition())?.word;
    if(word&&word.length<=256)return {q:word};
    if(kind==='source'&&selected?.id)return {id:selected.id};
    return {q:selected?.name||''};
  }
  function activeKind(){return document.querySelector('.workspace-editor-host')?.dataset.activeEditor;}
  function anchor(kind){
    const editor=editors[kind],position=editor?.getScrolledVisiblePosition(editor.getPosition()),bounds=editor?.getDomNode()?.getBoundingClientRect();
    return bounds&&position?{x:bounds.left+position.left,y:bounds.top+position.top+position.height+6}:{x:document.querySelector('.studio-tools')?.getBoundingClientRect().left||20,y:150};
  }
  function positionPopup(point){
    const width=Math.min(600,document.documentElement.clientWidth-24),height=Math.min(520,document.documentElement.clientHeight-32);
    popup.style.width=width+'px';popup.style.maxHeight=height+'px';popup.style.left=Math.max(12,Math.min(point.x,document.documentElement.clientWidth-width-12))+'px';
    popup.style.top=Math.max(12,Math.min(point.y,document.documentElement.clientHeight-height-16))+'px';
  }
  async function openIdentity(row,variant='cpp'){
    if(!row.id||!canLeave())return;if(popup.matches(':popover-open'))popup.hidePopover();
    if(state.page!=='sources'&&!await page('sources'))return;
    clearWorkspaceSelection();workspaceTree.active='source:'+row.id;await openSource(row.id,variant,true);
  }
  function searchWorkspaceFor(query){popup.hidePopover();openWorkspaceSearch();$('workspace-query').value=query;searchWorkspace();}
  async function showContext(kind=activeKind(),explicit=null){
    if(!['source','file','asset'].includes(kind)||!$('workspace-content-load').hidden)return;
    const query=explicit||selection(kind),request=++popupRequest;
    title.textContent=query.q||state[kind]?.name||'Symbol context';body.replaceChildren(make('p','Loading checked symbol context…','muted'));body.setAttribute('aria-busy','true');
    positionPopup(anchor(kind));if(!popup.matches(':popover-open'))popup.showPopover();popup.focus();
    try{const value=await context(query);if(request!==popupRequest||!popup.matches(':popover-open'))return;body.removeAttribute('aria-busy');renderContext(value,query,request);}
    catch(error){if(request!==popupRequest)return;body.removeAttribute('aria-busy');body.replaceChildren(make('p',error.message,'studio-conflict'),action('Retry','Retry symbol context',()=>showContext(kind,query)));}
  }
  function renderContext(value,query,request){
    body.replaceChildren();
    if(!value.subject){
      body.append(make('p',value.match_count?'Choose a catalog identity for this name.':'No exact engine symbol was resolved. Search the workspace for related code and assets.','muted'));
      for(const row of value.matches){const node=action(row.name,'Inspect '+row.name,()=>showContext(activeKind(),{id:row.id}));node.className='studio-reference-row';node.append(make('small',`${row.kind} · ${row.id}`));body.append(node);}
      body.append(action('Search workspace','Search workspace for this word',()=>searchWorkspaceFor(query.q||query.id||'')));return;
    }
    const subject=value.subject;title.textContent=subject.name;
    body.append(make('div',`${subject.kind} · ${subject.bytes??'?'} bytes · original RVA 0x${subject.rva.toString(16)}`,'studio-reference-meta'));
    if(subject.prototype)body.append(make('pre',subject.prototype,'studio-reference-prototype'));
    const controls=make('div',undefined,'studio-reference-actions');controls.append(action('Open source','Open catalog source for '+subject.name,()=>openIdentity(subject)));
    controls.append(action('Copy identity','Copy stable catalog identity',async()=>{await navigator.clipboard.writeText(subject.id);toast('Catalog identity copied.');}));body.append(controls);
    const groups=make('div',undefined,'studio-reference-groups');
    for(const [key,label] of [['caller','Called by'],['callee','Calls'],['inbound','Recorded inbound references'],['outbound','Recorded outbound references']]){
      const group=value.groups[key];if(!group||(!group.total&&['inbound','outbound'].includes(key)))continue;
      const section=make('section'),heading=make('h4',`${label} · ${group.total}`),list=make('div');section.append(heading,list);
      const renderRows=items=>{list.replaceChildren();if(!items.length)list.append(make('p','No recorded entries.','muted'));for(const row of items){const node=action(row.name,'Open reference '+row.name,()=>openIdentity(row));node.className='studio-reference-row';node.disabled=!row.id;node.title=row.instruction||row.id||'No unique catalog identity';if(row.site_rva!==undefined)node.append(make('small',`${row.relation} · site 0x${row.site_rva.toString(16)} · ${row.instruction}`));list.append(node);}};renderRows(group.items);
      if(group.total>group.limit){let offset=0;const paging=make('div',undefined,'studio-reference-pagination'),range=make('small'),prev=action('←','Previous '+label,()=>move(-group.limit)),next=action('→','Next '+label,()=>move(group.limit));paging.append(prev,range,next);section.append(paging);
        function update(){range.textContent=`${offset+1}–${Math.min(offset+group.limit,group.total)} of ${group.total}`;prev.disabled=offset===0;next.disabled=offset+group.limit>=group.total;}
        async function move(delta){const target=Math.max(0,offset+delta);prev.disabled=next.disabled=true;list.inert=true;list.setAttribute('aria-busy','true');try{const page=await api('/api/source/context?'+new URLSearchParams({id:subject.id,offset:String(target),limit:String(group.limit)}));if(request!==popupRequest||!popup.matches(':popover-open'))return;offset=target;renderRows(page.groups[key]?.items||[]);}finally{list.inert=false;list.removeAttribute('aria-busy');update();}}update();
      }
      groups.append(section);
    }body.append(groups);
    body.append(make('p',value.coverage+' Prototypes are recovered analysis.','studio-reference-footnote'));
  }
  function markdown(text){return String(text).replace(/[\\`*_{}\[\]<>]/g,'\\$&');}
  function installHover(){
    if(installHover.done||!window.monaco)return;installHover.done=true;
    const provider={provideHover:async(model,position,token)=>{
      const word=model.getWordAtPosition(position);if(!word||word.word.length>256||!/^(?:[A-Z_][A-Za-z0-9_]{2,}|[a-zA-Z]+_[A-Za-z0-9_]+)$/.test(word.word))return null;
      try{const result=await context({q:word.word});if(token.isCancellationRequested||!result.subject)return null;const subject=result.subject;
        const totals=['caller','callee'].filter(key=>result.groups[key]).map(key=>`${result.groups[key].total} ${key==='caller'?'recorded callers':'recorded callees'}`).join(' · ');
        const contents=[{value:`**${markdown(subject.name)}** · ${markdown(subject.kind)}\n\n${totals}\n\n\`Ctrl Shift R\` opens references. \`F12\` opens the catalog source.`,isTrusted:false,supportHtml:false}];
        if(subject.prototype)contents.splice(1,0,{value:'```cpp\n'+subject.prototype.replace(/`/g,'')+'\n```',isTrusted:false,supportHtml:false});
        return {range:new monaco.Range(position.lineNumber,word.startColumn,position.lineNumber,word.endColumn),contents};
      }catch{return null;}
    }};
    for(const language of ['cpp','c','gsc','lua','replay-asm','plaintext','json','ini'])monaco.languages.registerHoverProvider(language,provider);
  }
  function editorReady(kind,editor){
    if(registered.has(editor)||!window.monaco)return;registered.add(editor);installHover();
    editor.addAction({id:'replay.symbolContext',label:'Symbol context and cross-references',keybindings:[monaco.KeyMod.CtrlCmd|monaco.KeyMod.Shift|monaco.KeyCode.KeyR],contextMenuGroupId:'navigation',contextMenuOrder:1,run:()=>showContext(kind)});
    editor.addAction({id:'replay.goToCatalogSource',label:'Go to catalog source',keybindings:[monaco.KeyCode.F12],contextMenuGroupId:'navigation',contextMenuOrder:2,run:async()=>{
      const model=editor.getModel(),version=model.getVersionId(),position=editor.getPosition(),query=selection(kind),value=await context(query);
      const current=editor.getPosition();if(activeKind()!==kind||editor.getModel()!==model||model.getVersionId()!==version||current.lineNumber!==position.lineNumber||current.column!==position.column)return;
      if(value.subject)await openIdentity(value.subject);else await showContext(kind,query);
    }});
  }
  window.ReplayStudioReferences={editorReady};for(const [kind,editor] of Object.entries(editors))editorReady(kind,editor);
  window.ReplayStudio?.registerCommand('Symbol context and cross-references','Ctrl Shift R',()=>showContext());
  popup.addEventListener('toggle',event=>{if(event.newState==='closed')popupRequest++;});
})();
