/* Editor presentation and in-memory working tabs. Native edits still use app.js. */
(() => {
  'use strict';
  const documents = new Map(), scratch = {}, host = document.querySelector('.workspace-editor-host');
  const sources = $('sources'), split = sources.querySelector('.split');
  let active = null, restoring = false, diff = null, diffModels = [], staged = [], stagedTotal = 0;
  let reviewRequest = 0, drawerPage = 'changes', preferences;
  try { preferences = JSON.parse(localStorage.getItem('replay.editorPreferences') || '{}'); } catch { preferences = {}; }
  preferences = {fontSize:13, wordWrap:false, minimap:false, lineNumbers:true, inspector:true, ...preferences};
  preferences.fontSize = Math.max(10, Math.min(22, Number(preferences.fontSize) || 13));
  const create = (tag, text, className) => element(tag, text, className);
  function button(text, label, action, className = '') {
    const node = create('button', text, className); node.type = 'button'; node.title = label;
    node.setAttribute('aria-label', label); node.onclick = guard(action); return node;
  }
  const tabs = create('div', undefined, 'studio-tabs'); tabs.id = 'studio-tabs'; tabs.setAttribute('role','tablist'); tabs.setAttribute('aria-label','Open documents');
  const tools = create('div', undefined, 'studio-tools'), toolLeft = create('div'), toolRight = create('div');
  const toolStatus = create('span', 'Select a document', 'studio-tool-status');
  const undo = button('↶', 'Undo in active editor · Ctrl Z', () => editorCommand('undo'));
  const redo = button('↷', 'Redo in active editor · Ctrl Y', () => editorCommand('redo'));
  const find = button('Find', 'Find or replace in the active editor · Ctrl F', () => editorAction('actions.find'));
  const edit = button('Edit', 'Editing controls: replace, jump to line, comments and folding', showEditingControls);
  const wrap = button('Wrap', 'Toggle word wrap', () => { preferences.wordWrap = !preferences.wordWrap; applyPreferences(); });
  const compare = button('Compare', 'Compare working content with its saved version', review);
  const copy = button('Copy path', 'Copy the active file path or asset identity', async () => {
    const doc = current(); if (!doc) return; await navigator.clipboard.writeText(doc.path); toast('Document path copied.');
  });
  const settings = button('Aa', 'Editor preferences · Ctrl ,', () => preferenceDialog.showModal());
  const inspectorToggle = button('Details', 'Show document inspector · Ctrl Alt B', showInspector);
  const tabActions = button('⋯', 'Manage open tabs', showTabActions);
  toolLeft.append(undo, redo, find, edit, wrap, compare); toolRight.append(toolStatus, copy, settings, inspectorToggle, tabActions); tools.append(toolLeft, toolRight);
  host.prepend(tabs, tools);

  // Canvas coordinates already account for its displayed size in app.js. These
  // controls change presentation only, leaving decoded pixels and native saves intact.
  let imageTool='brush', imagePan=null;
  const imageNavigation=create('div',undefined,'studio-image-navigation');
  const imageBrush=button('Brush','Paint image',()=>setImageTool('brush'));
  const imageHand=button('Pan','Pan image without painting · hold Alt for temporary pan',()=>setImageTool('pan'));
  const imageZoom=create('select'),imageZoomLabel=create('label','Zoom');imageZoom.setAttribute('aria-label','Image preview zoom');
  for(const [value,label] of [['fit','Fit'],['0.25','25%'],['0.5','50%'],['1','100%'],['2','200%'],['4','400%'],['8','800%']]){const option=create('option',label);option.value=value;imageZoom.append(option);}
  imageZoomLabel.append(imageZoom);imageZoom.onchange=resizeImage;
  imageNavigation.append(imageBrush,imageHand,imageZoomLabel);imageView.before(imageNavigation);imageView.classList.add('studio-image-view');
  imagePngControls.push(imageNavigation);
  function setImageTool(value){imageTool=value;imageBrush.setAttribute('aria-pressed',String(value==='brush'));imageHand.setAttribute('aria-pressed',String(value==='pan'));imageCanvas.classList.toggle('studio-image-pan',value==='pan');}
  function resizeImage(){
    if(!imageCanvas.width||!imageCanvas.height)return;
    const zoom=imageZoom.value==='fit'?Math.min(1,Math.max(0.01,(imageView.clientWidth-36)/imageCanvas.width)):Number(imageZoom.value);
    imageCanvas.style.width=Math.max(1,imageCanvas.width*zoom)+'px';imageCanvas.style.height=Math.max(1,imageCanvas.height*zoom)+'px';
  }
  new MutationObserver(resizeImage).observe(imageCanvas,{attributes:true,attributeFilter:['width','height']});
  new ResizeObserver(()=>{if(imageZoom.value==='fit')resizeImage();}).observe(imageView);
  imageCanvas.addEventListener('pointerdown',event=>{
    if(event.button!==0||imageRenderBusy||!imageLoadCurrent(imageRenderToken)||!(imageTool==='pan'||event.altKey))return;
    event.preventDefault();event.stopImmediatePropagation();imagePan={id:event.pointerId,x:event.clientX,y:event.clientY,left:imageView.scrollLeft,top:imageView.scrollTop};imageCanvas.setPointerCapture(event.pointerId);
  },true);
  imageCanvas.addEventListener('pointermove',event=>{if(!imagePan||event.pointerId!==imagePan.id)return;event.preventDefault();event.stopImmediatePropagation();imageView.scrollLeft=imagePan.left+imagePan.x-event.clientX;imageView.scrollTop=imagePan.top+imagePan.y-event.clientY;},true);
  for(const name of ['pointerup','pointercancel','lostpointercapture'])imageCanvas.addEventListener(name,event=>{if(!imagePan||event.pointerId!==imagePan.id)return;event.stopImmediatePropagation();imagePan=null;},true);
  setImageTool('brush');

  const inspector = create('aside', undefined, 'studio-inspector'); inspector.setAttribute('aria-label','Document inspector');
  const inspectorHeading = create('div',undefined,'studio-section-title'); inspectorHeading.append(create('strong','Inspector'), button('×','Close inspector',() => {preferences.inspector=false;applyPreferences();}));
  const inspectorBody = create('div',undefined,'studio-inspector-body'); inspector.append(inspectorHeading,inspectorBody); split.append(inspector);

  const statusBar = create('footer',undefined,'studio-statusbar'), connection = create('span','Local server','studio-connection');
  const statusItem = create('span','IW8 workspace'), unsavedItem = create('span','All working tabs saved');
  const drawerToggle = button('Changes & output','Toggle changes and output · Ctrl Shift D',() => toggleDrawer());
  const commandsToggle = button('Commands','Editor commands · Ctrl Shift P',() => commandDialog.showModal());
  statusBar.append(connection,statusItem,unsavedItem,commandsToggle,drawerToggle); document.body.append(statusBar);
  const drawer = create('section',undefined,'studio-drawer'); drawer.hidden=true; drawer.setAttribute('aria-label','Changes and output');
  const drawerHeading=create('div',undefined,'studio-drawer-heading'), drawerTabs=create('div');
  const changesTab=button('Changes','Show working and staged changes',()=>setDrawerPage('changes'));
  const outputTab=button('Build output','Show current build output',()=>setDrawerPage('output'));
  drawerTabs.append(changesTab,outputTab); drawerHeading.append(drawerTabs,button('×','Close changes and output',()=>toggleDrawer(false)));
  const drawerContent=create('div',undefined,'studio-drawer-content'); drawer.append(drawerHeading,drawerContent); document.body.append(drawer);
  const outputPanel=create('div',undefined,'studio-output-panel'),outputHeading=create('div',undefined,'studio-output-heading'),outputControls=create('div',undefined,'studio-output-controls'),outputLog=create('pre',undefined,'studio-output-log');let followOutput=true;
  const outputFollow=button('Follow output','Toggle automatic scrolling to the latest build output',()=>{followOutput=!followOutput;outputFollow.setAttribute('aria-pressed',String(followOutput));if(followOutput)outputLog.scrollTop=outputLog.scrollHeight;});outputFollow.setAttribute('aria-pressed','true');
  outputControls.append(outputFollow,button('Copy log','Copy the currently loaded build log',async()=>{await navigator.clipboard.writeText($('build-log').textContent);toast('Loaded build log copied.');}),button('Full build details','Open receipts and artifacts for the selected build',()=>page('builds')));outputPanel.append(outputHeading,outputControls,outputLog);

  function dialog(title, className) {
    const modal=create('dialog',undefined,'studio-dialog '+className), heading=create('div',undefined,'studio-dialog-heading');
    heading.append(create('h2',title),button('×','Close '+title,()=>modal.close())); modal.append(heading); document.body.append(modal); return modal;
  }
  const inspectorDialog=dialog('Document details','studio-details'), mobileDetails=create('div',undefined,'studio-inspector-body');inspectorDialog.append(mobileDetails);
  function showInspector(){
    if(matchMedia('(max-width:1100px)').matches){renderInspector();mobileDetails.replaceChildren(inspectorBody.cloneNode(true));for(const node of mobileDetails.querySelectorAll('button'))node.remove();inspectorDialog.showModal();}
    else{preferences.inspector=!preferences.inspector;applyPreferences();}
  }
  const editingDialog=dialog('Editing controls','studio-editing'),editingList=create('div',undefined,'studio-command-list');editingDialog.append(editingList);
  const editingDefinitions=[
    ['Undo','Ctrl Z',()=>editorCommand('undo'),true],['Redo','Ctrl Y',()=>editorCommand('redo'),true],
    ['Find in document','Ctrl F',()=>editorAction('actions.find')],['Replace in document','Ctrl H',()=>editorAction('editor.action.startFindReplaceAction'),true],
    ['Go to line','Ctrl G',showGoToLine],['Toggle line comment','Ctrl /',()=>editorAction('editor.action.commentLine'),true],
    ['Fold all','',()=>editorAction('editor.foldAll')],['Unfold all','',()=>editorAction('editor.unfoldAll')],
    ['Select all','Ctrl A',()=>editorCommand('editor.action.selectAll')],
  ];
  function showEditingControls(){
    const doc=current(),isText=doc&&!doc.language.startsWith('image/');
    editingList.replaceChildren(...editingDefinitions.map(([name,key,action,mutates])=>{
      const node=button(name,name,async()=>{editingDialog.close();await action();},'studio-command');if(key)node.append(create('kbd',key));
      node.disabled=!isText||(mutates&&state[doc.kind]?.editable===false)||!!doc?.conflict||(name==='Undo'&&!editors[doc.kind]?.getModel()?.canUndo())||(name==='Redo'&&!editors[doc.kind]?.getModel()?.canRedo());return node;
    }));editingDialog.showModal();
  }
  const lineDialog=dialog('Go to line','studio-go-line'),lineForm=create('form'),lineInput=create('input'),lineLabel=create('label','Line'),lineHint=create('p',undefined,'muted');
  lineInput.type='number';lineInput.min='1';lineInput.required=true;lineInput.setAttribute('aria-label','Line number');lineLabel.append(lineInput);
  const lineGo=create('button','Go','primary');lineGo.type='submit';lineForm.append(lineLabel,lineHint,lineGo);lineDialog.append(lineForm);
  function showGoToLine(){
    const doc=current(),editor=doc&&editors[doc.kind];if(!editor||busy())return;
    lineInput.max=editor.getModel().getLineCount();lineInput.value=editor.getPosition()?.lineNumber||1;lineHint.textContent=`${doc.name} · ${lineInput.max} lines`;lineDialog.showModal();lineInput.focus();lineInput.select();
  }
  lineForm.onsubmit=guard(event=>{event.preventDefault();const doc=current(),editor=doc&&editors[doc.kind],line=Number(lineInput.value);if(!editor||!Number.isSafeInteger(line)||line<1||line>editor.getModel().getLineCount())throw new Error('Choose a line in this document.');lineDialog.close();editor.setPosition({lineNumber:line,column:1});editor.revealLineInCenter(line);editor.focus();});
  const tabDialog=dialog('Open tabs','studio-open-tabs'),tabList=create('div',undefined,'studio-command-list'),tabButtons=create('div',undefined,'studio-tab-actions');
  tabButtons.append(button('Save all','Save all working tabs',async()=>{tabDialog.close();await saveAll();}),button('Close saved tabs','Close saved tabs and keep unsaved work',async()=>{tabDialog.close();await closeDocuments(doc=>doc.buffer===doc.saved&&!doc.conflict);}),button('Close other tabs','Close all tabs except the active document',async()=>{tabDialog.close();await closeDocuments(doc=>doc.key!==active);}));tabDialog.append(tabButtons,tabList);
  function showTabActions(){capture();tabList.replaceChildren(...[...documents.values()].map(doc=>{const node=button(doc.name,'Open '+doc.name,async()=>{tabDialog.close();await navigate(doc);},'studio-command');if(doc.buffer!==doc.saved||doc.conflict)node.append(create('small','Unsaved'));return node;}));if(!documents.size)tabList.append(create('p','No open documents.','muted'));tabDialog.showModal();}
  async function closeDocuments(predicate){for(const doc of [...documents.values()].filter(predicate)){if(!await closeDocument(doc))break;}}
  async function nextTab(direction){const docs=[...documents.values()];if(!docs.length)return;const index=docs.findIndex(doc=>doc.key===active);await navigate(docs[(Math.max(0,index)+direction+docs.length)%docs.length]);}
  const discardDialog=dialog('Unsaved working buffer','studio-discard'),discardNote=create('p'),discardActions=create('div',undefined,'studio-tab-actions');let discardResolve=null;
  const keepBuffer=button('Keep editing','Keep this working buffer',()=>{discardResolve?.(false);discardResolve=null;discardDialog.close();});
  const discardBuffer=button('Discard buffer','Discard only this unsaved working buffer',()=>{discardResolve?.(true);discardResolve=null;discardDialog.close();},'primary');
  discardActions.append(keepBuffer,discardBuffer);discardDialog.append(discardNote,discardActions);
  discardDialog.addEventListener('close',()=>{discardResolve?.(false);discardResolve=null;});
  function confirmDiscard(doc){if(discardResolve)return Promise.resolve(false);discardNote.textContent=`Discard the unsaved working buffer for ${doc.name}? The saved version and its revision history remain available.`;discardDialog.showModal();keepBuffer.focus();return new Promise(resolve=>{discardResolve=resolve;});}
  const preferenceDialog=dialog('Editor preferences','studio-preferences');
  const preferenceNote=create('p','Preferences are saved in this browser. Working buffers stay in memory until you save or close them.','muted'); preferenceDialog.append(preferenceNote);
  for (const [key,label] of [['wordWrap','Wrap long lines'],['minimap','Show minimap'],['lineNumbers','Show line numbers'],['inspector','Show document inspector']]) {
    const row=create('label',undefined,'studio-preference'), input=create('input'); input.type='checkbox'; input.checked=!!preferences[key]; input.dataset.preference=key;
    input.onchange=()=>{preferences[key]=input.checked;applyPreferences();}; row.append(create('span',label),input); preferenceDialog.append(row);
  }
  const fontRow=create('label',undefined,'studio-preference'), font=create('input'); font.type='number'; font.min='10';font.max='22';font.value=preferences.fontSize;
  font.setAttribute('aria-label','Editor font size');font.onchange=()=>{preferences.fontSize=Math.max(10,Math.min(22,Number(font.value)||13));font.value=preferences.fontSize;applyPreferences();};
  fontRow.append(create('span','Font size'),font);preferenceDialog.append(fontRow);
  preferenceDialog.append(button('Reset preferences','Reset editor preferences',()=>{Object.assign(preferences,{fontSize:13,wordWrap:false,minimap:false,lineNumbers:true,inspector:true});font.value=13;applyPreferences();}));

  const reviewDialog=dialog('Compare with saved content','studio-review'), reviewBody=create('div',undefined,'studio-review-body');
  const reviewLabels=create('div',undefined,'studio-review-labels');reviewLabels.append(create('span','Saved content'),create('span','Working buffer'));
  const reviewFooter=create('div',undefined,'studio-review-footer'), applyRetained=button('Use retained buffer','Apply the retained buffer after reviewing the changed saved revision',()=>{
    const doc=current();if(!doc||!doc.conflict)return;doc.conflict=false;restore(doc);reviewDialog.close();render();
  },'primary');applyRetained.hidden=true;reviewFooter.append(create('span','This view is read-only. It does not save or compile changes.'),applyRetained);
  reviewDialog.append(reviewLabels,reviewBody,reviewFooter);
  function disposeDiff(){diff?.dispose();diff=null;for(const model of diffModels)model.dispose();diffModels=[];}
  reviewDialog.addEventListener('close',disposeDiff);

  const commandDialog=dialog('Editor commands','studio-commands'), commandInput=create('input'), commandList=create('div',undefined,'studio-command-list');
  commandInput.placeholder='Find a command…';commandInput.setAttribute('aria-label','Filter editor commands');commandDialog.append(commandInput,commandList);
  const commandDefinitions=[
    ['Find a file or asset','Ctrl K',()=>openWorkspaceSearch()],
    ['Save active document','Ctrl S',()=>saveCurrent()],
    ['Save all working tabs','Ctrl Shift S',()=>saveAll()],
    ['Undo','Ctrl Z',()=>editorCommand('undo')],
    ['Redo','Ctrl Y',()=>editorCommand('redo')],
    ['Go to line','Ctrl G',showGoToLine],
    ['Toggle line comment','Ctrl /',()=>editorAction('editor.action.commentLine')],
    ['Fold all','',()=>editorAction('editor.foldAll')],
    ['Unfold all','',()=>editorAction('editor.unfoldAll')],
    ['Manage open tabs','',showTabActions],
    ['Next open tab','',()=>nextTab(1)],
    ['Previous open tab','',()=>nextTab(-1)],
    ['Close saved tabs','',()=>closeDocuments(doc=>doc.buffer===doc.saved&&!doc.conflict)],
    ['Compare with saved content','',review],
    ['Find in editor','Ctrl F',()=>editorAction('actions.find')],
    ['Replace in editor','Ctrl H',()=>editorAction('editor.action.startFindReplaceAction')],
    ['Toggle word wrap','',()=>{preferences.wordWrap=!preferences.wordWrap;applyPreferences();}],
    ['Toggle IW8 Explorer','Ctrl Shift E',()=>$('iw8-explorer-toggle')?.click()],
    ['Show document inspector','Ctrl Alt B',showInspector],
    ['Show changes','Ctrl Shift D',()=>{toggleDrawer(true);setDrawerPage('changes');}],
    ['Show build output','',()=>{toggleDrawer(true);setDrawerPage('output');}],
    ['Review and compile game','',showBuildReview],
    ['Editor preferences','Ctrl ,',()=>preferenceDialog.showModal()],
    ['Reset pane layout','',()=>{localStorage.removeItem('replay.explorerWidth');$('iw8-explorer-divider')?.dispatchEvent(new MouseEvent('dblclick'));preferences.inspector=true;applyPreferences();}],
  ];
  function renderCommands(){commandList.replaceChildren(...commandDefinitions.filter(([name])=>name.toLowerCase().includes(commandInput.value.toLowerCase())).map(([name,key,action])=>{
    const node=button(name,name,async()=>{commandDialog.close();await action();},'studio-command');if(key)node.append(create('kbd',key));return node;
  }));}
  commandInput.oninput=renderCommands;renderCommands();
  commandDialog.addEventListener('keydown',event=>{
    const buttons=[...commandList.children],index=buttons.indexOf(document.activeElement);
    if(['ArrowDown','ArrowUp'].includes(event.key)){event.preventDefault();buttons[(index+(event.key==='ArrowDown'?1:-1)+buttons.length)%buttons.length]?.focus();}
    if(event.key==='Enter'&&document.activeElement===commandInput){event.preventDefault();buttons[0]?.click();}
  });

  const buildDialog=dialog('Compile game','studio-build-review'), buildNote=create('p',undefined,'muted'), buildSummary=create('div',undefined,'studio-build-summary');
  const buildProfile=$('build-profile').cloneNode(true);buildProfile.id='studio-build-profile';buildProfile.setAttribute('aria-label','Compilation content');
  const buildConfirm=button('Compile and verify','Start fresh compilation and verification',async()=>{
    if(hasUnsaved())throw new Error('Save or close the unsaved working tabs first.');
    $('build-profile').value=buildProfile.value;buildDialog.close();await compile();
  },'primary');buildDialog.append(buildNote,buildProfile,buildSummary,buildConfirm);
  const compileButton=$('compile');compileButton.onclick=guard(showBuildReview);

  function info(kind,value=state[kind]){
    if(!value||!['source','file','asset'].includes(kind))return null;
    const id=kind==='asset'?value.asset_id:kind==='file'?value.path:value.id;
    return {key:kind+':'+id+(kind==='source'?':'+value.variant:''),kind,id,variant:value.variant,name:value.name||id,
      path:value.path||value.name||id,content:value.content??'',revision:value.revision,language:value.language||'plaintext',
      value,selection:workspaceTree.active,zone:state.zone,zoneId:state.zoneId};
  }
  function current(){return active?documents.get(active):null;}
  function busy(){return !$('workspace-content-load').hidden;}
  function capture(){
    const doc=current();if(!doc||busy()||restoring)return;
    const selected=info(doc.kind);if(selected?.key!==doc.key)return;
    if(doc.conflict)return;
    doc.buffer=$(`${doc.kind}-content`).value;
    if(editors[doc.kind]&&doc.model===editors[doc.kind].getModel())doc.position=editors[doc.kind].saveViewState();
  }
  function preserveWorkingBuffers(){
    if($('sound-import')?.files.length)return false;
    capture();return true;
  }
  function hasUnsaved(){capture();return [...documents.values()].some(doc=>doc.buffer!==doc.saved||doc.conflict)||!!$('sound-import')?.files.length;}
  function loading(){
    capture();imagePan=null;restoring=true;
    for(const [kind,editor] of Object.entries(editors)){
      if(!scratch[kind])scratch[kind]=window.monaco.editor.createModel('', 'plaintext');
      if(editor.getModel()!==scratch[kind])editor.setModel(scratch[kind]);
    }
    restoring=false;inspectorBody.replaceChildren(create('p','Checking selected content…','muted'));
  }
  function cleared(){capture();loading();active=null;render();}
  function assertCanSave(kind){
    const doc=current();if(doc?.kind===kind&&doc.conflict)throw new Error('Review the changed saved revision before applying this retained buffer.');
  }
  // These acknowledgements are called only by the existing checked save/readback paths.
  // A background save can finish after navigation; retain any work typed since submission.
  function accepted(kind,value,submitted){
    capture();const id=kind==='asset'?value.asset_id:kind==='file'?value.path:value.id;
    const key=kind+':'+id+(kind==='source'?':'+value.variant:''),doc=documents.get(key);if(!doc)return;
    if(submitted===undefined||doc.buffer===submitted){doc.buffer=value.content??'';if(doc.model&&doc.model.getValue()!==doc.buffer)doc.model.setValue(doc.buffer);}
    doc.saved=value.content??'';doc.revision=value.revision;doc.value=value;doc.conflict=false;doc.savedInSession=true;
  }
  function restore(doc){
    restoring=true;
    const selected=state[doc.kind];
    if(window.monaco&&editors[doc.kind]&&!doc.language.startsWith('image/')){
      const language=doc.language==='assembly'||doc.language.includes('asm')?'replay-asm':doc.language==='ida-pseudocode'?'cpp':doc.language;
      if(!doc.model)doc.model=monaco.editor.createModel(doc.buffer,language);
      editors[doc.kind].setModel(doc.model);editors[doc.kind].updateOptions({readOnly:selected.editable===false});
      $(`${doc.kind}-content`).value=doc.model.getValue();
      if(doc.position)editors[doc.kind].restoreViewState(doc.position);
    }else{
      setEditor(doc.kind,doc.buffer,doc.language,selected.editable===false);
      if(doc.language==='image/png-base64'&&doc.buffer!==selected.content)doc.previewReady=renderAssetImage(doc.buffer);
      if(doc.language==='image/dds-base64'&&doc.buffer!==selected.content){imageDdsDownload.href=doc.buffer;imageDdsMetadata.textContent='Imported DDS pending native descriptor validation on save.';}
    }
    restoring=false;editorChanged(doc.kind);applyPreferences();
  }
  function opened(kind){
    const selected=info(kind);if(!selected)return;
    let doc=documents.get(selected.key);
    if(!doc){doc={...selected,saved:selected.content,buffer:selected.content};documents.set(doc.key,doc);}
    else{
      const unsaved=doc.buffer!==doc.saved||doc.conflict;
      if(unsaved&&(doc.revision!==selected.revision||doc.saved!==selected.content)){
        doc.conflict=true;doc.model?.dispose();doc.model=null;
      }else if(!unsaved){doc.buffer=selected.content;if(doc.model&&doc.model.getValue()!==selected.content){doc.model.dispose();doc.model=null;}}
      Object.assign(doc,selected,{saved:selected.content});
    }
    active=doc.key;
    if(!doc.conflict)restore(doc);
    render();
    if(matchMedia('(max-width:760px)').matches&&!sources.classList.contains('explorer-collapsed'))$('iw8-explorer-toggle')?.click();
  }
  function changed(kind){
    if(restoring||busy())return;
    const selected=info(kind),doc=current();if(!selected||doc?.key!==selected.key)return;
    if(doc.conflict){render();return;}
    if(doc.revision!==selected.revision){doc.saved=selected.content;doc.revision=selected.revision;doc.value=selected.value;doc.savedInSession=true;}
    capture();render();
  }
  function cacheLoaded(kind,value){
    const selected=info(kind,value);if(!selected||documents.has(selected.key))return;
    selected.selection=kind+':'+selected.id;
    if(kind==='asset'){selected.zoneId=value.zone_id||null;selected.zone=null;}
    documents.set(selected.key,{...selected,saved:selected.content,buffer:selected.content});renderTabs();
  }
  async function navigate(doc,reload=false){
    if(!canLeave())return;
    if(state.page!=='sources'&&!await page('sources'))return;
    clearWorkspaceSelection();workspaceTree.active=doc.selection;state.zone=doc.zone;state.zoneId=doc.zoneId;
    if(doc.kind==='source')await openSource(doc.id,doc.variant,true,reload?null:doc.value);
    if(doc.kind==='file')await openFile(doc.id,true,reload?null:doc.value);
    if(doc.kind==='asset')await openAsset(doc.id,true,null,reload?null:doc.value);
  }
  async function closeDocument(doc){
    capture();if((doc.buffer!==doc.saved||doc.conflict)&&!await confirmDiscard(doc))return false;
    const wasActive=active===doc.key;if(wasActive){clearWorkspaceSelection();activateWorkspaceEditor('empty');active=null;}
    documents.delete(doc.key);doc.model?.dispose();render();
    if(wasActive&&documents.size)await navigate([...documents.values()].at(-1));return true;
  }
  function renderTabs(){
    tabs.replaceChildren();
    if(!documents.size){tabs.append(create('span','WORKSPACE','studio-tabs-empty'));return;}
    for(const doc of documents.values()){
      const group=create('div',undefined,'studio-document-tab');group.classList.toggle('active',active===doc.key);
      const dirty=doc.buffer!==doc.saved||doc.conflict;
      const node=button(doc.name,doc.path+(dirty?' · Unsaved working buffer':''),()=>navigate(doc));node.setAttribute('role','tab');node.setAttribute('aria-selected',String(active===doc.key));node.tabIndex=active===doc.key?0:-1;
      node.prepend(create('span',doc.kind==='asset'?'◇':'{ }','studio-document-icon'));if(dirty)node.append(create('span','●','studio-dirty-dot'));
      group.append(node,button('×','Close '+doc.name,()=>closeDocument(doc),'studio-tab-close'));
      group.onauxclick=guard(async event=>{if(event.button===1){event.preventDefault();await closeDocument(doc);}});
      node.onkeydown=event=>{if(['ArrowLeft','ArrowRight'].includes(event.key)){event.preventDefault();const docs=[...documents.values()],index=docs.indexOf(doc);const next=docs[(index+(event.key==='ArrowRight'?1:-1)+docs.length)%docs.length];guard(()=>navigate(next))();}};
      tabs.append(group);
    }
  }
  function renderInspector(){
    inspectorBody.replaceChildren();const doc=current();
    if(!doc){inspectorBody.append(create('div','Select a document to inspect its format, saved revision and edit status.','studio-inspector-empty'));return;}
    const selected=state[doc.kind],value=selected||doc.value;
    inspectorBody.append(create('span',doc.kind==='asset'?(value.type||'Asset'):'SOURCE CODE','studio-eyebrow'),create('h3',doc.name));
    const status=doc.conflict?'Saved revision changed':doc.buffer!==doc.saved?'Unsaved working buffer':value.pending_path?'Staged for next build':'Saved locally';
    const badge=create('span',status,'studio-state-pill');badge.dataset.state=doc.conflict?'conflict':doc.buffer!==doc.saved?'dirty':'saved';inspectorBody.append(badge);
    if(doc.conflict){inspectorBody.append(create('p','The saved content changed while this tab had unsaved work. Compare both versions before using the retained buffer.','studio-conflict'),button('Review retained buffer','Compare changed saved content with retained work',review));}
    const details=create('dl');
    const rows=[['Document',doc.path],['Access',value.editable===false?'Read-only':'Editable'],['Format',value.payload_format||doc.language],['Identity',doc.id],['Revision',doc.revision||'Native baseline']];
    if(doc.kind==='asset')rows.push(['Fastfile',doc.zone?.relative_path||doc.zoneId||'Checked on open'],['Native type',String(value.type_id??'—')]);
    for(const [name,text] of rows){const dd=create('dd',String(text));dd.title=String(text);details.append(create('dt',name),dd);}inspectorBody.append(details);
    const reason=value.codec_error||value.package_status||value.provenance?.basis;if(reason){inspectorBody.append(create('div','ABOUT THIS DOCUMENT','studio-eyebrow'),create('p',reason,'muted'));}
    inspectorBody.append(button('Compare with saved','Review this working buffer',review),button('Editor preferences','Configure font and editor navigation',()=>preferenceDialog.showModal()));
  }
  function render(){
    renderTabs();renderInspector();const doc=current(),editable=!!doc&&state[doc.kind]?.editable!==false;
    const text=!!doc&&!doc.language.startsWith('image/');find.disabled=!text;edit.disabled=!text;wrap.disabled=!text;compare.disabled=!doc;copy.disabled=!doc;
    undo.disabled=!text||!editable||!!doc?.conflict||!editors[doc.kind]?.getModel()?.canUndo();redo.disabled=!text||!editable||!!doc?.conflict||!editors[doc.kind]?.getModel()?.canRedo();
    wrap.setAttribute('aria-pressed',String(preferences.wordWrap));if(!matchMedia('(max-width:1100px)').matches)inspectorToggle.setAttribute('aria-pressed',String(preferences.inspector));else inspectorToggle.removeAttribute('aria-pressed');
    const count=[...documents.values()].filter(d=>d.buffer!==d.saved||d.conflict).length;
    unsavedItem.textContent=count?`${count} unsaved ${count===1?'tab':'tabs'}`:'All working tabs saved';unsavedItem.dataset.dirty=String(!!count);
    statusItem.textContent=doc?`${doc.language} · ${editable?'Editable':'Read-only'}`:'IW8 workspace';
    toolStatus.textContent=doc?.conflict?'Revision conflict':doc?doc.kind==='asset'?'Native asset':'Source code':'Select a document';
    if(doc&&!doc.conflict)$(`${doc.kind}-dirty`).textContent=doc.buffer!==doc.saved?'Unsaved':state[doc.kind]?.pending_path?'Staged for build':'Saved locally';
    if(!drawer.hidden&&drawerPage==='changes')renderChanges();
  }
  function applyPreferences(){
    try{localStorage.setItem('replay.editorPreferences',JSON.stringify(preferences));}catch{/* Optional browser preference. */}
    document.body.classList.toggle('studio-inspector-visible',!!preferences.inspector);
    inspector.hidden=!preferences.inspector;document.documentElement.style.setProperty('--studio-font-size',preferences.fontSize+'px');
    for(const editor of Object.values(editors))editor.updateOptions({fontSize:preferences.fontSize,lineHeight:preferences.fontSize+8,wordWrap:preferences.wordWrap?'on':'off',minimap:{enabled:!!preferences.minimap},lineNumbers:preferences.lineNumbers?'on':'off'});
    for(const text of document.querySelectorAll('.code-wrap textarea'))text.wrap=preferences.wordWrap?'soft':'off';
    for(const input of preferenceDialog.querySelectorAll('[data-preference]'))input.checked=!!preferences[input.dataset.preference];
    render();
  }
  function editorAction(action){const doc=current();if(!doc||busy())return;const editor=editors[doc.kind];if(!editor){$(`${doc.kind}-content`).focus();toast('Use the browser’s text search in this fallback editor.');return;}editor.focus();editor.getAction(action)?.run();}
  function editorCommand(command){const doc=current(),editor=doc&&editors[doc.kind];if(!editor||busy()||doc.conflict)return;editor.focus();editor.trigger('studio',command,null);render();}
  async function saveCurrent(){
    const doc=current();if(!doc||busy())return;
    if(state.buildActive||state.buildStarting||state.backendRestart)throw new Error('Wait for the current operation before saving working tabs.');
    if(doc.conflict)throw new Error('Review the changed saved revision before applying this retained buffer.');
    if(state[doc.kind]?.editable===false)throw new Error('This document is read-only.');
    if(doc.kind==='asset'&&doc.previewReady&&!(await doc.previewReady))throw new Error('The image preview did not load. Retry the image before saving.');
    if(current()!==doc||busy())throw new Error('The selected document changed while its preview was loading.');
    if(doc.kind==='asset'&&imageRenderBusy)throw new Error('Wait for the image preview to finish loading before saving.');
    if(doc.kind==='source')await saveSource();if(doc.kind==='file')await saveFile();if(doc.kind==='asset')await saveAsset();render();if(!drawer.hidden)await refreshStaged();
  }
  async function saveAll(){
    if(busy()||state.buildActive||state.buildStarting)throw new Error('Wait for the current operation before saving working tabs.');
    if($('sound-import')?.files.length)throw new Error('Save the selected WAV through its audio controls first.');
    capture();const start=current(),pending=[...documents.values()].filter(doc=>doc.buffer!==doc.saved||doc.conflict);
    for(const doc of pending){await navigate(doc);if(active!==doc.key)throw new Error('The selected document did not load.');await saveCurrent();capture();if(doc.buffer!==doc.saved||doc.conflict)throw new Error(`${doc.name} still has unsaved work; remaining tabs were kept.`);}
    if(start&&documents.has(start.key))await navigate(start);toast('All working tabs saved locally.');
  }
  async function review(){
    capture();const doc=current();if(!doc||busy())return;disposeDiff();reviewBody.replaceChildren();reviewBody.classList.remove('studio-diff');applyRetained.hidden=!doc.conflict;
    reviewDialog.querySelector('h2').textContent=doc.name;reviewDialog.showModal();
    if(doc.language==='image/png-base64'){
      for(const content of [doc.saved,doc.buffer]){const img=create('img');img.src=imagePngData(content);img.alt='Image comparison';reviewBody.append(img);}return;
    }
    if(doc.language.startsWith('image/')||Math.max(doc.saved.length,doc.buffer.length)>2000000){reviewBody.append(create('p','This resource is too large for a text comparison. Use its native export and preview controls.','muted'));return;}
    if(window.monaco){
      reviewBody.classList.add('studio-diff');const language=doc.language==='assembly'?'replay-asm':doc.language;
      diffModels=[monaco.editor.createModel(doc.saved,language),monaco.editor.createModel(doc.buffer,language)];
      diff=monaco.editor.createDiffEditor(reviewBody,{theme:'replay-black',readOnly:true,originalEditable:false,automaticLayout:true,renderSideBySide:!matchMedia('(max-width:760px)').matches,fontSize:preferences.fontSize,minimap:{enabled:false},scrollBeyondLastLine:false});
      diff.setModel({original:diffModels[0],modified:diffModels[1]});
    }else{for(const content of [doc.saved,doc.buffer])reviewBody.append(create('pre',content));}
  }
  async function refreshStaged(){
    const request=++reviewRequest;drawerContent.setAttribute('aria-busy','true');
    try{const result=await api('/api/asset-edits?limit=1000');if(request!==reviewRequest)return;staged=result.items;stagedTotal=result.total;if(drawerPage==='changes')renderChanges();}
    catch(error){if(request===reviewRequest&&drawerPage==='changes')drawerContent.replaceChildren(create('p',error.message,'studio-conflict'),button('Retry','Retry loading staged changes',refreshStaged));}
    finally{if(request===reviewRequest)drawerContent.removeAttribute('aria-busy');}
  }
  function renderChanges(){
    drawerContent.replaceChildren();const working=create('div',undefined,'studio-change-column'),saved=create('div',undefined,'studio-change-column');
    working.append(create('h3','Working buffers'),create('p','Unsaved tabs are retained here until saved or closed.','muted'));
    const pending=[...documents.values()].filter(doc=>doc.buffer!==doc.saved||doc.conflict);
    if(!pending.length)working.append(create('p','No unsaved working buffers.','studio-clean'));
    for(const doc of pending)working.append(button(doc.name,'Open unsaved '+doc.name,()=>navigate(doc),'studio-change-row'));
    if(pending.length)working.append(button('Save all working tabs','Save each checked working document',saveAll,'primary'));
    saved.append(create('h3',`Saved asset drafts · ${stagedTotal}`),create('p','Staged payloads enter the next supported asset build.','muted'));
    if(!staged.length)saved.append(create('p','No asset drafts staged.','studio-clean'));
    for(const row of staged){
      const node=button(row.name||row.asset_id,'Open staged '+(row.name||row.asset_id),async()=>{
        if(!canLeave())return;if(state.page!=='sources'&&!await page('sources'))return;
        clearWorkspaceSelection();state.zoneId=row.zone_id;await openAsset(row.asset_id,true);
      },'studio-change-row');node.append(create('small',`${row.type||'asset'} · ${row.operation||'edit'}${row.error?' · '+row.error:''}`));saved.append(node);
    }
    if(stagedTotal>staged.length)saved.append(create('p',`Showing the first ${staged.length} drafts. Filter the owning fastfile to inspect the remaining changes.`,'muted'));
    drawerContent.append(working,saved);
  }
  function renderOutput(){
    const job=state.job;
    if(!job){drawerContent.replaceChildren(create('p','Select a build to see its output.','muted'),button('Open build history','Browse compilation jobs',()=>page('builds')));return;}
    if(outputPanel.parentElement!==drawerContent)drawerContent.replaceChildren(outputPanel);
    outputHeading.textContent=`${job.profile} · ${job.status} · ${job.error||job.phase}`;
    const position=outputLog.scrollTop;outputLog.textContent=$('build-log').textContent;outputLog.scrollTop=followOutput?outputLog.scrollHeight:position;
  }
  function setDrawerPage(value){drawerPage=value;changesTab.setAttribute('aria-pressed',String(value==='changes'));outputTab.setAttribute('aria-pressed',String(value==='output'));if(value==='changes'){renderChanges();guard(refreshStaged)();}else renderOutput();}
  function toggleDrawer(open=drawer.hidden){drawer.hidden=!open;document.body.classList.toggle('studio-drawer-open',open);drawerToggle.setAttribute('aria-expanded',String(open));if(open)setDrawerPage(drawerPage);}
  async function showBuildReview(){
    if(state.buildActive||state.buildStarting||state.backendRestart)return;
    capture();buildProfile.value=$('build-profile').value;buildSummary.replaceChildren();buildConfirm.disabled=true;buildNote.textContent='Checking the saved draft list…';buildDialog.showModal();
    try{const data=await api('/api/asset-edits?limit=1000');const count=[...documents.values()].filter(doc=>doc.buffer!==doc.saved||doc.conflict).length;
      buildNote.textContent=count?`Save or close ${count} unsaved working ${count===1?'tab':'tabs'} before compiling.`:'Compile the selected saved inputs, then verify the executable and asset replacements.';
      buildSummary.append(create('div',`${data.total} saved asset drafts`),create('small','Output is published separately. The root game folder is changed only when you deploy a verified job.'));
      buildConfirm.disabled=hasUnsaved();
    }catch(error){buildNote.textContent=error.message;}
  }
  for(const kind of ['source','file','asset'])$(`${kind}-reset`).onclick=guard(async()=>{
    const doc=current();if(!doc||doc.kind!==kind)return;
    capture();if((doc.buffer!==doc.saved||doc.conflict)&&!await confirmDiscard(doc))return;
    doc.buffer=doc.saved;doc.conflict=false;
    // Replace the displayed working value before navigation captures it again.
    if(doc.model)doc.model.setValue(doc.saved);restore(doc);await navigate(doc,true);
  });
  // Keep keyboard saves on app.js's validated paths; only add editor-level controls.
  document.addEventListener('keydown',guard(async event=>{
    if(document.querySelector('dialog[open]')||busy()||event.defaultPrevented)return;
    const mod=event.ctrlKey||event.metaKey,key=event.key.toLowerCase();
    if(mod&&event.shiftKey&&key==='p'){event.preventDefault();commandDialog.showModal();commandInput.focus();}
    if(mod&&key===','){event.preventDefault();preferenceDialog.showModal();}
    if(mod&&key==='g'){event.preventDefault();event.stopImmediatePropagation();showGoToLine();}
    if(mod&&event.shiftKey&&key==='s'){event.preventDefault();event.stopImmediatePropagation();await saveAll();}
    if(mod&&event.shiftKey&&key==='d'){event.preventDefault();toggleDrawer();}
    if(mod&&event.shiftKey&&key==='e'){event.preventDefault();$('iw8-explorer-toggle')?.click();}
    if(mod&&event.altKey&&key==='b'){event.preventDefault();showInspector();}
  }),true);
  window.addEventListener('beforeunload',event=>{if(hasUnsaved()){event.preventDefault();event.returnValue='';}});
  matchMedia('(max-width:760px)').addEventListener('change',event=>{if(event.matches&&current()&&!sources.classList.contains('explorer-collapsed'))$('iw8-explorer-toggle')?.click();});
  const outputObserver=new MutationObserver(()=>{if(!drawer.hidden&&drawerPage==='output')renderOutput();});outputObserver.observe($('build-log'),{childList:true,characterData:true,subtree:true});
  const connectionObserver=new MutationObserver(()=>{connection.textContent=$('connection').textContent;connection.dataset.offline=String(state.backendRestart);});connectionObserver.observe($('connection'),{childList:true});
  window.ReplayStudio={preserveWorkingBuffers,loading,opened,changed,hasUnsaved,accepted,cleared,assertCanSave,cacheLoaded,
    reviewDocuments(){capture();return [...documents.values()].map(doc=>({key:doc.key,kind:doc.kind,id:doc.id,variant:doc.variant,name:doc.name,path:doc.path,language:doc.language,saved:doc.saved,buffer:doc.buffer,revision:doc.revision,conflict:!!doc.conflict}));},
    registerCommand(name,key,action){commandDefinitions.push([name,key,action]);renderCommands();}};
  applyPreferences();
  // Monaco initializes asynchronously; apply saved preferences when it becomes available.
  const ready=new MutationObserver(()=>{if(Object.keys(editors).length===3){ready.disconnect();if(current())restore(current());applyPreferences();}});
  ready.observe(host,{childList:true,subtree:true});
})();
