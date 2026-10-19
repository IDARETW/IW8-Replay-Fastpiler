'use strict';
(() => {
  const owner='replay-compiler-errors',attached=new Map();let live=true,timer=null,flight=false,generation=0;
  try{live=localStorage.getItem('replay.liveErrors')!=='off';}catch{}
  const toggle=element('button','Live errors'),status=element('button','C++ diagnostics','source-error-status');
  toggle.type=status.type='button';toggle.id='source-live-errors';status.id='source-error-status';
  toggle.title='Automatically check the active C++ buffer without saving · compiler errors appear on their source lines';
  status.title='Go to the next compiler error · F8';status.setAttribute('aria-live','polite');
  $('source-check').after(toggle,status);
  const fileCheck=element('button','Check errors');fileCheck.type='button';fileCheck.title='Check this authored C/C++ buffer without saving';$('file-save').before(fileCheck);
  const fileStatus=element('button','C++ diagnostics','source-error-status');fileStatus.type='button';fileCheck.after(fileStatus);
  new MutationObserver(()=>{fileStatus.textContent=status.textContent;fileStatus.title=status.title;fileStatus.disabled=status.disabled;fileStatus.dataset.errors=status.dataset.errors||'0';}).observe(status,{childList:true,attributes:true});
  function activeKind(){return document.querySelector('.workspace-editor-host')?.dataset.activeEditor;}
  function active(){const kind=activeKind(),editor=editors[kind],selected=state[kind];return ['source','file'].includes(kind)&&editor&&selected&&['cpp','c'].includes(selected.language)?{kind,editor,model:editor.getModel(),selected}:null;}
  function markers(text,model,content){
    const result=[],lines=content.split('\n');
    for(const diagnostic of text.split('\n')){
      const match=diagnostic.match(/^(.*?):(\d+):(?:(\d+):)?\s*(fatal error|error|warning):\s*(.*)$/);if(!match)continue;
      let line=Number(match[2]),column=Number(match[3]||1),message=match[5];
      if(!/^candidate(?:\.(?:cpp|c))?$/.test(match[1])){
        const leaf=match[1].replace(/\\/g,'/').split('/').at(-1);
        const include=lines.findIndex(value=>/^\s*#\s*include\b/.test(value)&&value.includes(leaf));
        if(include<0)continue;
        message=`Included ${leaf}:${line}:${column}: ${message}`;line=include+1;column=Math.max(1,lines[include].indexOf(leaf)+1);
      }
      if(line<1||line>model.getLineCount())continue;
      column=Math.min(column,model.getLineMaxColumn(line));
      const symbol=message.match(/(?:identifier|type name) '([^']+)'/),length=symbol?.[1]?.length||1;
      result.push({severity:match[4]==='warning'?monaco.MarkerSeverity.Warning:monaco.MarkerSeverity.Error,startLineNumber:line,endLineNumber:line,startColumn:column,endColumn:Math.min(model.getLineMaxColumn(line),column+length),message,source:'Replay C++ compiler'});
    }
    return result;
  }
  function paint(context,items){
    if(context.editor.getModel()!==context.model||context.model.isDisposed())return;
    monaco.editor.setModelMarkers(context.model,owner,items);
    const hook=attached.get(context.kind);hook?.decorations.set(items.filter(item=>item.severity===monaco.MarkerSeverity.Error).map(item=>({range:new monaco.Range(item.startLineNumber,1,item.startLineNumber,1),options:{isWholeLine:true,linesDecorationsClassName:'replay-error-line'}})));
    if(hook)hook.markers=items;
    const errors=items.filter(item=>item.severity===monaco.MarkerSeverity.Error).length,warnings=items.length-errors;
    status.textContent=`${errors} errors · ${warnings} warnings`;status.dataset.errors=String(errors);status.disabled=!items.length;
  }
  function schedule(){
    clearTimeout(timer);++generation;const context=active();if(!context)return;
    const content=context.model.getValue();paint(context,[]);
    if(context.kind==='source'&&(!context.selected.editable||!context.selected.symbol)){status.textContent='Reference source';return;}
    if(!live){status.title='Live validation is off; use Check compilation or Check errors for compiler markers';return;}
    if(content.length>1_000_000){status.textContent='Large buffer · use Check compilation';return;}
    if(state.backendRestart){status.title='Reload the workstation backend before checking compilation';return;}
    status.textContent='C++ check pending…';timer=setTimeout(()=>check(false),1400);
  }
  async function check(manual=false){
    const context=active();if(!context||(!manual&&!live))return;
    if(flight||state.buildActive){timer=setTimeout(()=>check(manual),1600);return;}
    if(state.backendRestart)return;
    if(context.kind==='source'&&(!context.selected.editable||!context.selected.symbol))return;
    const token=generation,model=context.model,content=model.getValue(),selected=context.selected;
    flight=true;status.textContent='Checking C++…';status.disabled=!(attached.get(context.kind)?.markers?.length);
    try{
      const value=await api(context.kind==='source'?'/api/source/check':'/api/file/check',context.kind==='source'?{id:selected.id,revision:selected.revision,content}:{path:selected.path,revision:selected.revision,content});
      if(token!==generation||active()?.model!==model||model.isDisposed()||model.getValue()!==content)return;
      checked(context.kind,content,value);
    }catch(error){if(token===generation&&active()?.model===model){const items=attached.get(context.kind)?.markers||[],errors=items.filter(item=>item.severity===monaco.MarkerSeverity.Error).length;status.textContent=`${errors?`${errors} errors · `:''}C++ check unavailable`;status.disabled=!items.length;status.title=error.message;}}
    finally{flight=false;}
  }
  function checked(kind,content,value){
    const context=active();if(!context||context.kind!==kind||context.model.getValue()!==content)return;
    const compiler=markers(value.diagnostics||'',context.model,content);
    paint(context,compiler);
    status.title=value.diagnostics||value.scope||'No C++ compilation diagnostics for this buffer. Game linking and runtime checks are separate.';
    if(!value.compiled&&!compiler.length){status.textContent='Compilation blocked · see diagnostics';status.disabled=false;}
    if(kind==='source'){
      sourceDiagnostics.hidden=false;sourceDiagnosticsTitle.textContent=value.compiled?'C++ object compilation passed':'Compilation needs corrections';
      sourceDiagnosticsText.textContent=value.diagnostics||value.note||'Compilation passed.';
    }
  }
  function editorReady(kind,editor){
    if(!['source','file'].includes(kind)||attached.has(kind))return;
    editor.updateOptions({glyphMargin:true});
    const decorations=editor.createDecorationsCollection();attached.set(kind,{editor,decorations});
    editor.onDidChangeModel(()=>{decorations.clear();schedule();});editor.onDidChangeModelContent(schedule);
    if(active()?.editor===editor)schedule();
  }
  function settings(){toggle.setAttribute('aria-pressed',String(live));toggle.textContent=live?'Live errors on':'Live errors off';}
  toggle.onclick=()=>{live=!live;try{localStorage.setItem('replay.liveErrors',live?'on':'off');}catch{}settings();schedule();};
  fileCheck.onclick=guard(()=>check(true));status.onclick=()=>{const context=active();if(!context)return;context.editor.trigger('replay-diagnostics','editor.action.marker.next',null);context.editor.focus();if(status.textContent.startsWith('Compilation blocked')&&context.kind==='source')sourceDiagnostics.open=true;};
  fileStatus.onclick=()=>status.click();
  const host=document.querySelector('.workspace-editor-host');new MutationObserver(()=>{clearTimeout(timer);++generation;fileCheck.hidden=state.file?.language==='assembly';schedule();}).observe(host,{attributes:true,attributeFilter:['data-active-editor']});
  window.ReplaySourceErrors={editorReady,checked};settings();for(const [kind,editor] of Object.entries(editors))editorReady(kind,editor);
})();
