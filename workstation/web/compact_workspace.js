/* Consolidate existing controls; native editor actions and revision checks stay intact. */
(() => {
  'use strict';
  const host=document.querySelector('.workspace-editor-host'), tools=host.querySelector('.studio-tools');
  const bar=document.querySelector('.app-bar'), sidebarToggle=$('sidebar-toggle');
  bar.prepend(sidebarToggle);
  const explorerToggle=$('iw8-explorer-toggle');if(explorerToggle)sidebarToggle.after(explorerToggle);
  bar.insertBefore($('compile'),bar.querySelector('.app-environment'));
  document.querySelector('.studio-statusbar').append($('job-badge'));
  const pageTitle=$('page-title');pageTitle.classList.add('compact-page-title');$('main-content').prepend(pageTitle);

  const button=(text,label,run)=>{const node=element('button',text);node.type='button';node.title=label;node.setAttribute('aria-label',label);node.onclick=run;return node;};
  const actions=element('div',undefined,'compact-document-actions');actions.setAttribute('aria-label','Active document actions');
  const menuButton=button('⋮','Document actions and diagnostics',()=>showMenu());menuButton.setAttribute('aria-haspopup','dialog');menuButton.setAttribute('aria-expanded','false');
  const menu=element('div',undefined,'compact-document-popover');menu.id='compact-document-popover';menu.setAttribute('popover','auto');menu.setAttribute('role','dialog');menu.setAttribute('aria-label','Document actions and diagnostics');menuButton.setAttribute('aria-controls',menu.id);
  const heading=element('div',undefined,'compact-document-menu-heading');heading.append(element('strong','Document actions'),button('×','Close document actions',()=>menu.hidePopover()));menu.append(heading);document.body.append(menu);
  const groups=new Map(), menus=new Map();
  for(const kind of ['source','file','asset']){
    const row=$(`${kind}-editor`).querySelector('.editor-toolbar'), original=row.querySelector(':scope > div');
    const group=element('div',undefined,'compact-document-action-group'), panel=element('div',undefined,'compact-document-menu-group');
    group.dataset.kind=panel.dataset.kind=kind;groups.set(kind,group);menus.set(kind,panel);actions.append(group);menu.append(panel);
    const basis=row.querySelector(':scope > span');if(basis){basis.classList.add('compact-document-basis');panel.append(basis);}
    const save=$(`${kind}-save`);save.setAttribute('aria-label',kind==='asset'?'Compile and save asset':'Save changes');save.title=kind==='asset'?'Compile and save this asset':'Save this document · Ctrl S';save.textContent='Save';save.classList.add('compact-save');
    const check=kind==='source'?$('source-check'):kind==='file'?[...original.children].find(node=>node.textContent==='Check errors'):null;
    if(check){check.setAttribute('aria-label',kind==='source'?'Check compilation':'Check compilation of authored C++');check.title='Check this buffer without saving';check.textContent='Check';group.append(check);}
    const status=original.querySelector('.source-error-status');if(status)group.append(status);
    const secondary=element('div',undefined,'compact-document-menu-buttons');secondary.append(...original.children);panel.append(secondary);group.append(save);
  }
  const sourceDiagnostics=document.querySelector('.source-recovery');menus.get('source').append(sourceDiagnostics);
  const assetStatus=$('asset-package-status');menus.get('asset').append(assetStatus);
  const zonePanel=element('div',undefined,'compact-document-menu-group');zonePanel.dataset.kind='zone';menus.set('zone',zonePanel);menu.append(zonePanel);
  const zoneDetail=$('zone-detail');zoneDetail.classList.add('compact-document-basis');zonePanel.append($('zone-name'),zoneDetail,$('zone-status'));
  const extract=$('zone-extract');extract.title='Extract the selected fastfile to cache';zonePanel.append(extract);
  const toolRight=tools.querySelector(':scope > div:last-child');
  const copy=toolRight.querySelector('button[aria-label="Copy the active file path or asset identity"]');if(copy)menu.append(copy);
  for(const [label,text] of [['Toggle word wrap','↔'],['Compare working content with its saved version','±'],['Show document inspector · Ctrl Alt B','▤']]){
    const control=tools.querySelector(`button[aria-label="${label}"]`);if(control){control.textContent=text;control.classList.add('compact-icon-control');}
  }
  actions.append(menuButton);toolRight.prepend(actions);
  const loading=$('workspace-content-load');

  function updateLoading(){
    menuButton.disabled=!loading.hidden;
    if(!loading.hidden&&menu.matches(':popover-open'))menu.hidePopover();
  }

  function activeKind(){return host.dataset.activeEditor;}
  function update(){
    const kind=activeKind();for(const [key,group] of groups)group.hidden=key!==kind;for(const [key,panel] of menus)panel.hidden=key!==kind;
    actions.hidden=!menus.has(kind);if(menu.matches(':popover-open'))menu.hidePopover();
  }
  function showMenu(){
    if(!menus.has(activeKind())||!loading.hidden)return;
    if(menu.matches(':popover-open')){menu.hidePopover();return;}
    menu.showPopover();const rect=menuButton.getBoundingClientRect();
    menu.style.right=Math.max(8,innerWidth-rect.right)+'px';menu.style.top=Math.min(rect.bottom+6,Math.max(8,innerHeight-180))+'px';menu.style.maxHeight=Math.max(120,innerHeight-rect.bottom-20)+'px';
  }
  menu.addEventListener('toggle',event=>{menuButton.setAttribute('aria-expanded',String(event.newState==='open'));if(event.newState==='closed')sourceDiagnostics.open=false;});
  new MutationObserver(update).observe(host,{attributes:true,attributeFilter:['data-active-editor']});
  new MutationObserver(updateLoading).observe(loading,{attributes:true,attributeFilter:['hidden']});
  new MutationObserver(()=>{if(sourceDiagnostics.open&&!sourceDiagnostics.hidden&&activeKind()==='source'&&!menu.matches(':popover-open'))showMenu();}).observe(sourceDiagnostics,{attributes:true,attributeFilter:['open','hidden']});
  update();updateLoading();
})();
