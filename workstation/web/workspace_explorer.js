/* Compact, lazy IW8 tree. This layer only changes navigation and layout;
   editor mutations and their verified readbacks stay in app.js. */
(() => {
  'use strict';
  const list = document.getElementById('source-list');
  const sources = document.getElementById('sources');
  const split = sources.querySelector('.split');
  const pane = sources.querySelector('.browser-pane');
  const pages = new Map();
  const expanded = new Set();
  const pending = new Map();
  const errors = new Map();
  let rootId = null;
  let focusId = null;
  let renderedNode = null;
  let drawing = false;
  const originalRender = renderWorkspaceTree;
  const storage = {
    get(key) { try { return localStorage.getItem(key); } catch { return null; } },
    set(key, value) { try { localStorage.setItem(key, value); } catch { /* Optional preference. */ } },
  };

  function expandable(item) { return item.kind === 'folder' || item.kind === 'zone'; }
  function remember(page, append = false, reveal = false) {
    const old = pages.get(page.node);
    const rows = append && old ? [...old.items, ...page.items] : page.items;
    const seen = new Set();
    pages.set(page.node, {...page, items: rows.filter(item => !seen.has(item.id) && seen.add(item.id))});
    const crumbs = page.breadcrumbs || [];
    if (crumbs.length) rootId = crumbs[0].id || page.node;
    else if (page.label === 'IW8') rootId = page.node;
    // A reveal, breadcrumb, or checked refresh can land directly in a deep
    // folder. Keep the ancestor chain visible without inventing child data.
    for (let i = 0; i < crumbs.length; i++) {
      const crumb = crumbs[i];
      const id = crumb.id || rootId;
      if (!id) continue;
      if (reveal) expanded.add(id);
      if (i + 1 < crumbs.length) {
        const next = crumbs[i + 1];
        if (!next.id) continue;
        const ancestor = pages.get(id) || {node: id, label: crumb.label, items: [], total: 0,
          offset: 0, limit: 100, breadcrumbs: crumbs.slice(0, i + 1), placeholder: true};
        if (!ancestor.items.some(item => item.id === next.id)) {
          ancestor.items.push({...next, id: next.id, name: next.label,
            kind: next.kind === 'zone' ? 'zone' : 'folder', expandable: true, placeholder: true});
        }
        pages.set(id, ancestor);
      }
    }
  }

  function treeRow(item, depth, parent) {
    const branch = expandable(item);
    const open = expanded.has(item.id);
    const row = document.createElement('div');
    row.className = 'iw8-tree-row';
    row.setAttribute('role', 'treeitem');
    row.setAttribute('aria-level', String(depth + 1));
    row.setAttribute('aria-selected', String(workspaceTree.active === `${item.kind}:${item.id}`));
    if (branch) row.setAttribute('aria-expanded', String(open));
    if (pending.has(item.id)) row.setAttribute('aria-busy', 'true');
    row.dataset.id = item.id;
    row.dataset.kind = item.kind;
    row.style.setProperty('--tree-depth', depth);
    const disclosure = document.createElement('button');
    disclosure.className = 'iw8-tree-disclosure';
    disclosure.type = 'button';
    disclosure.tabIndex = -1;
    disclosure.textContent = branch ? (open ? '▾' : '▸') : '';
    disclosure.disabled = !branch || pending.has(item.id);
    if (!branch) disclosure.setAttribute('aria-hidden', 'true');
    disclosure.setAttribute('aria-label', `${open ? 'Collapse' : 'Expand'} ${item.name}`);
    disclosure.onclick = guard(() => { focusId = item.id; return toggle(item); });
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'iw8-tree-label';
    button.dataset.kind = item.kind;
    button.dataset.itemId = item.id;
    button.title = `${item.name}\n${workspaceItemDetail(item)}`;
    button.tabIndex = focusId === item.id ? 0 : -1;
    const icon = document.createElement('span');
    icon.className = 'iw8-tree-icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = ({folder: '▱', zone: '▣', source: 'ƒ', global: '◇', file: '▤', asset: '◈'})[item.kind] || '·';
    const name = document.createElement('span');
    name.className = 'iw8-tree-name';
    name.textContent = item.name;
    button.append(icon, name);
    const count = Number.isSafeInteger(item.count) ? item.count : item.kind === 'zone' ? null : undefined;
    if (Number.isSafeInteger(count)) {
      const badge = document.createElement('span');
      badge.className = 'iw8-tree-count';
      badge.textContent = count.toLocaleString();
      button.append(badge);
    }
    button.onfocus = () => { focusId = item.id; };
    button.onclick = guard(async () => {
      focusId = item.id;
      if (branch) return toggle(item, item.kind === 'zone');
      // Checked mutations refresh this leaf's actual parent instead of the
      // last unrelated branch expanded in the tree.
      if (parent && pages.has(parent)) {
        workspaceTree.node = parent;
        workspaceTree.page = pages.get(parent);
        workspaceTree.offset = 0;
        renderedNode = parent;
      }
      await selectWorkspaceItem(item);
      draw();
    });
    button.onkeydown = guard(async event => {
      const buttons = [...list.querySelectorAll('.iw8-tree-label')];
      const index = buttons.indexOf(button);
      if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
        event.preventDefault();
        const at = event.key === 'Home' ? 0 : event.key === 'End' ? buttons.length - 1 :
          Math.max(0, Math.min(buttons.length - 1, index + (event.key === 'ArrowDown' ? 1 : -1)));
        buttons[at]?.focus();
      } else if (event.key === 'ArrowRight' && branch) {
        event.preventDefault();
        if (!open) await toggle(item);
        else buttons[index + 1]?.focus();
      } else if (event.key === 'ArrowLeft') {
        event.preventDefault();
        if (branch && open) { expanded.delete(item.id); draw(); }
        else if (parent) [...list.querySelectorAll('.iw8-tree-row')]
          .find(candidate => candidate.dataset.id === parent)?.querySelector('.iw8-tree-label')?.focus();
      }
    });
    row.append(disclosure, button);
    return row;
  }

  function appendBranch(host, item, depth, parent, visited) {
    const row = treeRow(item, depth, parent);
    const node = document.createElement('div');
    node.className = 'iw8-tree-node';
    node.setAttribute('aria-label', item.name);
    for (const attribute of ['role', 'aria-level', 'aria-selected', 'aria-expanded', 'aria-busy']) {
      if (row.hasAttribute(attribute)) node.setAttribute(attribute, row.getAttribute(attribute));
    }
    row.removeAttribute('role');
    node.append(row);
    host.append(node);
    if (!expandable(item) || !expanded.has(item.id) || visited.has(item.id)) return;
    const nextVisited = new Set(visited).add(item.id);
    const group = document.createElement('div');
    group.setAttribute('role', 'group');
    group.className = 'iw8-tree-group';
    const page = pages.get(item.id);
    if (pending.has(item.id) || errors.has(item.id)) {
      const message = document.createElement('button');
      message.type = 'button';
      message.className = 'iw8-tree-more';
      message.style.setProperty('--tree-depth', depth + 1);
      message.disabled = pending.has(item.id);
      message.textContent = pending.has(item.id) ? 'Loading branch…' : 'Could not load branch — Retry';
      message.title = errors.get(item.id) || '';
      message.onclick = guard(() => fetchBranch(item, 0));
      group.append(message);
    } else if (page) {
      for (const child of page.items) appendBranch(group, child, depth + 1, item.id, nextVisited);
      if (!page.items.length) {
        const empty = document.createElement('span');
        empty.className = 'iw8-tree-empty';
        empty.style.setProperty('--tree-depth', depth + 1);
        empty.textContent = page.extract_required ? 'Extract this fastfile to populate assets' : 'Empty folder';
        group.append(empty);
      }
      if (page.placeholder || page.items.length < page.total) {
        const more = document.createElement('button');
        more.type = 'button';
        more.className = 'iw8-tree-more';
        more.style.setProperty('--tree-depth', depth + 1);
        more.textContent = page.placeholder ? 'Load folder contents…' :
          `Load more · ${page.items.length.toLocaleString()} of ${page.total.toLocaleString()}`;
        more.onclick = guard(() => fetchBranch(item, page.placeholder ? 0 : page.items.length));
        group.append(more);
      }
    }
    node.append(group);
  }

  function draw() {
    if (drawing || workspaceGlobalSearchActive || !rootId) return;
    drawing = true;
    try {
      const scroll = list.scrollTop;
      const hadFocus = list.contains(document.activeElement);
      list.setAttribute('role', 'tree');
      list.setAttribute('aria-label', 'IW8 code and asset tree');
      list.classList.add('iw8-branch-tree');
      const fragment = document.createDocumentFragment();
      appendBranch(fragment, {id: rootId, name: 'IW8', kind: 'folder'}, 0, null, new Set());
      list.replaceChildren(fragment);
      const buttons = [...list.querySelectorAll('.iw8-tree-label')];
      const focused = buttons.find(button => button.dataset.itemId === focusId) || buttons[0];
      if (focused) focused.tabIndex = 0;
      list.scrollTop = scroll;
      if (hadFocus) focused?.focus({preventScroll: true});
      document.getElementById('workspace-tree-status').hidden = true;
      document.getElementById('source-prev').parentElement.hidden = true;
    } finally { drawing = false; }
  }

  async function fetchBranch(item, offset) {
    if (pending.has(item.id)) return pending.get(item.id);
    errors.delete(item.id);
    const work = (async () => {
      try {
        const page = ReplayWorkspaceTree.validatePage(await api(ReplayWorkspaceTree.url(item.id, '', offset, 100)));
        remember(page, offset > 0);
        return page;
      } catch (error) { errors.set(item.id, error.message); throw error; }
      finally { pending.delete(item.id); draw(); }
    })();
    pending.set(item.id, work);
    draw();
    return work;
  }

  async function toggle(item, selectZone = false) {
    if (pending.has(item.id)) return;
    if (selectZone && item.kind === 'zone' && !item.placeholder) {
      // Clicking the fastfile name opens its existing metadata/extraction
      // controls. Its disclosure arrow only browses children, preserving the
      // current editor and unsaved text just like an ordinary folder arrow.
      await selectWorkspaceItem(item);
      draw();
      return;
    }
    if (expanded.has(item.id)) { expanded.delete(item.id); draw(); return; }
    expanded.add(item.id);
    if (!pages.has(item.id) || pages.get(item.id).placeholder) await fetchBranch(item, 0);
    else draw();
  }

  renderWorkspaceTree = function(page) {
    originalRender(page);
    if (workspaceGlobalSearchActive || document.getElementById('source-search').value.trim()) {
      list.classList.remove('iw8-branch-tree');
      list.setAttribute('role', 'list');
      document.getElementById('source-prev').parentElement.hidden = false;
      return;
    }
    remember(page, false, renderedNode !== page.node);
    renderedNode = page.node;
    draw();
  };

  const collapse = document.createElement('button');
  collapse.type = 'button';
  collapse.className = 'icon-button iw8-collapse-all';
  collapse.title = 'Collapse all branches';
  collapse.setAttribute('aria-label', 'Collapse all IW8 branches');
  collapse.textContent = '⊟';
  collapse.onclick = () => { expanded.clear(); if (rootId) expanded.add(rootId); focusId = rootId; draw(); };
  document.getElementById('new-source').before(collapse);

  const divider = document.createElement('div');
  divider.id = 'iw8-explorer-divider';
  divider.setAttribute('role', 'separator');
  divider.setAttribute('aria-label', 'Resize IW8 Explorer and search');
  divider.setAttribute('aria-orientation', 'vertical');
  divider.setAttribute('aria-controls', 'source-list');
  divider.tabIndex = 0;
  split.insertBefore(divider, pane.nextSibling);
  let width = Number(storage.get('replay.explorerWidth')) || 280;
  function resize(value, persist = true) {
    if (!split.clientWidth) return;
    const max = Math.max(220, Math.min(900, split.clientWidth - 320));
    width = Math.max(220, Math.min(max, value));
    split.style.setProperty('--explorer-width', `${width}px`);
    divider.setAttribute('aria-valuemin', '220');
    divider.setAttribute('aria-valuemax', String(max));
    divider.setAttribute('aria-valuenow', String(Math.round(width)));
    if (persist) storage.set('replay.explorerWidth', String(Math.round(width)));
  }
  let drag = null;
  divider.onpointerdown = event => {
    if (event.button !== 0) return;
    event.preventDefault();
    drag = {id: event.pointerId, x: event.clientX, width};
    divider.setPointerCapture(event.pointerId);
    document.body.classList.add('resizing-explorer');
  };
  divider.onpointermove = event => { if (drag?.id === event.pointerId) resize(drag.width + event.clientX - drag.x, false); };
  function endDrag() {
    if (!drag) return;
    drag = null;
    document.body.classList.remove('resizing-explorer');
    resize(width);
  }
  divider.onpointerup = divider.onpointercancel = divider.onlostpointercapture = endDrag;
  divider.onkeydown = event => {
    if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
      event.preventDefault();
      resize(event.key === 'Home' ? 220 : event.key === 'End' ? 900 : width + (event.key === 'ArrowLeft' ? -20 : 20));
    }
  };
  divider.ondblclick = () => resize(280);
  const explorerToggle = document.createElement('button');
  explorerToggle.id = 'iw8-explorer-toggle';
  explorerToggle.type = 'button';
  explorerToggle.className = 'icon-button';
  explorerToggle.textContent = '▱';
  explorerToggle.setAttribute('aria-controls', 'source-list');
  function setExplorerCollapsed(collapsed) {
    sources.classList.toggle('explorer-collapsed', collapsed);
    explorerToggle.setAttribute('aria-expanded', String(!collapsed));
    explorerToggle.setAttribute('aria-label', collapsed ? 'Show IW8 Explorer' : 'Hide IW8 Explorer');
    explorerToggle.title = collapsed ? 'Show IW8 Explorer' : 'Hide IW8 Explorer';
    storage.set('replay.explorerCollapsed', String(collapsed));
  }
  explorerToggle.onclick = () => setExplorerCollapsed(!sources.classList.contains('explorer-collapsed'));
  document.getElementById('sidebar-toggle').after(explorerToggle);
  setExplorerCollapsed(storage.get('replay.explorerCollapsed') === 'true');
  const layout = () => {
    document.body.classList.toggle('explorer-page', sources.classList.contains('active'));
    resize(width, false);
  };
  new MutationObserver(layout).observe(sources, {attributes: true, attributeFilter: ['class']});
  new ResizeObserver(() => resize(width, false)).observe(split);
  layout();
  if (workspaceTree.page && !workspaceGlobalSearchActive) renderWorkspaceTree(workspaceTree.page);
})();
