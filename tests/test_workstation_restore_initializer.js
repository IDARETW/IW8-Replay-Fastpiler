'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const appPath = path.resolve(process.argv[2] || 'workstation/web/app.js');
const app = fs.readFileSync(appPath, 'utf8');
const start = app.indexOf('sourceRestore.onclick=guard(async()=>{');
const end = app.indexOf("\n$('source-remove')", start);
assert.notEqual(start, -1, 'restore handler exists');
assert.notEqual(end, -1, 'restore handler has a bounded end');
const handlerSource = app.slice(start, end).trim();

function setup({ content = '[9, 9]', saved = '[1, 2]', confirmResult = false, api } = {}) {
  const source = { id: 'global_fixture', variant: 'global-initializer', revision: 'saved-revision', content: saved };
  const editor = { value: content };
  const state = { source };
  const calls = { confirms: [], api: [], setEditor: [], basis: [], changed: [], toasts: [] };
  const nativeSource = { id: source.id, variant: source.variant, revision: 'native-revision',
    content: '[1, 2]', language: 'json', editable: true };
  const sandbox = {
    sourceRestore: {}, state, sourceRequest: 17,
    dirty: kind => !!state[kind] && editor.value !== (state[kind].content ?? ''),
    window: { confirm: message => { calls.confirms.push(message); return confirmResult; } },
    api: api || (async (route, body) => { calls.api.push({ route, body }); return nativeSource; }),
    setEditor: (kind, value, language, readonly) => {
      calls.setEditor.push({ kind, value, language, readonly });
      editor.value = value;
    },
    showSourceBasis: value => calls.basis.push(value),
    editorChanged: kind => calls.changed.push(kind),
    toast: message => calls.toasts.push(message),
    $: id => { assert.equal(id, 'source-content'); return editor; },
    guard: fn => async (...args) => {
      try { return await fn(...args); }
      catch (error) { calls.toasts.push(`ERROR: ${error.message}`); }
    },
  };
  vm.runInNewContext(handlerSource, sandbox, { filename: appPath });
  return { editor, source, state, calls, sandbox, handler: sandbox.sourceRestore.onclick, nativeSource };
}

function expectedRequest() {
  return { route: '/api/source/remove', body: {
    id: 'global_fixture', revision: 'saved-revision', variant: 'global-initializer',
  } };
}

(async () => {
  const canceled = setup({ content: '[9, 9]', saved: '[1, 2]', confirmResult: false });
  await canceled.handler();
  assert.equal(canceled.calls.confirms.length, 1);
  assert.equal(canceled.calls.api.length, 0, 'cancel sends no restore request');
  assert.equal(canceled.editor.value, '[9, 9]', 'cancel preserves unsaved text');
  assert.equal(canceled.state.source, canceled.source, 'cancel preserves selection and baseline');
  assert.equal(canceled.calls.toasts.length, 0);

  const confirmed = setup({ content: '[9, 9]', saved: '[1, 2]', confirmResult: true,
    api: async (route, body) => { confirmed.calls.api.push({ route, body }); return confirmed.nativeSource; } });
  await confirmed.handler();
  assert.equal(JSON.stringify(confirmed.calls.api), JSON.stringify([expectedRequest()]));
  assert.equal(confirmed.state.source, confirmed.nativeSource, 'restored source becomes the active selection');
  assert.equal(confirmed.editor.value, confirmed.nativeSource.content, 'unchanged editor reopens with native content');
  assert.equal(confirmed.calls.setEditor.length, 1);
  assert.equal(confirmed.calls.changed.length, 1);
  assert.equal(confirmed.calls.toasts.length, 1);

  const clean = setup({ content: '[1, 2]', saved: '[1, 2]', confirmResult: false });
  await clean.handler();
  assert.equal(clean.calls.confirms.length, 0, 'clean restore does not prompt');
  assert.equal(clean.calls.api.length, 1);
  assert.equal(clean.editor.value, clean.nativeSource.content);

  const rejected = setup({ content: '[9, 9]', saved: '[1, 2]', confirmResult: true,
    api: async (route, body) => { rejected.calls.api.push({ route, body }); throw new Error('revision conflict'); } });
  await rejected.handler();
  assert.equal(rejected.state.source, rejected.source, 'failed restore leaves source selection intact');
  assert.equal(rejected.editor.value, '[9, 9]', 'failed restore keeps editor text');
  assert.deepEqual(rejected.calls.toasts, ['ERROR: revision conflict']);
  assert.equal(rejected.calls.setEditor.length, 0, 'failed restore does not reset the editor');

  let resolveInFlight;
  const inFlight = setup({ content: '[1, 2]', saved: '[1, 2]', api: async (route, body) => {
    inFlight.calls.api.push({ route, body });
    return new Promise(resolve => { resolveInFlight = resolve; });
  } });
  const pending = inFlight.handler();
  inFlight.editor.value = '[7, 8]';
  resolveInFlight(inFlight.nativeSource);
  await pending;
  assert.equal(inFlight.state.source, inFlight.nativeSource);
  assert.equal(inFlight.editor.value, '[7, 8]', 'new text typed during restore stays in the editor');
  assert.equal(inFlight.sandbox.dirty('source'), true, 'new text remains dirty against restored baseline');
  assert.equal(inFlight.calls.setEditor.length, 0, 'in-flight edit is not overwritten');

  let resolveNavigation;
  const navigation = setup({ content: '[1, 2]', saved: '[1, 2]', api: async (route, body) => {
    navigation.calls.api.push({ route, body });
    return new Promise(resolve => { resolveNavigation = resolve; });
  } });
  const navigationPending = navigation.handler();
  const otherSource = { id: 'other_global', variant: 'global-initializer', content: 'other' };
  navigation.state.source = otherSource;
  navigation.sandbox.sourceRequest += 1;
  navigation.editor.value = 'other text';
  resolveNavigation(navigation.nativeSource);
  await navigationPending;
  assert.equal(navigation.state.source, otherSource, 'navigation during restore keeps the new selection');
  assert.equal(navigation.editor.value, 'other text', 'navigation during restore keeps the new editor buffer');
  assert.equal(navigation.calls.setEditor.length, 0);
  assert.equal(navigation.calls.toasts.length, 0, 'stale restore response is not announced as the current selection');

  process.stdout.write('Restore initializer regression passed: cancel, confirm, clean restore, API failure, in-flight edit, and navigation race.\n');
})().catch(error => { console.error(error); process.exitCode = 1; });
