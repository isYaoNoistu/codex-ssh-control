import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';

class Element {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase(); this.children = []; this.dataset = {}; this.attributes = {};
    this.value = ''; this.checked = false; this.disabled = false; this.hidden = false; this._text = '';
    this.classList = { add() {}, remove() {}, toggle() {} };
    this.style = { setProperty() {} };
  }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text + this.children.map(child => child.textContent ?? child).join(''); }
  set innerHTML(_) { throw new Error('Host data must never be rendered through innerHTML.'); }
  append(...items) { this.children.push(...items); }
  appendChild(item) { this.append(item); return item; }
  replaceChildren(...items) { this._text = ''; this.children = items; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
  getAttribute(key) { return this.attributes[key] ?? null; }
  removeAttribute(key) { delete this.attributes[key]; }
  addEventListener(type, handler) { this['on' + type] = handler; }
  focus() {} scrollIntoView() {} reportValidity() { return true; }
  async click() { if (!this.disabled) return this.onclick?.({ preventDefault() {}, target: this }); }
}
const host = (id, overrides = {}) => ({ id, name: id, hostname: id + '.example.invalid', port: 22, username: 'deploy', identityFile: '', sshAlias: '', defaultCwd: '', enabled: true, ...overrides });
const initial = (overrides = {}) => ({ threadId: 'trusted-thread-123456789', hosts: [host('prod'), host('uat')], grantedHostIds: [], shortcutHelp: '/ssh-prod /ssh-uat', ...overrides });
const settle = async () => { for (let i = 0; i < 12; i++) await new Promise(resolve => setImmediate(resolve)); };

async function harness(startState = initial(), override) {
  let html = '';
  try { html = await readFile(new URL('../ui/panel.html', import.meta.url), 'utf8'); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  assert.ok(html, 'The SSH host panel must exist.');
  const source = html.match(/<script>([\s\S]*?)<\/script>/)?.[1];
  assert.ok(source, 'Panel must contain its self-contained UI controller.');
  const ids = new Map([...html.matchAll(/<([a-z][a-z0-9]*)\b[^>]*\bid="([^"]+)"[^>]*>/gi)].map(match => { const element = new Element(match[1]); element.textContent = html.slice(match.index + match[0].length).split('<')[0]; return [match[2], element]; }));
  const listeners = new Map(), documentListeners = new Map(), calls = [], messages = [], intervals = [], timeouts = new Map(), timeoutDelays = [];
  let nextTimer = 0, state = structuredClone(startState);
  const document = {
    hidden: false, documentElement: new Element('html'), body: new Element('body'),
    getElementById: id => { assert.ok(ids.has(id), 'Unknown element ' + id); return ids.get(id); },
    createElement: tag => new Element(tag),
    addEventListener: (event, handler) => documentListeners.set(event, handler),
  };
  const parent = { postMessage(message) {
    messages.push(structuredClone(message));
    if (!Object.hasOwn(message, 'id')) return;
    queueMicrotask(async () => {
      let result;
      if (message.method === 'ui/initialize') result = { protocolVersion: '2026-01-26', hostInfo: { name: 'test-host', version: '1' }, hostCapabilities: {}, hostContext: { threadId: 'ui-context-only', theme: 'light' } };
      else if (message.method === 'tools/call') {
        const call = structuredClone(message.params); calls.push(call);
        result = await override?.(call, state);
        if (!result) {
          if (call.name === 'ssh_grant') state.grantedHostIds = [...new Set([...state.grantedHostIds, ...call.arguments.hostIds])];
          if (call.name === 'ssh_revoke') state.grantedHostIds = state.grantedHostIds.filter(id => !call.arguments.hostIds.includes(id));
          if (call.name === 'ssh_host_save') { const h = structuredClone(call.arguments.host); state.hosts = [...state.hosts.filter(item => item.id !== h.id), h]; }
          if (call.name === 'ssh_host_enabled') state.hosts = state.hosts.map(h => h.id === call.arguments.hostId ? { ...h, enabled: call.arguments.enabled } : h);
          if (call.name === 'ssh_host_remove') { state.hosts = state.hosts.filter(h => h.id !== call.arguments.hostId); state.grantedHostIds = state.grantedHostIds.filter(id => id !== call.arguments.hostId); }
          result = { structuredContent: { state: structuredClone(state) }, content: [] };
        }
      } else result = {};
      listeners.get('message')?.({ source: parent, data: { jsonrpc: '2.0', id: message.id, result } });
    });
  } };
  const window = { parent, addEventListener: (event, handler) => listeners.set(event, handler) };
  const context = vm.createContext({ document, window, crypto: webcrypto, atob, btoa, Uint8Array, console, Map, Set, Object, Array, String, Number, Boolean, Date, Error,
    setTimeout: (handler, delay) => { const id = ++nextTimer; timeouts.set(id, handler); timeoutDelays.push(delay); return id; }, clearTimeout: id => timeouts.delete(id),
    setInterval: handler => { intervals.push(handler); return intervals.length; }, clearInterval() {},
  });
  new vm.Script(source, { filename: 'ssh-control-panel.js' }).runInContext(context);
  await settle();
  function findAction(action, id) {
    const walk = element => {
      if (element.dataset?.action === action && element.dataset?.hostId === id) return element;
      for (const child of element.children ?? []) { const found = walk(child); if (found) return found; }
    };
    for (const element of ids.values()) { const found = walk(element); if (found) return found; }
    assert.fail('Missing action ' + action + ' for ' + id);
  }
  return { ids, calls, messages, intervals, timeouts, timeoutDelays, document, documentListeners, findAction, settle, state: () => state };
}

const reply = (state, extra = {}) => ({ content: [], structuredContent: { state: structuredClone(state), ...extra } });
const walk = (el, predicate) => predicate(el) ? el : (el.children || []).map(child => walk(child, predicate)).find(Boolean);
const field = (el, name) => walk(el, item => item.dataset?.field === name);
const publicKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJJMpQTZ72aCrNvXhtf7A/rXHeXWQvi7rYNb3l2xkzuE';
const policy = () => ({mode:'restricted',roots:[{id:'app',path:'/srv/app',read:true,write:true,match:'exact'}],blockedPaths:[],commandRules:[],actions:{'service.restart':'ask'},grantMinutes:60,timeoutSeconds:60,maxConcurrent:2,maxOutputKiB:128,localRoots:[{id:'build',path:'C:/artifacts',read:true,write:false,match:'recursive'}],actionArguments:{'service.restart':{names:['nginx']}},jobs:{enabled:true,timeoutSeconds:7200,maxOutputKiB:512,allowedShells:['/bin/bash'],allowedEnv:['BUILD_ID'],cpuSeconds:300,maxMemoryMiB:1024,maxProcesses:32},transfers:{enabled:true,maxBytes:12345,maxEntries:8,timeoutSeconds:180}});
const catalog = [{id:'service.restart',label:'重启服务',description:'',mutating:true,defaultDecision:'ask',parameters:[{name:'name',label:'服务名'}]}];

test('managed connection saves structured jumps and preserves confirmed host keys', async () => {
  const connection = {mode:'managed',hostKeys:[publicKey],jumpHosts:[{hostname:'jump.invalid',username:'jump',port:2222,identityFile:'',hostKeys:[publicKey]}],connectTimeoutSeconds:12,keepaliveIntervalSeconds:16,keepaliveCountMax:3,pooling:{enabled:false,persistSeconds:70}};
  const h = await harness(initial({hosts:[host('prod',{connection})]}));
  await h.findAction('edit','prod').click();
  assert.equal(h.ids.get('connection-mode').value,'managed');
  assert.equal(h.ids.get('jump-hosts').children.length,1);
  h.ids.get('connection-timeout').value='20';
  await h.ids.get('host-form').onsubmit({preventDefault(){}}); await settle();
  const saved=h.calls.find(c=>c.name==='ssh_host_save').arguments.host.connection;
  assert.equal(saved.connectTimeoutSeconds,20); assert.deepEqual(saved.jumpHosts,connection.jumpHosts); assert.deepEqual(saved.hostKeys,[publicKey]);
});

test('policy editor preserves infrastructure fields and exact directory rules', async () => {
  const h=await harness(initial(),(call,state)=>call.name==='ssh_permissions'?reply(state,{policy:{hostId:'prod',revision:3,policy:policy()},actions:catalog}):undefined);
  await h.findAction('policy','prod').click(); await settle();
  h.ids.get('policy-timeout').value='91';
  await h.ids.get('policy-form').onsubmit({preventDefault(){}}); await settle();
  const saved=h.calls.find(c=>c.name==='ssh_policy_save').arguments.policy;
  assert.equal(saved.timeoutSeconds,91);
  for(const key of ['localRoots','actionArguments','jobs','transfers','roots']) assert.deepEqual(saved[key],policy()[key],key);
});

test('scanning only displays untrusted candidates and requires explicit fingerprint confirmation', async () => {
  const h=await harness(initial({hosts:[host('prod',{connection:{mode:'managed',hostKeys:[],jumpHosts:[]}})]}),(call,state)=>call.name==='ssh_host_key_scan'?reply(state,{candidates:[{type:'ssh-ed25519',publicKey,fingerprint:'SHA256:from-server',source:'scan',trusted:false}]}):undefined);
  await h.findAction('edit','prod').click();
  const keys=h.ids.get('target-host-keys');
  await field(keys,'scan').click(); await settle();
  assert.equal(h.calls.some(c=>c.name==='ssh_host_keys_confirm'),false);
  assert.match(keys.textContent,/SHA256:/);
  assert.equal(field(keys,'confirm').disabled,true);
});

test('jobs display escaped output, use byte cursors and cancel with exact identity', async () => {
  const job={id:'job-1',hostId:'prod',status:'running',observation:'unknown',operation:{command:'echo hello'},output:'<img src=x>',nextCursor:10,hasMore:true};
  const h=await harness(initial({grantedHostIds:['prod']}),(call,state)=>call.name==='ssh_job_list'?reply(state,{jobs:[job],nextCursor:'page-2'}):call.name==='ssh_job_read'?reply(state,{job:{...job,output:call.arguments.cursor?' next':'<img src=x>',hasMore:!call.arguments.cursor}}):undefined);
  await h.ids.get('tab-history').click(); await settle();
  h.ids.get('execution-kind').value='jobs'; await h.ids.get('execution-kind').onchange(); await settle();
  await walk(h.ids.get('infrastructure-list'),e=>e.dataset?.taskId==='job-1').click(); await settle();
  assert.match(h.ids.get('infrastructure-detail').textContent,/<img src=x>/);
  await h.ids.get('infrastructure-output-more').click(); await settle();
  assert.equal(h.calls.filter(c=>c.name==='ssh_job_read').at(-1).arguments.cursor,10);
  await h.ids.get('infrastructure-cancel').click(); await settle();
  const call=h.calls.find(c=>c.name==='ssh_job_cancel'); assert.equal(call.arguments.taskId,'job-1'); assert.ok(call.arguments.explanation); assert.equal(call.arguments.uiToken,undefined);
});

test('transfer details show progress and resume is disabled after grant expires', async () => {
  const transfer={id:'transfer-1',hostId:'prod',status:'interrupted',direction:'upload',localPath:'C:/build/a',remotePath:'/srv/a',bytesTransferred:5,totalBytes:10};
  const h=await harness(initial(),(call,state)=>call.name==='ssh_transfer_list'?reply(state,{transfers:[transfer]}):call.name==='ssh_transfer_read'?reply(state,{transfer}):undefined);
  await h.ids.get('tab-history').click(); await settle(); h.ids.get('execution-kind').value='transfers'; await h.ids.get('execution-kind').onchange(); await settle();
  await walk(h.ids.get('infrastructure-list'),e=>e.dataset?.transferId==='transfer-1').click(); await settle();
  assert.match(h.ids.get('infrastructure-detail').textContent,/5.*10/); assert.equal(h.ids.get('infrastructure-resume').disabled,true);
});

test('unconfirmed pasted keys block save and checked keys use the app-only compare-and-set confirmation', async () => {
  const h=await harness(initial({hosts:[host('prod',{connection:{mode:'managed',hostKeys:[],jumpHosts:[]}})]}));
  await h.findAction('edit','prod').click();
  const keys=h.ids.get('target-host-keys'),input=field(keys,'publicKeys');input.value=publicKey;await input.oninput();
  await h.ids.get('host-form').onsubmit({preventDefault(){}});await settle();
  assert.equal(h.calls.some(c=>c.name==='ssh_host_save'),false);
  const check=field(keys,'verified');check.checked=true;check.onchange();
  await field(keys,'confirm').click();await settle();
  const call=h.calls.find(c=>c.name==='ssh_host_keys_confirm');
  assert.deepEqual(call.arguments.candidates,[publicKey]);assert.deepEqual(call.arguments.expectedCurrentFingerprints,[]);
  assert.match(call.arguments.fingerprints[0],/^SHA256:[A-Za-z0-9+/]{43}$/);assert.equal(call.arguments.hopIndex,-1);assert.equal(call.arguments.confirmed,true);assert.equal(call.arguments.uiToken,'__SSH_UI_TOKEN__');
});

test('native mode requires explicit trust and serializes the SSH alias without stale direct fields', async () => {
  const h=await harness();await h.findAction('edit','prod').click();
  h.ids.get('connection-mode').value='native';h.ids.get('connection-mode').onchange();h.ids.get('host-alias').value='trusted-config';
  await h.ids.get('host-form').onsubmit({preventDefault(){}});assert.equal(h.calls.some(c=>c.name==='ssh_host_save'),false);
  h.ids.get('native-trust').checked=true;await h.ids.get('host-form').onsubmit({preventDefault(){}});await settle();
  const saved=h.calls.find(c=>c.name==='ssh_host_save').arguments.host;assert.deepEqual(saved.connection,{mode:'native',trustedLocalConfig:true});assert.equal(saved.hostname,'');assert.equal(saved.sshAlias,'trusted-config');
});

test('runtime list pagination uses server cursor and ignores late replies after changing record type', async () => {
  let release;
  const h=await harness(initial(),(call,state)=>call.name==='ssh_job_list'?(call.arguments.cursor?new Promise(resolve=>{release=()=>resolve(reply(state,{jobs:[{id:'late-job',hostId:'prod',status:'running'}]}));}):reply(state,{jobs:[{id:'first',hostId:'prod',status:'running'}],nextCursor:20})):call.name==='ssh_transfer_list'?reply(state,{transfers:[]}):undefined);
  await h.ids.get('tab-history').click();await settle();h.ids.get('execution-kind').value='jobs';await h.ids.get('execution-kind').onchange();await settle();
  const pending=h.ids.get('infrastructure-more').click();await settle();assert.equal(h.calls.filter(c=>c.name==='ssh_job_list').at(-1).arguments.cursor,20);
  h.ids.get('execution-kind').value='transfers';await h.ids.get('execution-kind').onchange();await settle();release();await pending;await settle();
  assert.doesNotMatch(h.ids.get('infrastructure-list').textContent,/late-job/);
});

test('native cancellation approval locks controls for up to 180 seconds and failure is shown safely', async () => {
  let finish;
  const job={id:'job-1',hostId:'prod',status:'running',output:''};
  const h=await harness(initial({grantedHostIds:['prod']}),(call,state)=>call.name==='ssh_job_list'?reply(state,{jobs:[job]}):call.name==='ssh_job_read'?reply(state,{job}):call.name==='ssh_job_cancel'?new Promise(resolve=>{finish=()=>resolve({isError:true,content:[{type:'text',text:'APPROVAL_DECLINED: 用户拒绝 <取消>'}]});}):undefined);
  await h.ids.get('tab-history').click();await settle();h.ids.get('execution-kind').value='jobs';await h.ids.get('execution-kind').onchange();await settle();await walk(h.ids.get('infrastructure-list'),e=>e.dataset?.taskId==='job-1').click();await settle();
  const pending=h.ids.get('infrastructure-cancel').click();await settle();assert.equal(h.ids.get('execution-kind').disabled,true);assert.equal(h.ids.get('infrastructure-cancel').disabled,true);assert.ok(h.timeoutDelays.includes(180000));finish();await pending;await settle();
  assert.match(h.ids.get('error-message').textContent,/用户拒绝 <取消>/);assert.equal(h.ids.get('execution-kind').disabled,false);
});

test('Windows capability probe disables unsupported pooling and renders prerequisites as text', async () => {
  const h=await harness(initial({grantedHostIds:['prod'],hosts:[host('prod',{connection:{mode:'managed',hostKeys:[publicKey],jumpHosts:[]}})]}),(call,state)=>call.name==='ssh_capabilities'?reply(state,{capabilities:{local:{platform:'win32',pooling:{supported:false,reason:'Windows 不支持连接复用'}},remote:{os:'Linux',python:{version:'3.12'},tasksReady:true,transfersReady:false}}}):undefined);
  await h.findAction('edit','prod').click();await h.ids.get('probe-capabilities').click();await settle();assert.equal(h.ids.get('connection-pooling').disabled,true);assert.match(h.ids.get('capabilities-result').textContent,/Windows.*不支持/);assert.match(h.ids.get('capabilities-result').textContent,/前置条件不满足/);
});

test('revoked job details request cached output without attempting remote refresh',async()=>{
  const job={id:'job-1',hostId:'prod',status:'running',output:'cached output'};
  const h=await harness(initial(),(call,state)=>call.name==='ssh_job_list'?reply(state,{jobs:[job]}):call.name==='ssh_job_read'?
    (call.arguments.refresh?{isError:true,content:[{type:'text',text:'grant revoked'}]}:reply(state,{job})):undefined);
  await h.ids.get('tab-history').click();h.ids.get('execution-kind').value='jobs';await h.ids.get('execution-kind').onchange();await settle();
  await walk(h.ids.get('infrastructure-list'),e=>e.dataset?.taskId==='job-1').click();await settle();
  assert.equal(h.calls.find(c=>c.name==='ssh_job_read').arguments.refresh,false);
  assert.match(h.ids.get('infrastructure-detail').textContent,/cached output/);assert.equal(h.ids.get('infrastructure-cancel').disabled,true);
});

test('switching an existing managed connection to legacy explicitly clears merged connection settings',async()=>{
  const h=await harness(initial({hosts:[host('prod',{connection:{mode:'managed',hostKeys:[publicKey],jumpHosts:[]}})]}));
  await h.findAction('edit','prod').click();h.ids.get('connection-mode').value='legacy';h.ids.get('connection-mode').onchange();
  await h.ids.get('host-form').onsubmit({preventDefault(){}});await settle();
  assert.equal(h.calls.find(c=>c.name==='ssh_host_save').arguments.host.connection,null);
});
