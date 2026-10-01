import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { computed, reactive, ref, watch, watchEffect } from 'vue'
import { parse, compileScript, compileTemplate } from '@vue/compiler-sfc'

const read = path => readFileSync(new URL(path, import.meta.url), 'utf8')
const view = read('../src/views/ProxiesView.vue')
const script = view.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
const transpile = text => ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText
const format = vm.createContext({ exports: {}, TextEncoder })
vm.runInContext(transpile(read('../src/format.ts')), format)
const candidate = (id, enabled = true) => ({ id, name: id, host: `${id}.example.com`, port: 443, enabled })
function setup() {
  const requests = []
  const desk = reactive({ nodes: [
    { id: 's', name: 'Server', role: 'server', address: 'a.example.com', port: 443, tunnel: { listen_port: 8444 }, connect_endpoints: [candidate('off', false), candidate('a'), candidate('b')] },
    { id: 'other', name: 'Other', role: 'server', connect_endpoints: [candidate('c')] },
    { id: 'client', name: 'Client', role: 'client' },
  ], mappings: [], reload: async () => {}, notify: () => {} })
  let tick = () => {}, unmount = () => {}
  const context = vm.createContext({ exports: {}, computed, reactive, ref, watch, watchEffect, ...format.exports, inject: () => desk, deskKey: {}, api: async (...args) => requests.push(args), onMounted: cb => { tick = cb }, onUnmounted: cb => { unmount = cb }, setInterval: cb => { tick = cb; return 7 }, clearInterval: () => {}, registerPageRefresh: () => () => {} })
  vm.runInContext(transpile(script + '\nglobalThis.editor = { open, draft, save, fields, connections, missingConnection, connectionLabel, tunnelState, statuses, now, ask, run };'), context)
  const editor = context.editor
  editor.open()
  editor.draft.serverId = 's'
  Object.assign(editor.draft, { name: 'Map', listenPort: '18080', targetPort: '80' })
  return { ...editor, desk, requests, tick: () => tick(), unmount: () => unmount() }
}

test('mapping defaults to first enabled endpoint, saves and restores explicit and automatic selection', async () => {
  const e = setup()
  assert.equal(e.draft.connectEndpointId, 'a')
  assert.deepEqual(Array.from(e.connections.value, item => item.id), ['a', 'b'])
  for (const id of ['b', '']) {
    e.draft.connectEndpointId = id
    await e.save()
    const body = e.requests.at(-1)[2]
    assert.equal(body.connect_endpoint_id, id)
    assert.equal(body.server_id, 's')
    assert.equal(body.client_id, 'client')
    assert.equal('connect_endpoints' in body, false)
    e.open({ ...body, id: 'map/id' })
    assert.equal(e.draft.connectEndpointId, id)
    assert.match(e.connectionLabel(body), id ? /b.example.com:443/ : /自动/)
  }
  e.open()
  e.draft.serverId = 's'
  assert.equal(e.draft.connectEndpointId, 'a')
})

test('switching server resets selection but editing stale selection does not silently fallback', async () => {
  const e = setup()
  e.draft.connectEndpointId = 'b'
  e.draft.serverId = 'other'
  assert.equal(e.draft.connectEndpointId, 'c')
  e.draft.connectEndpointId = 'a'
  await assert.rejects(e.save(), /不属于此服务端/)
  e.open({ id: 'm', name: 'Map', server_id: 's', client_id: 'client', connect_endpoint_id: 'gone', pool: 1, listen_host: '0.0.0.0', listen_port: 18080, target_host: 'localhost', target_port: 80, enabled: true })
  assert.equal(e.draft.connectEndpointId, 'gone')
  assert.equal(e.missingConnection.value, true)
  await assert.rejects(e.save(), /重新选择/)
  assert.equal(e.requests.length, 0)
})

test('disabled, deleted and revoked endpoint owners are rejected, including disabled mappings', async () => {
  const e = setup()
  e.draft.enabled = false
  e.draft.connectEndpointId = 'off'
  await assert.rejects(e.save(), /停用/)
  e.draft.connectEndpointId = 'a'
  e.desk.nodes[0].connect_endpoints.splice(1, 1)
  await assert.rejects(e.save(), /重新选择/)
  e.draft.connectEndpointId = ''
  e.desk.nodes[0].connect_endpoints.forEach(item => { item.enabled = false })
  await assert.rejects(e.save(), /没有启用/)
  e.desk.nodes[0].revoked = true
  await assert.rejects(e.save(), /可用的服务端/)
  assert.equal(e.requests.length, 0)
})

test('toggle retains selected endpoint and endpoint UI has explicit labels and empty states', async () => {
  const e = setup()
  const mapping = { id: 'm', name: 'Map', server_id: 's', client_id: 'client', connect_endpoint_id: 'b', enabled: true }
  e.ask(mapping, 'toggle')
  await e.run()
  assert.equal(e.requests[0][2].connect_endpoint_id, 'b')
  assert.equal(e.requests[0][2].enabled, false)
  assert.match(view, /label for="map-connection"/)
  assert.match(view, /id="map-connection".*v-model="draft.connectEndpointId"/)
  assert.match(view, /原连接地址不可用/)
  assert.match(view, /指定入口后只连接该地址/)
})

test('floating notifications occupy no layout space and expose dismissal and live announcements', () => {
  const consoleView = read('../src/views/ConsoleView.vue')
  const css = read('../src/styles.css')
  assert.doesNotMatch(consoleView + css, /notice-slot/)
  assert.match(css, /\.notice-layer\s*\{[^}]*position: fixed/)
  assert.match(css, /\.notice-layer\s*\{[^}]*calc\(100vw - 24px\)/)
  assert.match(consoleView, /class="notice-layer" aria-live="polite" aria-atomic="true"/)
  assert.match(consoleView, /aria-label="关闭提示" @click="desk.dismissNotice\(\)"/)
})

test('changed Vue templates compile with no malformed or duplicate editor blocks', () => {
  for (const path of ['../src/views/ProxiesView.vue', '../src/views/ConsoleView.vue', '../src/components/NodesTable.vue', '../src/components/NodeEditor.vue']) {
    const text = read(path)
    const parsed = parse(text, { filename: path })
    assert.deepEqual(parsed.errors, [])
    const compiled = compileScript(parsed.descriptor, { id: path })
    const template = compileTemplate({ source: parsed.descriptor.template.content, filename: path, id: path, compilerOptions: { bindingMetadata: compiled.bindings } })
    assert.deepEqual(template.errors, [])
    assert.doesNotMatch(text, /^CUT |^PUT /m)
  }
  assert.equal((read('../src/components/NodesTable.vue').match(/<NodeEditor /g) || []).length, 1)
})

test('tunnel state distinguishes disabled, offline and applied nodes without claiming reachability', () => {
  const e = setup()
  const mapping = { id: 'm', server_id: 's', client_id: 'client', enabled: true }
  assert.equal(e.tunnelState({ ...mapping, enabled: false }).text, '已停用')
  assert.equal(e.tunnelState(mapping).text, '两端离线')
  for (const node of [e.desk.nodes[0], e.desk.nodes[2]]) Object.assign(node, { last_seen: Math.floor(Date.now()/1000), desired_revision: 2, applied_revision: 2 })
  assert.equal(e.tunnelState(mapping).text, '未连接')
  e.statuses.value = { m: { server: { acknowledged: true, reason: 'acknowledged', linked: true }, client: { acknowledged: true, reason: 'acknowledged', linked: true } } }
  assert.equal(e.tunnelState(mapping).text, '已连接')
  e.desk.nodes[2].applied_revision = 1
  assert.equal(e.tunnelState(mapping).text, '已连接')
  e.desk.nodes[2].revoked = true
  assert.equal(e.tunnelState(mapping).text, '节点不可用')
  assert.match(view, /隧道状态/)
  assert.match(view, /已连接/)
  assert.doesNotMatch(view, /两端已应用|不是目标服务探针/)
  assert.equal(view.includes('.sort(byNameAndId)'), true)
  assert.doesNotMatch(view, /配置状态未知|待业务验证/)
})

test('mapping heartbeat status expires on local clock without new API data', () => {
 const e = setup()
 const stamp = Math.floor(Date.now()/1000)
 for (const node of [e.desk.nodes[0],e.desk.nodes[2]]) Object.assign(node,{last_seen:stamp,desired_revision:1,applied_revision:1,error:'',revoked:false})
 const mapping={enabled:true,server_id:'s',client_id:'client'}
 assert.equal(e.tunnelState(mapping).text,'未连接')
 e.statuses.value={ [mapping.id]: {server:{acknowledged:true,reason:'acknowledged',linked:true},client:{acknowledged:true,reason:'acknowledged',linked:true}} }
 assert.equal(e.tunnelState(mapping).text,'已连接')
 e.now.value=(stamp+91)*1000
 assert.equal(e.tunnelState(mapping).text,'两端离线')
 e.desk.nodes[0].last_seen=stamp+91
 assert.equal(e.tunnelState(mapping).text,'客户端离线')
 e.unmount()
})
