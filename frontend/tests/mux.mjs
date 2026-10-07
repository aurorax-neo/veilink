import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { computed, reactive, ref, watch, watchEffect } from 'vue'

const source = readFileSync(new URL('../src/views/ProxiesView.vue', import.meta.url), 'utf8')
const script = source.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
test('mapping mux select defaults off, round-trips every option and clears for UDP', async () => {
  const requests = []
  const desk = { nodes: [{ id: 's', role: 'server' }, { id: 'c', role: 'client' }], mappings: [], reload: async () => {}, notify: () => {} }
  const context = vm.createContext({ exports: {}, computed, reactive, ref, watch, watchEffect, byNameAndId: (a, b) => (a.name || '').localeCompare(b.name || '') || a.id.localeCompare(b.id), inject: () => desk, deskKey: {}, validateMapping: () => '', api: async (...args) => requests.push(args), onMounted: () => {}, onUnmounted: () => {} })
  vm.runInContext(ts.transpileModule(script + '\nglobalThis.editor = { open, draft, muxType, save, fields };', { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText, context)
  const e = context.editor
  e.open()
  assert.equal(e.muxType.value, '')
  assert.equal(e.draft.bandwidthLimit, '0')
  e.draft.bandwidthLimit = '48'
  await e.save()
  assert.equal(requests.at(-1)[2].bandwidth_limit, '48Mbps')
  e.open({ ...requests.at(-1)[2], id: 'm' })
  assert.equal(e.draft.bandwidthLimit, '48')
  for (const [value, expected] of [['1500Kbps', '1.5'], ['1.234Kbps', '0.001234'], ['0.048Gbps', '48'], ['', '0']]) {
    assert.equal(e.fields({ ...requests.at(-1)[2], bandwidth_limit: value }).bandwidthLimit, expected)
  }
  e.draft.bandwidthLimit = '0'
  await e.save()
  assert.equal(requests.at(-1)[2].bandwidth_limit, '')
  await e.save()
  assert.equal(requests.at(-1)[2].mux, false)
  assert.equal(requests.at(-1)[2].mux_type, '')
  e.open({ id: 'm', name: 'test', server_id: 's', client_id: 'c', pool: 1, mux: true, listen_host: '127.0.0.1', listen_port: 8080, target_host: 'localhost', target_port: 80, network: 'tcp', enabled: true })
  assert.equal(e.muxType.value, 'smux')
  for (const type of ['smux', 'yamux', 'h2mux', '']) {
    e.muxType.value = type
    await e.save()
    assert.equal(requests.at(-1)[2].mux, type !== '')
    assert.equal(requests.at(-1)[2].mux_type, type)
    e.open({ ...requests.at(-1)[2], id: 'm' })
    assert.equal(e.muxType.value, type)
  }
  e.muxType.value = 'yamux'
  e.draft.network = 'udp'
  assert.equal(e.muxType.value, '')
  await e.save()
  assert.equal(requests.at(-1)[2].mux, false)
  assert.equal(requests.at(-1)[2].mux_type, '')
  e.draft.network = 'tcp'
  assert.equal(e.muxType.value, '')
  e.open({ ...requests.at(-1)[2], network: 'udp', mux: true, mux_type: 'h2mux' })
  assert.equal(e.muxType.value, '')
  e.open()
  assert.equal(e.muxType.value, '')
})
test('mux uses one standard dropdown with off and three protocols, never checkbox or radio', () => {
  for (const text of ['TCP mux（默认关闭）', '带宽上限（Mbps）', '0（不限速）', 'type="number"']) assert.ok(source.includes(text), text)
  assert.ok(!source.includes('现有连接会断开'))
  const select = source.match(/<select id="map-mux-type"[^>]*>[\s\S]*?<\/select>/)?.[0]
  assert.ok(select)
  assert.ok(select.includes(':disabled="draft.network !== \'tcp\'"'))
  assert.ok(select.includes('<option value="">关闭</option>'))
  assert.equal((select.match(/<option /g) || []).length, 4)
  for (const type of ['smux', 'yamux', 'h2mux']) assert.ok(select.includes(`<option value="${type}">${type}</option>`))
  assert.doesNotMatch(source, /<input[^>]*(?:id="map-mux|v-model="(?:draft.mux|muxType)")|private-session|私有共享会话/)
})
