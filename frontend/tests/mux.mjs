import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { computed, reactive, ref, watch } from 'vue'

const source = readFileSync(new URL('../src/views/ProxiesView.vue', import.meta.url), 'utf8')
const script = source.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
test('mapping mux defaults off, round-trips edits and is not sent for UDP', async () => {
  const requests = []
  const desk = { nodes: [{ id: 's', role: 'server' }, { id: 'c', role: 'client' }], mappings: [], reload: async () => {}, notify: () => {} }
  const context = vm.createContext({ exports: {}, computed, reactive, ref, watch, inject: () => desk, deskKey: {}, validateMapping: () => '', api: async (...args) => requests.push(args) })
  vm.runInContext(ts.transpileModule(script + '\nglobalThis.editor = { open, draft, muxType, save, fields };', { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText, context)
  const e = context.editor
  e.open()
  assert.equal(e.draft.mux, false)
  await e.save()
  assert.equal(requests.at(-1)[2].mux, false)
  assert.equal(requests.at(-1)[2].mux_type, '')
  e.draft.mux = true
  await e.save()
  assert.equal(requests.at(-1)[2].mux, true)
  assert.equal(requests.at(-1)[2].mux_type, 'smux')
  e.open({ id: 'm', name: 'test', server_id: 's', client_id: 'c', pool: 1, mux: true, listen_host: '127.0.0.1', listen_port: 8080, target_host: 'localhost', target_port: 80, network: 'tcp', enabled: true })
  assert.equal(e.draft.mux, true)
  assert.equal(e.muxType.value, 'smux')
  await e.save()
  assert.equal(requests.at(-1)[2].mux_type, 'smux')
  for (const type of ['smux', 'yamux', 'h2mux']) {
    e.muxType.value = type
    await e.save()
    assert.equal(requests.at(-1)[2].mux_type, type)
    e.open({ ...requests.at(-1)[2], id: 'm' })
    assert.equal(e.muxType.value, type)
  }
  e.draft.mux = false
  assert.equal(e.muxType.value, '')
  await e.save()
  assert.equal(requests.at(-1)[2].mux_type, '')
  e.draft.mux = true
  assert.equal(e.muxType.value, 'smux')
  e.muxType.value = 'yamux'
  e.draft.network = 'udp'
  assert.equal(e.draft.mux, false)
  assert.equal(e.muxType.value, '')
  await e.save()
  assert.equal(requests.at(-1)[2].mux, false)
  assert.equal(requests.at(-1)[2].mux_type, '')
  e.draft.network = 'tcp'
  assert.equal(e.draft.mux, false)
  e.open()
  assert.equal(e.draft.mux, false)
})
test('mux guidance explains default, isolation, Vision and apply interruption', () => {
  for (const text of ['TCP mux（默认关闭）', '独立认证连接', 'Vision 不直拷', 'UDP 始终使用 XUDP', '自动重建', '现有连接会断开']) assert.ok(source.includes(text), text)
  assert.ok(source.includes('v-if="draft.network === \'tcp\' && draft.mux"'))
  for (const type of ['smux', 'yamux', 'h2mux']) assert.ok(source.includes(`<option value="${type}">${type}</option>`))
  assert.doesNotMatch(source, /private-session|私有共享会话/)
})
