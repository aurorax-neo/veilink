import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { computed, reactive } from 'vue'

const source = path => readFileSync(new URL(path, import.meta.url), 'utf8')
const transpile = text => ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText
const format = vm.createContext({ exports: {}, TextEncoder })
vm.runInContext(transpile(source('../src/format.ts')), format)
const { heartbeatOnline, revisionState, attentionReasons, nodeName, presence, byNameAndId } = format.exports

test('heartbeat boundaries and failed revisions remain distinct', () => {
  const now = 1000_000
  const node = { last_seen: 925, revoked: false, applied_revision: 2, desired_revision: 3, error: 'apply failed' }
  assert.equal(heartbeatOnline(node, now), true)
  assert.equal(revisionState(node).text, '应用失败')
  for (const last_seen of [0, 910, 909, 1001]) assert.equal(heartbeatOnline({ ...node, last_seen }, now), false)
  assert.equal(heartbeatOnline({ ...node, last_seen: 911 }, now), true)
  assert.equal(heartbeatOnline({ ...node, revoked: true }, now), false)
  assert.equal(revisionState({ ...node, error: '' }).text, '待应用')
  assert.equal(revisionState({ ...node, error: '', applied_revision: 3 }).text, '已应用')
  assert.equal(revisionState({ ...node, error: '', desired_revision: 0, applied_revision: 0 }).text, '尚无配置')
  assert.equal(revisionState({ ...node, error: '', applied_revision: 0 }).text, '待应用')
  assert.equal(revisionState({ ...node, revoked: true }).text, '不再同步')
})

test('Dashboard metrics use actual node and mapping state', () => {
  const now = Math.floor(Date.now() / 1000)
  const desk = reactive({
    nodes: [
      { id: 's', role: 'server', last_seen: now - 75, applied_revision: 2, desired_revision: 2 },
      { id: 'c', role: 'client', last_seen: now, applied_revision: 1, desired_revision: 2, error: 'apply failed' },
      { id: 'old', role: 'client', last_seen: now - 100, applied_revision: 2, desired_revision: 2 },
      { id: 'revoked', role: 'server', last_seen: now, revoked: true },
    ],
    mappings: [{ enabled: true }, { enabled: false }],
  })
  const vue = source('../src/views/DashboardView.vue')
  const script = vue.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
  const context = vm.createContext({ exports: {}, computed, byNameAndId, inject: key => key === 'desk' ? desk : () => {}, deskKey: 'desk', navigateKey: 'navigate', heartbeatOnline, attentionReasons, nodeName, presence, revisionState })
  vm.runInContext(transpile(script + '\nglobalThis.metrics = { onlineServers, onlineClients, attention };'), context)
  assert.equal(context.metrics.onlineServers.value, 1)
  assert.equal(context.metrics.onlineClients.value, 1)
  assert.equal(context.metrics.attention.value.length, 2)
  assert.equal(attentionReasons({ id: 'off', disabled: true, last_seen: 0, applied_revision: 1, desired_revision: 4, error: 'apply failed' }).length, 0)
  desk.nodes.push({ id: 'stopped', role: 'server', disabled: true, last_seen: now, applied_revision: 1, desired_revision: 9 })
  assert.equal(context.metrics.attention.value.length, 2)
  assert.equal(context.metrics.onlineServers.value, 1)
  const expression = vue.match(/{{\s*(desk\.mappings\.filter\(m => m\.enabled\)\.length)\s*}}/)[1]
  assert.equal(vm.runInContext(expression, context), 1)
  desk.mappings[0].enabled = false
  desk.nodes[1].revoked = true
  assert.equal(vm.runInContext(expression, context), 0)
  assert.equal(context.metrics.onlineClients.value, 0)
})
