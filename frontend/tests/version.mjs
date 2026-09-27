import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { ref } from 'vue'

const source = path => readFileSync(new URL(path, import.meta.url), 'utf8')
const view = source('../src/views/ConsoleView.vue')
const script = view.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
function setup(api) {
  const context = vm.createContext({ exports: {}, ref, api, inject: () => ({}), deskKey: {}, defineProps: () => {}, defineEmits: () => {}, onMounted: () => {} })
  vm.runInContext(ts.transpileModule(script + '\nglobalThis.state = { loadVersion, software, versionError };', { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText, context)
  return context.state
}

test('software metadata comes from authenticated API, separate from configuration revisions', async () => {
  const state = setup(async path => { assert.equal(path, '/version'); return { version: 'v1.2.3', commit: 'a'.repeat(40) } })
  await state.loadVersion()
  assert.equal(state.software.value.version, 'v1.2.3')
  assert.equal(state.versionError.value, false)
  const nodes = source('../src/components/NodesTable.vue')
  assert.match(nodes, /配置修订/)
  assert.match(nodes, /期望 r{{ node.desired_revision }}/)
  assert.match(nodes, /已应用 r{{ node.applied_revision }}/)
  assert.match(nodes, /node.software_version \|\| '未上报'/)
  assert.doesNotMatch(nodes, /<th[^>]*>版本<\/th>/)
  assert.match(nodes, /节点上报，未验真/)
  assert.match(nodes, /tools\/verify-node\.py/)
  assert.match(nodes, /独立可信的发布 SHA-256/)
})

test('software metadata failure is visible and retryable without breaking the console', async () => {
  let failed = true
  const state = setup(async () => { if (failed) throw new Error('network'); return { version: 'dev', commit: 'unknown' } })
  await state.loadVersion()
  assert.equal(state.versionError.value, true)
  assert.equal(state.software.value, null)
  failed = false
  await state.loadVersion()
  assert.equal(state.versionError.value, false)
  assert.equal(state.software.value.version, 'dev')
})
