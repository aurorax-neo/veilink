import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { ref } from 'vue'

const source = path => readFileSync(new URL(path, import.meta.url), 'utf8')
const view = source('../src/views/ConsoleView.vue')
const script = view.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
function setup(getVersionInfo) {
  const context = vm.createContext({
    exports: {},
    ref,
    api: getVersionInfo,
    getVersionInfo: typeof getVersionInfo === 'function' ? getVersionInfo : async () => ({ backend_version: 'v1.2.3', api_version: 'v1', web_version: 'v1.2.3' }),
    inject: () => ({}),
    deskKey: {},
    defineProps: () => {},
    defineEmits: () => {},
    onMounted: () => {}
  })
  vm.runInContext(ts.transpileModule(script + '\nglobalThis.state = { loadVersion, software, versionError };', { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText, context)
  return context.state
}

test('software metadata comes from authenticated API, separate from configuration revisions', async () => {
  const state = setup(async () => ({ backend_version: 'v1.2.3', api_version: 'v1', web_version: 'v1.2.3' }))
  await state.loadVersion()
  assert.equal(state.software.value.backend_version, 'v1.2.3')
  assert.equal(state.versionError.value, false)
  const nodes = source('../src/components/NodesTable.vue')
  assert.match(nodes, /配置是否最新/)
  assert.match(nodes, /revisionLabel\(node\)/)
  assert.match(nodes, /更新状态/)
  assert.match(nodes, /node.software_version \|\| '未上报'/)
  assert.doesNotMatch(nodes, /<th[^>]*>版本<\/th>/)
  assert.match(nodes, /节点上报，未验真/)
  assert.match(nodes, /tools\/verify-node\.py/)
  assert.match(nodes, /独立可信的发布 SHA-256/)
})

test('software metadata failure is visible and retryable without breaking the console', async () => {
  let failed = true
  const state = setup(async () => { if (failed) throw new Error('network'); return { backend_version: 'dev', api_version: 'v1', web_version: 'dev' } })
  await state.loadVersion()
  assert.equal(state.versionError.value, true)
  assert.equal(state.software.value, null)
  failed = false
  await state.loadVersion()
  assert.equal(state.versionError.value, false)
  assert.equal(state.software.value.backend_version, 'dev')
})
