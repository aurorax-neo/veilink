import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { ref } from 'vue'

const source = readFileSync(new URL('../src/views/SettingsView.vue', import.meta.url), 'utf8')
const script = source.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
test('settings reads builtin status without download or redirect controls', async () => {
  const requests = []
  const context = vm.createContext({ exports: {}, ref, onMounted: () => {}, ApiError: Error,
    api: async (path, method) => { requests.push({ path, method }); return { mode: 'builtin', active_version: 'v1.0.0', serving: true } },
  })
  vm.runInContext(ts.transpileModule(script + '\nglobalThis.state = { load, status };', { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText, context)
  await context.state.load()
  assert.equal(context.state.status.value.mode, 'builtin')
  assert.deepEqual(requests, [{ path: '/web/config', method: undefined }])
  assert.doesNotMatch(source, /\/web\/(update|probe)|frontend_url|web_mode|mirrors|拉取更新|下载加速/)
})
