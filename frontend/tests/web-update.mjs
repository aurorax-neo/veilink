import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { computed, ref } from 'vue'

const source = readFileSync(new URL('../src/views/SettingsView.vue', import.meta.url), 'utf8')
const script = source.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
function setup(failSave = false) {
  const requests = []
  const saved = { mirrors: ['https://first.example', 'https://second.example'], active_version: 'web-v1.0.0', frontend_url: '' }
  const context = vm.createContext({
    exports: {}, ref, computed, onMounted: () => {}, ApiError: Error,
    api: async (path, method, body) => {
      requests.push({ path, method, body })
      if (path === '/web/config' && method === 'POST') {
        if (failSave) throw new Error('镜像保存失败')
        saved.mirrors = [...body.mirrors]
      }
      return { ...saved }
    },
  })
  vm.runInContext(ts.transpileModule(script + '\nglobalThis.state = { load, mirrors, update, updateVersion, updateBad, updateMsg, hasChanges };', { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText, context)
  return { ...context.state, requests }
}

test('update saves modified mirror order first and empty version means latest', async () => {
  const s = setup()
  await s.load()
  s.mirrors.value.reverse()
  assert.equal(s.hasChanges.value, true)
  s.updateVersion.value = '  '
  await s.update()
  const save = s.requests.findIndex(r => r.path === '/web/config' && r.method === 'POST')
  const update = s.requests.findIndex(r => r.path === '/web/update')
  assert.ok(save >= 0 && update > save)
  assert.equal(s.requests[update].body.version, '')
  assert.equal(s.updateBad.value, false)
})

test('failed mirror save stops update and shows the error', async () => {
  const s = setup(true)
  await s.load()
  s.mirrors.value.push('https://gx.aorz.kdns.fr')
  await s.update()
  assert.equal(s.requests.some(r => r.path === '/web/update'), false)
  assert.equal(s.updateBad.value, true)
  assert.match(s.updateMsg.value, /镜像保存失败/)
})
