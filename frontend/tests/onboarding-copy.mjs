import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { computed, ref } from 'vue'

const source = readFileSync(new URL('../src/components/NodeOnboarding.vue', import.meta.url), 'utf8')
const script = source.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
function setup(copyText) {
 const calls = []
 const context = vm.createContext({ exports: {}, computed, ref, location: { origin: 'https://panel.example' }, Date, window: { setInterval: () => 1, clearInterval: () => {} }, onUnmounted: () => {}, defineExpose: () => {}, api: async () => {}, copyText: async value => { calls.push(value); await copyText(value) } })
 vm.runInContext(ts.transpileModule(script + '\nglobalThis.result = { copy, status, copyError };', { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText, context)
 return { ...context.result, calls }
}
test('both deployment steps copy their own command and report clipboard failure', async () => {
 const state = setup(async () => {})
 await state.copy('mkdir -p /opt/docker/example', '目录准备命令')
 await state.copy('docker run -itd --name example token', '接入命令')
 assert.deepEqual(state.calls, ['mkdir -p /opt/docker/example', 'docker run -itd --name example token'])
 assert.equal(state.status.value, '接入命令已复制。')
 const denied = setup(async () => { throw new Error('denied') })
 await denied.copy('mkdir -p /opt/docker/example', '目录准备命令')
 assert.match(denied.copyError.value, /目录准备命令复制失败/)
 assert.match(source, /@click="copy\(result.prepare, '目录准备命令'\)"/)
 assert.match(source, /:disabled="expired" @click="copy\(result.command, '接入命令'\)"/)
})
