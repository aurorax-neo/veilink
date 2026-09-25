import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'

const source = path => readFileSync(new URL(path, import.meta.url), 'utf8')
test('protocol guidance covers prerequisites, pairing and safe Vision fallback', () => {
  const editor = source('../src/components/NodeEditor.vue')
  for (const text of ['TLS 使用 TCP', 'REALITY 使用 TCP', 'plain 使用 TCP', 'UDP 转发', '客户端密码须一致', 'decryption', 'encryption', '记录边界', '加密回退', 'mux、控制与 UDP 不裸传']) assert.ok(editor.includes(text), text)
  const onboarding = source('../src/components/NodeOnboarding.vue')
  for (const text of ['-control-ca 仅信任 Master HTTPS', '客户端不加本地隧道 flags', '节点在线仅代表心跳']) assert.ok(onboarding.includes(text), text)
})

test('node API errors give protocol guidance without exposing backend secrets', async () => {
  const context = vm.createContext({ exports: {}, fetch: async () => ({ status: 400, ok: false, json: async () => ({ error: 'SECRET private material' }) }) })
  vm.runInContext(ts.transpileModule(source('../src/api.ts'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText, context)
  for (const [path, method] of [['/nodes', 'POST'], ['/nodes/id', 'PUT']]) {
    await assert.rejects(context.exports.api(path, method, {}), error => {
      for (const protocol of ['TLS', 'plain', 'REALITY', 'Hysteria2', 'VLESS Encryption', 'Vision']) assert.ok(error.message.includes(protocol))
      assert.doesNotMatch(error.message, /SECRET/)
      return error.status === 400
    })
  }
  await assert.rejects(context.exports.api('/nodes/id/join', 'POST'), /请求无效或资源冲突/)
})
