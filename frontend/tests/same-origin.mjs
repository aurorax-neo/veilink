import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'

test('API and version ignore obsolete custom server URLs and remain same-origin', async () => {
  const values = new Map([
    ['veilink_server_url', 'https://other.example'],
    ['veilink_api_key', 'vlk_test'],
  ])
  const calls = []
  const context = vm.createContext({
    exports: {},
    sessionStorage: {
      getItem: (key) => values.get(key),
      setItem: (key, value) => values.set(key, value),
      removeItem: (key) => values.delete(key),
    },
    localStorage: {
      getItem: () => 'vlk_persistent_should_not_be_used',
      setItem: () => { throw new Error('localStorage write') },
      removeItem: () => values.delete('veilink_api_key'),
    },
    fetch: async (url, options) => {
      calls.push({ url, options })
      return { ok: true, status: 200, text: async () => '[]', json: async () => ({ api_version: 'v1' }) }
    },
  })
  const source = readFileSync(new URL('../src/api.ts', import.meta.url), 'utf8')
  vm.runInContext(ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText, context)
  await context.exports.api('/nodes')
  await context.exports.getVersionInfo()
  assert.equal(calls[0].url, '/api/v1/nodes')
  assert.equal(calls[0].options.headers.Authorization, 'Bearer vlk_test')
  assert.equal(calls[1].url, '/api/version')
  assert.equal(context.exports.buildUrl('//other.example'), '/other.example')
  assert.equal(values.get('veilink_server_url'), 'https://other.example')
})
