import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import vm from 'node:vm'
import ts from 'typescript'

const source = path => readFileSync(new URL(path, import.meta.url), 'utf8')
const context = vm.createContext({ exports: {} })
vm.runInContext(ts.transpileModule(source('../src/format.ts'), { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText, context)
const compare = context.exports.byNameAndId

test('name and ID sort is deterministic across API response order and duplicate names', () => {
  const rows = [
    { id: 'b', name: '同名' }, { id: 'c', name: '其他' },
    { id: 'a', name: '同名' }, { id: 'd', name: '其他' },
  ]
  const expected = rows.slice().sort(compare).map(row => row.id)
  assert.deepEqual(expected.slice().sort(), rows.map(row => row.id).sort())
  assert.ok(expected.indexOf('a') < expected.indexOf('b'))
  for (const order of [rows.slice().reverse(), [rows[2], rows[0], rows[3], rows[1]]]) {
    assert.deepEqual(order.sort(compare).map(row => row.id), expected)
  }
})

test('visible lists use deterministic ordering without reordering dial candidates', () => {
  for (const path of ['../src/components/NodesTable.vue', '../src/views/ProxiesView.vue', '../src/views/DashboardView.vue', '../src/views/LogsView.vue']) {
    assert.match(source(path), /sort\((?:byNameAndId|\(a, b\) =>[^\n]*byNameAndId)/, path)
  }
  const mappings = source('../src/views/ProxiesView.vue')
  assert.match(mappings, /return candidates\.filter\(candidate => candidate\.enabled\)/)
  assert.doesNotMatch(mappings, /return candidates\.filter\(candidate => candidate\.enabled\)\.sort/)
})
