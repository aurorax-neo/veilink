import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'

const source = path => readFileSync(new URL(path, import.meta.url), 'utf8')
const transpile = text => ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText

function load(api) {
  const context = vm.createContext({ exports: {}, api })
  vm.runInContext(transpile(source('../src/pageRefresh.ts').replace(/^import .*$/gm, '') + '\nglobalThis.mod = { registerPageRefresh, runPageRefresh, askNodes, nodeBaseline, nodeChanged, waitForReports };'), context)
  return context.mod
}

test('page refresh wakes only a connected node and isolates a failing page', async () => {
  const calls = []
  const mod = load(async (path, method, body) => {
    calls.push([path, method, body])
    if (path.includes('bad')) throw new Error('offline')
    if (path.includes('closed')) return { connected: false }
    if (path.includes('weird')) return { connected: 'yes' }
    return { connected: true }
  })
  const connected = await mod.askNodes(['good/id', 'bad', 'closed', 'weird'])
  assert.deepEqual([...connected].sort(), ['good/id'])
  assert.deepEqual(calls.map(call => call[0]).sort(), ['/nodes/bad/refresh', '/nodes/closed/refresh', '/nodes/good%2Fid/refresh', '/nodes/weird/refresh'])
  let ran = 0
  const stop = mod.registerPageRefresh(async () => { ran++; throw new Error('page failed') })
  await mod.runPageRefresh()
  assert.equal(ran, 1)
  stop()
  await mod.runPageRefresh()
  assert.equal(ran, 1)
})

test('report wait stops when the deadline has passed or the report arrives', async () => {
  const mod = load(async () => ({ connected: false }))
  let loads = 0
  await mod.waitForReports(async () => { loads++ }, () => true, Date.now() - 1)
  assert.equal(loads, 0)
  const node = { id: 'n', last_seen: 1, applied_revision: 2, error: '' }
  const baseline = mod.nodeBaseline(node)
  assert.equal(mod.nodeChanged(node, baseline), false)
  assert.equal(mod.nodeChanged({ ...node, last_seen: 3 }, baseline), true)
  assert.equal(mod.nodeChanged(undefined, baseline), false)
})

test('each page refresh reads its own data and node tables do not stack the report time', () => {
  const consoleView = source('../src/views/ConsoleView.vue')
  const nodes = source('../src/components/NodesTable.vue')
  assert.match(consoleView, /runPageRefresh\(\)/)
  assert.match(source('../src/views/DashboardView.vue'), /registerPageRefresh/)
  assert.match(source('../src/views/ProxiesView.vue'), /registerPageRefresh/)
  assert.match(source('../src/views/LogsView.vue'), /registerPageRefresh\(refreshFromPage\)/)
  assert.match(nodes, /registerPageRefresh\(refreshRole\)/)
  assert.match(nodes, /fit-value">\{\{ statusLine\(node\) \}\}/)
  assert.doesNotMatch(nodes, /class="node-refresh-feedback fit"/)
})
