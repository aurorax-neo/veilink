import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { computed, ref } from 'vue'

const source = path => readFileSync(new URL(path, import.meta.url), 'utf8')
const table = source('../src/components/NodesTable.vue')
const script = table.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
const transpile = text => ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText
const format = vm.createContext({ exports: {} })
vm.runInContext(transpile(source('../src/format.ts')), format)

function setup(response = { connected: true }, reload = async () => {}, role = 'server') {
  const calls = [], notices = []
  let reloads = 0
  let tick = null
  let unmount = null
  let cleared = null
  const desk = {
    nodes: [], mappings: [],
    reload: async () => { reloads++; await reload() },
    notify: (text, bad = false) => notices.push({ text, bad }),
  }
  const context = vm.createContext({
    exports: {}, computed, ref, Error, ...format.exports,
    defineProps: () => ({ role }), inject: () => desk, deskKey: {},
    onMounted: callback => { tick = callback() },
    onUnmounted: callback => { unmount = callback },
    setInterval: callback => { tick = callback; return 7 },
    clearInterval: id => { cleared = id },
    api: async (...args) => {
      calls.push(structuredClone(args))
      return typeof response === 'function' ? response(...args) : response
    },
  })
  vm.runInContext(transpile(script + '\nglobalThis.state = { refreshNode, refreshing, revisionLabel, revisionDescription, saved, now };'), context)
  return { ...context.state, calls, notices, tick: () => tick?.(), unmount: () => unmount?.(), get cleared() { return cleared }, get reloads() { return reloads } }
}
const node = { id: 'node/id', revoked: false, desired_revision: 4, applied_revision: 4, last_seen: 1000, error: '' }
const deferred = () => {
  let resolve
  const promise = new Promise(done => { resolve = done })
  return { promise, resolve }
}
test('node presence clock refreshes locally and clears its interval on unmount', () => {
  const state = setup()
  const before = state.now.value
  assert.equal(state.cleared, null)
  state.tick()
  assert.ok(state.now.value >= before)
  state.unmount()
  assert.equal(state.cleared, 7)
})

test('server, client and embedded refresh encode IDs and report requests, not application', async () => {
  for (const role of ['server', 'client']) {
    for (const embedded of [false, true]) {
      const state = setup({ connected: true }, undefined, role)
      const target = { ...node, role, embedded }
      await state.refreshNode(target)
      assert.deepEqual(state.calls, [['/nodes/node%2Fid/refresh', 'POST', {}]])
      assert.equal(state.reloads, 1)
      assert.deepEqual(state.notices, [])
      assert.equal(state.refreshing.value.size, 0)
      assert.equal(target.applied_revision, 4)
    }
  }
})

test('offline refresh reports automatic reconnect sync and reloads', async () => {
  const state = setup({ connected: false })
  await state.refreshNode(node)
  assert.deepEqual(state.notices, [{ text: '节点未连接，重连后自动同步', bad: false }])
  assert.equal(state.reloads, 1)
  assert.equal(state.refreshing.value.size, 0)
})

test('API and reload errors notify as bad, clear busy and permit retry', async () => {
  for (const failReload of [false, true]) {
    let failed = true
    const fail = async () => { if (failed) throw new Error('refresh failed') }
    const state = setup(failReload ? { connected: true } : async () => { await fail(); return { connected: true } }, failReload ? fail : undefined)
    await state.refreshNode(node)
    assert.deepEqual(state.notices.at(-1), { text: 'refresh failed', bad: true })
    assert.equal(state.refreshing.value.size, 0)
    assert.equal(state.reloads, failReload ? 1 : 0)
    failed = false
    await state.refreshNode(node)
    assert.equal(state.calls.length, 2)
    assert.equal(state.refreshing.value.size, 0)
  }
})

test('duplicate clicks are ignored through request and reload; other rows remain usable', async () => {
  const request = deferred(), reload = deferred()
  const state = setup(() => request.promise, () => reload.promise)
  const first = state.refreshNode(node)
  await state.refreshNode({ ...node })
  assert.equal(state.calls.length, 1)
  const other = state.refreshNode({ ...node, id: 'other' })
  assert.equal(state.calls.length, 2)
  request.resolve({ connected: true })
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(state.reloads, 2)
  await state.refreshNode(node)
  assert.equal(state.calls.length, 2)
  assert.equal(state.refreshing.value.has(node.id), true)
  reload.resolve()
  await Promise.all([first, other])
  assert.equal(state.refreshing.value.size, 0)
})

test('revoked nodes cannot refresh', async () => {
  const state = setup()
  await state.refreshNode({ ...node, revoked: true })
  assert.equal(state.calls.length, 0)
  assert.equal(state.reloads, 0)
  assert.equal(state.notices.length, 0)
  assert.equal(state.refreshing.value.size, 0)
  assert.match(table, /:title="'已请求节点立即同步并上报，结果以节点上报为准'" :aria-label="'已请求节点立即同步并上报，结果以节点上报为准'"/)
})

test('revision column shows only latest status and distinguishes pending, failure and missing heartbeat', () => {
  const state = setup()
  assert.equal(state.revisionLabel({ ...node, applied_revision: 2 }), '未同步')
  assert.equal(state.revisionLabel({ ...node, error: 'failure' }), '应用失败')
  assert.equal(state.revisionLabel(node), '最新')
  assert.equal(state.revisionLabel({ ...node, revoked: true }), '不再同步')
  assert.equal(state.revisionLabel({ ...node, desired_revision: 0 }), '尚无配置')
  const unseen = { ...node, last_seen: 0, applied_revision: 0, desired_revision: 17 }
  assert.equal(state.revisionLabel(unseen), '未上报')
  assert.match(state.revisionDescription(unseen), /节点尚未上报心跳.*检查节点容器日志、Master 地址和网络连通性/)
  assert.equal(state.revisionLabel({ ...unseen, last_seen: 1000 }), '未同步')
  assert.match(table, /配置是否最新/)
  assert.match(table, /:title="revisionDescription\(node\)" :aria-label="revisionDescription\(node\)"/)
  assert.doesNotMatch(table, /revision-value|已应用 r\$|期望 r\$/)
})

test('save confirmation awaits reported application rather than claiming success', async () => {
  const state = setup()
  await state.saved()
  assert.equal(state.reloads, 1)
  assert.match(state.notices[0].text, /已保存.*等待节点上报/)
  assert.doesNotMatch(state.notices[0].text, /已应用|已生效/)
})
