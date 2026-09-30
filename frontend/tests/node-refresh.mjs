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
  const calls = [], notices = [], nodeReloads = []
  let reloads = 0, tick, unmount, cleared
  const desk = {
    nodes: [], mappings: [], loading: false,
    reload: async () => { reloads++; desk.loading = true; await reload() },
    reloadNodes: async id => { nodeReloads.push(id); await reload() },
    notify: (text, bad = false) => notices.push({ text, bad }),
  }
  const context = vm.createContext({
    exports: {}, computed, ref, Error, ...format.exports,
    defineProps: () => ({ role }), inject: () => desk, deskKey: {},
    onMounted: callback => callback(), onUnmounted: callback => { unmount = callback },
    setInterval: callback => { tick = callback; return 7 }, clearInterval: id => { cleared = id },
    api: async (...args) => { calls.push(structuredClone(args)); return typeof response === 'function' ? response(...args) : response },
  })
  vm.runInContext(transpile(script + '\nglobalThis.state = { refreshNode, refreshing, refreshFeedback, revisionLabel, revisionDescription, saved, now };'), context)
  return { ...context.state, desk, calls, notices, nodeReloads, tick: () => tick?.(), unmount: () => unmount?.(), get cleared() { return cleared }, get reloads() { return reloads } }
}
const node = { id: 'node/id', name: 'node', revoked: false, desired_revision: 4, applied_revision: 4, last_seen: 1000, error: '' }
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done }); return { promise, resolve } }

test('presence clock stops on unmount', () => {
  const s = setup(), before = s.now.value
  s.tick(); assert.ok(s.now.value >= before)
  s.unmount(); assert.equal(s.cleared, 7)
})
test('server/client/embedded refresh targets one node and never starts global refresh', async () => {
  for (const role of ['server', 'client']) for (const embedded of [false, true]) {
    const s = setup({ connected: true }, undefined, role), target = { ...node, role, embedded }
    await s.refreshNode(target)
    assert.deepEqual(s.calls, [['/nodes/node%2Fid/refresh', 'POST', {}]])
    assert.deepEqual(s.nodeReloads, [node.id])
    assert.equal(s.reloads, 0); assert.equal(s.desk.loading, false)
    assert.deepEqual(s.notices, []); assert.equal(s.refreshing.value.size, 0)
    assert.equal(target.applied_revision, 4)
    assert.match(s.refreshFeedback.value[node.id].text, /已请求上报.*等待/)
  }
})
test('no push subscription is a row warning, not a green global success or offline heartbeat claim', async () => {
  const s = setup({ connected: false })
  await s.refreshNode({ ...node, last_seen: Date.now() / 1000 })
  assert.match(s.refreshFeedback.value[node.id].text, /推送通道未连接，重连后自动同步/)
  assert.equal(s.refreshFeedback.value[node.id].bad, false)
  assert.deepEqual(s.notices, []); assert.equal(s.reloads, 0)
  assert.deepEqual(s.nodeReloads, [node.id])
})
test('API and node read failures are local, clear busy, and allow retry', async () => {
  for (const failReload of [false, true]) {
    let failed = true
    const fail = async () => { if (failed) throw new Error('refresh failed') }
    const s = setup(failReload ? { connected: true } : async () => { await fail(); return { connected: true } }, failReload ? fail : undefined)
    await s.refreshNode(node)
    assert.equal(s.refreshFeedback.value[node.id].text, 'refresh failed')
    assert.equal(s.refreshFeedback.value[node.id].bad, true)
    assert.equal(s.refreshing.value.size, 0); assert.equal(s.reloads, 0)
    assert.deepEqual(s.notices, [])
    failed = false; await s.refreshNode(node)
    assert.equal(s.calls.length, 2); assert.equal(s.refreshing.value.size, 0)
  }
})
test('malformed refresh responses never report success or trigger a node read', async () => {
  for (const result of [null, {}, { connected: 'false' }, { connected: 1 }]) {
    const s = setup(result)
    await s.refreshNode(node)
    assert.match(s.refreshFeedback.value[node.id].text, /响应无效/)
    assert.equal(s.refreshFeedback.value[node.id].bad, true)
    assert.equal(s.nodeReloads.length, 0); assert.equal(s.reloads, 0)
  }
})
test('duplicate requests stay blocked through node read; other rows and global button stay independent', async () => {
  const request = deferred(), read = deferred(), s = setup(() => request.promise, () => read.promise)
  const first = s.refreshNode(node)
  await s.refreshNode({ ...node }); assert.equal(s.calls.length, 1)
  const other = s.refreshNode({ ...node, id: 'other' }); assert.equal(s.calls.length, 2)
  assert.equal(s.desk.loading, false)
  request.resolve({ connected: true }); await new Promise(resolve => setImmediate(resolve))
  assert.deepEqual(s.nodeReloads, [node.id, 'other'])
  await s.refreshNode(node); assert.equal(s.calls.length, 2)
  assert.equal(s.refreshing.value.has(node.id), true)
  read.resolve(); await Promise.all([first, other])
  assert.equal(s.refreshing.value.size, 0); assert.equal(s.reloads, 0)
})
test('late responses after navigation do not read or display feedback', async () => {
  for (const duringRead of [false, true]) {
    const pending = deferred()
    const s = setup(duringRead ? { connected: true } : () => pending.promise, duringRead ? () => pending.promise : undefined)
    const run = s.refreshNode(node)
    await new Promise(resolve => setImmediate(resolve)); s.unmount()
    pending.resolve({ connected: false }); await run
    assert.equal(Object.keys(s.refreshFeedback.value).length, 0)
    assert.equal(s.nodeReloads.length, duringRead ? 1 : 0)
    assert.equal(s.refreshing.value.size, 0)
  }
})
test('revoked nodes cannot refresh; button label describes action rather than past success', async () => {
  const s = setup(); await s.refreshNode({ ...node, revoked: true })
  assert.equal(s.calls.length, 0); assert.equal(s.nodeReloads.length, 0)
  assert.match(table, /title="请求节点刷新状态"/)
  assert.match(table, /:aria-busy="refreshing.has\(node.id\)"/)
})
test('revision status preserves applied/pending/failed distinctions', () => {
  const s = setup()
  assert.equal(s.revisionLabel({ ...node, applied_revision: 2 }), '未同步')
  assert.equal(s.revisionLabel({ ...node, error: 'failure' }), '应用失败')
  assert.equal(s.revisionLabel(node), '最新')
  assert.equal(s.revisionLabel({ ...node, revoked: true }), '不再同步')
  assert.equal(s.revisionLabel({ ...node, desired_revision: 0 }), '尚无配置')
  const unseen = { ...node, last_seen: 0, applied_revision: 0, desired_revision: 17 }
  assert.equal(s.revisionLabel(unseen), '未上报')
  assert.match(s.revisionDescription(unseen), /节点尚未上报心跳.*检查节点容器日志、Master 地址和网络连通性/)
  assert.match(table, /:title="revisionDescription\(node\)" :aria-label="revisionDescription\(node\)"/)
})
test('saving still reloads full data without claiming configuration applied', async () => {
  const s = setup(); await s.saved()
  assert.equal(s.reloads, 1); assert.match(s.notices[0].text, /已保存.*等待节点上报/)
})
