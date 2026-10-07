import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { reactive, ref } from 'vue'

const source = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
const script = source.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')

class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

function setup(api, initialKey = '') {
  let mounted
  let currentKey = initialKey
  const context = vm.createContext({
    exports: {},
    reactive,
    ref,
    Error,
    api,
    ApiError,
    getApiKey: () => currentKey,
    setApiKey: (k) => { currentKey = k },
    clearApiKey: () => { currentKey = '' },
    setUnauthorized: () => {},
    checkApiCompatibility: async () => true,
    pageFromHash: () => 'dashboard',
    provide: () => {},
    deskKey: 0,
    navigateKey: 1,
    watch: () => {},
    onMounted: (fn) => { mounted = fn },
    onUnmounted: () => {},
    window: {
      addEventListener: () => {},
      removeEventListener: () => {},
      setInterval: () => 1,
      clearInterval: () => {},
      setTimeout: () => 1,
      clearTimeout: () => {},
    },
    document: { visibilityState: 'visible', title: '' },
    pages: { dashboard: { title: '仪表盘' } },
  })
  vm.runInContext(
    ts.transpileModule(
      script + '\nglobalThis.app = { submitLogin, logout, phase, loginError, loginBusy, desk, refreshLive, resetDesk };',
      { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }
    ).outputText,
    context
  )
  return {
    ...context.app,
    mount: () => mounted(),
    pageDocument: context.document,
    getCurrentKey: () => currentKey,
  }
}

test('login requires valid key and succeeds into app on valid stats check', async () => {
  const calls = []
  const app = setup(async (path) => {
    calls.push(path)
    if (path === '/stats') return { active_mappings: 0, online_servers: 0, online_clients: 0 }
    return []
  })
  assert.equal(app.phase.value, 'boot')
  await app.submitLogin('vlk_test_token')
  assert.equal(app.phase.value, 'app')
  assert.equal(app.getCurrentKey(), 'vlk_test_token')
  assert.ok(calls.includes('/stats'))
})

test('login fails closed on rejected key or network error', async () => {
  const app = setup(async () => {
    throw new ApiError('认证失败', 401)
  })
  await app.submitLogin('vlk_invalid')
  assert.equal(app.phase.value, 'boot')
  assert.equal(app.loginError.value, '认证失败')
  assert.equal(app.getCurrentKey(), '')
})

test('LoginView validates API key format', () => {
  const text = readFileSync(new URL('../src/views/LoginView.vue', import.meta.url), 'utf8')
    .match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1]
    .replace(/^import .*$/gm, '')

  let submittedKey = ''
  const c = vm.createContext({
    exports: {},
    ref,
    defineProps: () => ({ error: '', busy: false }),
    defineEmits: () => (event, key) => { if (event === 'submit') submittedKey = key },
  })

  vm.runInContext(
    ts.transpileModule(
      text + '\nglobalThis.login = { apiKey, localError, onSubmit };',
      { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }
    ).outputText,
    c
  )

  const login = c.login
  // Empty key rejected
  login.apiKey.value = '   '
  login.onSubmit()
  assert.equal(submittedKey, '')
  assert.match(login.localError.value, /请输入 API Key/)

  // Invalid prefix rejected
  login.apiKey.value = 'invalid_key'
  login.onSubmit()
  assert.equal(submittedKey, '')
  assert.match(login.localError.value, /vlk_/)

  login.apiKey.value = ' vlk_correct_token '
  login.onSubmit()
  assert.equal(submittedKey, 'vlk_correct_token')
  assert.equal(login.localError.value, '')
})

test('login view renders API key without a configurable server address', () => {
  const view = readFileSync(new URL('../src/views/LoginView.vue', import.meta.url), 'utf8')
  assert.doesNotMatch(view, /server-url|服务地址|恢复默认/)
  assert.match(view, /<label for="apikey">API Key<\/label>/)
  assert.match(view, /placeholder="vlk_\.\.\."/)
  assert.match(view, /进入控制台/)
})

test('authenticated live refresh only fetches nodes, skips hidden/busy views and keeps UI quiet', async () => {
  const calls = []
  const app = setup(async (path) => {
    calls.push(path)
    return path === '/nodes' ? [{ id: 'fresh', last_seen: 42 }] : []
  })
  app.phase.value = 'app'
  app.desk.loaded = true
  app.desk.mappings = [{ id: 'existing' }]
  await app.refreshLive()
  assert.deepEqual(calls, ['/nodes'])
  assert.equal(app.desk.nodes[0].last_seen, 42)
  assert.equal(app.desk.mappings[0].id, 'existing')
  assert.equal(app.desk.loading, false)
  assert.equal(app.desk.notice, '')
  app.pageDocument.visibilityState = 'hidden'
  await app.refreshLive()
  app.pageDocument.visibilityState = 'visible'
  app.desk.loading = true
  await app.refreshLive()
  app.desk.loading = false
  app.phase.value = 'login'
  await app.refreshLive()
  assert.deepEqual(calls, ['/nodes'])
})

test('failed or stale live poll cannot replace state or show a success/failure notice', async () => {
  let finish
  const app = setup(() => new Promise((resolve) => { finish = resolve }))
  app.phase.value = 'app'
  const poll = app.refreshLive()
  await app.refreshLive()
  app.phase.value = 'login'
  app.resetDesk()
  finish([{ id: 'stale' }])
  await poll
  assert.equal(app.desk.nodes.length, 0)
  const failed = setup(async () => { throw new Error('offline') })
  failed.phase.value = 'app'
  await failed.refreshLive()
  assert.equal(failed.desk.notice, '')
  assert.equal(failed.desk.error, '')
})

test('full reload fetches traffic independently and stale polls cannot overwrite a full refresh', async () => {
  const calls = []
  const app = setup(async (path) => {
    calls.push(path)
    if (path === '/nodes') return [{ id: 's' }]
    if (path === '/mappings') return [{ id: 'm' }]
    if (path === '/traffic') return [{ mapping_id: 'm', up_bytes: 2, down_bytes: 3, reported_at: '2026-01-01T00:00:00Z' }]
    return []
  })
  await app.desk.reload()
  assert.deepEqual(calls, ['/nodes', '/mappings', '/audit', '/traffic'])
  assert.equal(app.desk.loaded, true)
  assert.equal(app.desk.traffic[0].up_bytes, 2)
  const unavailable = setup(async (path) => {
    if (path === '/traffic') throw new Error('traffic offline')
    return []
  })
  await unavailable.desk.reload()
  assert.equal(unavailable.desk.loaded, true)
  assert.equal(unavailable.desk.trafficLoaded, false)
  assert.match(unavailable.desk.trafficError, /traffic offline|流量读取失败/)
  assert.equal(unavailable.desk.notice, '')
})

test('session restoration via stored API Key restores app phase on mount', async () => {
  const calls = []
  const active = setup(async (path) => {
    calls.push(path)
    if (path === '/stats') return { active_mappings: 1 }
    return []
  }, 'vlk_stored_valid_key')
  await active.mount()
  assert.equal(active.phase.value, 'app')
  assert.ok(calls.includes('/stats'))

  const invalid = setup(async (path) => {
    if (path === '/stats') throw new ApiError('invalid', 401)
    return []
  }, 'vlk_stored_invalid_key')
  await invalid.mount()
  assert.equal(invalid.phase.value, 'login')
  assert.equal(invalid.getCurrentKey(), '')
})

test('node-only read merges the target and never toggles global loading or reads unrelated APIs', async () => {
  const calls = []
  const app = setup(async (path) => {
    calls.push(path)
    return [{ id: 'a', last_seen: 20 }, { id: 'b', last_seen: 999 }]
  })
  app.phase.value = 'app'
  app.desk.nodes = [{ id: 'a', last_seen: 1 }, { id: 'b', last_seen: 2 }]
  app.desk.mappings = [{ id: 'mapping' }]
  await app.desk.reloadNodes('a')
  assert.deepEqual(calls, ['/nodes'])
  assert.equal(app.desk.loading, false)
  assert.equal(app.desk.nodes[0].last_seen, 20)
  assert.equal(app.desk.nodes[1].last_seen, 2)
  assert.equal(app.desk.mappings[0].id, 'mapping')
})

test('late node reads cannot overwrite logout, polling or a global refresh', async () => {
  for (const mode of ['logout', 'poll', 'global']) {
    let finish
    let first = true
    const app = setup((path) => {
      if (first) {
        first = false
        return new Promise((resolve) => { finish = resolve })
      }
      return Promise.resolve(path === '/nodes' ? [{ id: 'a', last_seen: 50 }] : [])
    })
    app.phase.value = 'app'
    app.desk.nodes = [{ id: 'a', last_seen: 1 }]
    const pending = app.desk.reloadNodes('a')
    if (mode === 'logout') {
      app.phase.value = 'login'
      app.resetDesk()
    } else {
      await app.desk.reload(mode === 'poll' ? { silent: true } : undefined)
    }
    finish([{ id: 'a', last_seen: 2 }])
    await pending
    assert.equal(app.desk.nodes[0]?.last_seen, mode === 'logout' ? undefined : 50)
    assert.equal(app.desk.loading, false)
  }
})

test('malformed or missing target reads fail without overwriting nodes', async () => {
  for (const response of [null, {}, []]) {
    const app = setup(async () => response)
    app.phase.value = 'app'
    app.desk.nodes = [{ id: 'a', last_seen: 1 }]
    await assert.rejects(app.desk.reloadNodes('a'))
    assert.equal(app.desk.nodes[0].last_seen, 1)
    assert.equal(app.desk.loading, false)
  }
})
