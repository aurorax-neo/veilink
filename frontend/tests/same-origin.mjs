import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'

function loadTs(relPath, extraGlobals = {}) {
  const source = readFileSync(new URL(relPath, import.meta.url), 'utf8')
  const js = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText
  const context = vm.createContext({
    exports: {},
    module: { exports: {} },
    TextEncoder,
    URL,
    URLSearchParams,
    ...extraGlobals,
  })
  vm.runInContext(js, context)
  return context.exports
}

test('API stays strictly same-origin, sends credentials, and stores session token in sessionStorage only', async () => {
  const session = new Map([['veilink_session_token', 'vls_session_123']])
  const calls = []
  let unauthorizedCalls = 0
  const mod = loadTs('../src/api.ts', {
    sessionStorage: {
      getItem: (k) => session.get(k) ?? null,
      setItem: (k, v) => session.set(k, v),
      removeItem: (k) => session.delete(k),
    },
    localStorage: {
      getItem: () => 'vls_should_never_be_read',
      setItem: () => {
        throw new Error('localStorage must not store session tokens')
      },
      removeItem: () => {},
    },
    fetch: async (url, options) => {
      calls.push({ url, options })
      if (url === '/api/v1/auth/login') {
        return {
          ok: false,
          status: 401,
          json: async () => ({ error: 'invalid email or password' }),
          text: async () => JSON.stringify({ error: 'invalid email or password' }),
        }
      }
      return {
        ok: true,
        status: 200,
        text: async () => JSON.stringify([{ id: 'n1', last_seen: Math.floor(Date.now() / 1000) + 9999 }]),
        json: async () => ({ api_version: 'v1', backend_version: '0.4.23', web_version: '0.4.23' }),
      }
    },
  })

  mod.setUnauthorized(() => {
    unauthorizedCalls += 1
  })

  assert.equal(mod.getSessionToken(), 'vls_session_123')
  const nodes = await mod.api('/nodes')
  assert.equal(calls[0].url, '/api/v1/nodes')
  assert.equal(calls[0].options.credentials, 'same-origin')
  assert.equal(calls[0].options.headers.Authorization, 'Bearer vls_session_123')
  assert.ok(nodes[0].last_seen <= Math.floor(Date.now() / 1000), 'future last_seen should be clamped')

  // Public auth endpoints returning 401 must surface server error without triggering global session logout
  await assert.rejects(
    () => mod.api('/auth/login', 'POST', { email: 'admin@veilink.io', password: 'wrong' }),
    (err) => err.status === 401 && err.message === 'invalid email or password',
  )
  assert.equal(unauthorizedCalls, 0)

  await mod.checkApiCompatibility()
  assert.equal(calls[2].url, '/api/version')
  assert.equal(calls[2].options.credentials, 'same-origin')
})

test('API calibrates server clock offset from X-Server-Time-Ms without falsifying historical last_seen', async () => {
  const host = {}
  const serverAheadMs = Date.now() + 600_000 // Server clock 10 minutes ahead of client browser
  const serverNowSec = Math.floor(serverAheadMs / 1000)
  const mod = loadTs('../src/api.ts', {
    globalThis: host,
    sessionStorage: { getItem: () => 'tok', setItem: () => {}, removeItem: () => {} },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    fetch: async () => ({
      ok: true,
      status: 200,
      headers: {
        get: (name) => (name.toLowerCase() === 'x-server-time-ms' ? String(serverAheadMs) : null),
      },
      text: async () =>
        JSON.stringify([
          { id: 'live', last_seen: serverNowSec - 2 },
          { id: 'dead', last_seen: serverNowSec - 300 },
        ]),
    }),
  })
  const nodes = await mod.api('/nodes')
  assert.ok(Math.abs(host.__VEILINK_CLOCK_OFFSET_MS__ - 600_000) < 2000)
  assert.equal(nodes[0].last_seen, serverNowSec - 2)
  assert.equal(nodes[1].last_seen, serverNowSec - 300)
})
