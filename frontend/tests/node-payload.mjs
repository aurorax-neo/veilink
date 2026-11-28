import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'

function transpile(relPath) {
  const src = readFileSync(new URL(relPath, import.meta.url), 'utf8')
  return ts.transpileModule(src, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText
}

function loadModules() {
  const cache = new Map()
  const req = (spec) => {
    const map = {
      '../format': '../src/format.ts',
      './format': '../src/format.ts',
    }
    const target = map[spec]
    if (!target) throw new Error(`Unexpected import: ${spec}`)
    if (!cache.has(target)) {
      const m = { exports: {} }
      const ctx = vm.createContext({ exports: m.exports, module: m, require: req, TextEncoder, structuredClone })
      vm.runInContext(transpile(target), ctx)
      cache.set(target, m.exports)
    }
    return cache.get(target)
  }
  const format = req('../format')
  const payloadMod = { exports: {} }
  const ctx = vm.createContext({
    exports: payloadMod.exports,
    module: payloadMod,
    require: req,
    TextEncoder,
    structuredClone,
  })
  vm.runInContext(transpile('../src/lib/nodePayload.ts'), ctx)
  return { format, payload: payloadMod.exports }
}

const DEMO_CERT = '-----BEGIN CERTIFICATE-----\nZGVtbw==\n-----END CERTIFICATE-----'
const DEMO_KEY = '-----BEGIN PRIVATE KEY-----\nZGVtbw==\n-----END PRIVATE KEY-----'

test('VLESS + TLS + Vision builds clean server payload', () => {
  const { payload } = loadModules()
  const { draft, endpoints, originalTunnel } = payload.nodeToDraft(undefined, 'gw-1')
  Object.assign(draft, {
    name: 'Edge Tokyo',
    listen: '0.0.0.0',
    listenPort: '443',
    protocol: 'vless',
    transport: 'tcp',
    security: 'tls',
    flow: 'xtls-rprx-vision',
    cert: DEMO_CERT,
    key: DEMO_KEY,
  })
  endpoints[0].host = 'tokyo.example.com'
  const out = payload.buildNodeSavePayload('server', draft, endpoints, originalTunnel)
  assert.equal(out.name, 'Edge Tokyo')
  assert.equal(out.address, 'tokyo.example.com')
  assert.equal(out.tunnel.protocol, 'vless')
  assert.equal(out.tunnel.transport_security, 'tls')
  assert.equal(out.tunnel.flow, 'xtls-rprx-vision')
  assert.equal(out.tunnel.listen_port, 443)
})

test('REALITY + XHTTP auto selects stream-one without download endpoint and rejects xhttpTLS=true', () => {
  const { payload } = loadModules()
  const { draft, endpoints, originalTunnel } = payload.nodeToDraft(undefined, 'gw-2')
  Object.assign(draft, {
    name: 'Reality XHTTP',
    protocol: 'vless',
    transport: 'xhttp',
    security: 'reality',
    xhttpMode: 'auto',
    xhttpTLS: true,
    dest: 'www.microsoft.com:443',
    privateKey: 'privkey',
    shortIDs: 'a1b2c3d4',
    names: 'www.microsoft.com',
  })
  endpoints[0].host = 'edge.example.com'
  assert.equal(payload.effectiveXhttpMode(draft), 'stream-one')
  assert.throws(() => payload.buildNodeSavePayload('server', draft, endpoints, originalTunnel), /关闭连接 HTTPS/)

  draft.xhttpTLS = false
  const out = payload.buildNodeSavePayload('server', draft, endpoints, originalTunnel)
  assert.equal(out.tunnel.xhttp.mode, 'auto')
  assert.equal(out.tunnel.xhttp.tls, false)
  assert.equal(out.tunnel.reality.dest, 'www.microsoft.com:443')
})

test('XHTTP custom header tokenizer rejects duplicate keys and disallowed headers', () => {
  const { payload } = loadModules()
  assert.deepEqual(
    JSON.parse(JSON.stringify(payload.parseXHTTPHeaders('{"User-Agent":"Chrome/156","X-Custom-Env":"prod"}'))),
    { 'User-Agent': 'Chrome/156', 'X-Custom-Env': 'prod' },
  )
  assert.throws(() => payload.parseXHTTPHeaders('{"User-Agent":"A","user-agent":"B"}'), /重复/)
  assert.throws(() => payload.parseXHTTPHeaders('{"Authorization":"Bearer x"}'), /不允许请求头/)
})

test('Hysteria2 enforces QUIC + TLS + password and client payload stays stripped', () => {
  const { payload } = loadModules()
  const { draft, endpoints, originalTunnel } = payload.nodeToDraft(undefined, 'hy-1')
  Object.assign(draft, {
    name: 'HY2 Gateway',
    protocol: 'hysteria2',
    transport: 'quic',
    security: 'tls',
    cert: DEMO_CERT,
    key: DEMO_KEY,
    password: '',
  })
  endpoints[0].host = 'hy.example.com'
  assert.throws(() => payload.buildNodeSavePayload('server', draft, endpoints, originalTunnel), /Hysteria2 密码/)

  draft.password = 'super-secret'
  const out = payload.buildNodeSavePayload('server', draft, endpoints, originalTunnel)
  assert.equal(out.tunnel.protocol, 'hysteria2')
  assert.equal(out.tunnel.hysteria2.password, 'super-secret')

  const clientOut = JSON.parse(JSON.stringify(payload.buildNodeSavePayload('client', draft, endpoints, originalTunnel)))
  assert.deepEqual(clientOut, { name: 'HY2 Gateway', role: 'client', address: '', port: 0 })

  draft.mode = 'offline'
  const offlineServer = payload.buildNodeSavePayload('server', draft, endpoints, originalTunnel)
  assert.equal(offlineServer.mode, 'offline')
  const offlineClient = JSON.parse(JSON.stringify(payload.buildNodeSavePayload('client', draft, endpoints, originalTunnel)))
  assert.deepEqual(offlineClient, { name: 'HY2 Gateway', role: 'client', mode: 'offline', address: '', port: 0 })

  const roundTrip = payload.nodeToDraft({ id: 'c-off', name: 'Airgap', role: 'client', mode: 'offline', address: '', port: 0, revoked: false, desired_revision: 2, applied_revision: 0, exported_revision: 2, last_seen: 0, error: '' })
  assert.equal(roundTrip.draft.mode, 'offline')
  const embeddedLocked = payload.nodeToDraft({ id: 'gw-emb', name: 'Builtin', role: 'server', mode: 'offline', embedded: true, address: '127.0.0.1', port: 443, revoked: false, desired_revision: 1, applied_revision: 1, last_seen: 100, error: '' })
  assert.equal(embeddedLocked.draft.mode, 'online')
})

test('Mapping validation detects tunnel port conflict and enabled overlap', () => {
  const { format } = loadModules()
  const nodes = [
    {
      id: 'srv-1',
      name: 'GW',
      role: 'server',
      address: 'gw.example.com',
      port: 443,
      connect_endpoints: [{ id: 'ep1', name: 'Primary', host: 'gw.example.com', port: 443, enabled: true }],
      tunnel: { listen_host: '0.0.0.0', listen_port: 443 },
      revoked: false,
      desired_revision: 1,
      applied_revision: 1,
      last_seen: Math.floor(Date.now() / 1000),
      error: '',
    },
    {
      id: 'cli-1',
      name: 'Office',
      role: 'client',
      address: '',
      port: 0,
      revoked: false,
      desired_revision: 1,
      applied_revision: 1,
      last_seen: Math.floor(Date.now() / 1000),
      error: '',
    },
  ]
  const conflict = format.validateMapping(
    {
      name: 'Web',
      serverId: 'srv-1',
      clientId: 'cli-1',
      connectEndpointId: 'ep1',
      pool: 2,
      listenHost: '0.0.0.0',
      listenPort: '443',
      targetHost: '127.0.0.1',
      targetPort: '8080',
      network: 'tcp',
      enabled: true,
    },
    nodes,
    [],
  )
  assert.match(conflict || '', /本地隧道监听冲突/)

  const ok = format.validateMapping(
    {
      name: 'Web',
      serverId: 'srv-1',
      clientId: 'cli-1',
      connectEndpointId: 'ep1',
      pool: 2,
      listenHost: '0.0.0.0',
      listenPort: '8443',
      targetHost: '127.0.0.1',
      targetPort: '8080',
      network: 'tcp',
      enabled: true,
    },
    nodes,
    [],
  )
  assert.equal(ok, null)
})
