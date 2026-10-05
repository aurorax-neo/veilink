import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { computed, reactive, ref, watch } from 'vue'

const source = path => readFileSync(new URL(path, import.meta.url), 'utf8')
const transpile = text => ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText
const formatContext = vm.createContext({ exports: {}, TextEncoder })
vm.runInContext(transpile(source('../src/format.ts')), formatContext)
const { validateNode, validatePEM, PEM_MAX_BYTES, byNameAndId } = formatContext.exports
const editorSource = source('../src/components/NodeEditor.vue')
const script = editorSource.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
// Envelope-only fixtures, not real certificates or private keys. Crypto parsing belongs to the API.
const cert = '-----BEGIN CERTIFICATE-----\nZGVtbw==\n-----END CERTIFICATE-----'
const key = '-----BEGIN PRIVATE KEY-----\nZGVtbw==\n-----END PRIVATE KEY-----'
function setup(role = 'server', respond = async () => undefined) {
  const requests = []
  const context = vm.createContext({
    exports: {}, computed, reactive, ref, watch, structuredClone, TextEncoder,
    validateNode, validatePEM, PEM_MAX_BYTES,
    defineProps: () => ({ role, saved: async () => {} }), defineExpose: () => {},
    api: async (...args) => { requests.push(args); return respond(...args) },
  })
  vm.runInContext(transpile(script + '\nglobalThis.editor = { open, save, draft, streamUpPeriod, endpoints, addEndpoint, removeEndpoint, uploadPEM, uploads, clearSecrets, pemFields, reading, uploadError, generate, generation, options, xhttpHeadersError, setSessionTable, setMetaPlacement, setPaddingPlacement };'), context)
  const editor = context.editor
  editor.open()
  Object.assign(editor.draft, { name: 'Demo node', address: 'example.com', listenPort: '8444', cert, key })
  if (role === 'server') Object.assign(editor.endpoints[0], { name: '首选地址', host: 'example.com', port: 443, enabled: true })
  return { ...editor, requests }
}
const payload = e => e.requests.at(-1)[2].tunnel
const upload = (e, field, text, size = new TextEncoder().encode(text).length) => e.uploadPEM({ target: { files: [{ size, text: async () => text }], value: 'selected' } }, field)

test('server TLS requires complete PEM pair; save sends PEM only', async () => {
  const e = setup()
  e.draft.key = ''
  await assert.rejects(e.save(), /完整/)
  e.draft.key = 'not PEM'
  await assert.rejects(e.save(), /完整/)
  e.draft.key = key
  e.draft.ca = cert
  await e.save()
  assert.equal(e.requests[0][0], '/nodes')
  assert.equal(e.requests[0][1], 'POST')
  assert.equal(payload(e).transport_security, 'tls')
  assert.equal(payload(e).cert_pem, cert)
  assert.equal(payload(e).key_pem, key)
  assert.equal(payload(e).ca_pem, cert)
  assert.equal(validatePEM(cert + '\n' + cert, 'cert'), null)
  assert.ok(validatePEM(cert, 'key'))
  assert.ok(validatePEM(key.replaceAll('PRIVATE KEY', 'ENCRYPTED PRIVATE KEY'), 'key'))
  assert.ok(validatePEM('a'.repeat(PEM_MAX_BYTES + 1), 'ca'))
  assert.equal(e.requests.length, 1)
})

test('HY2 requires PEM and password; switching modes fully replaces tunnel', async () => {
  const e = setup()
  e.draft.transport = 'tcp'
  e.draft.security = 'tls'
  e.draft.flow = 'xtls-rprx-vision'
  e.draft.protocol = 'hysteria2'
  assert.equal(e.draft.flow, '')
  assert.equal(e.draft.transport, 'quic')
  await assert.rejects(e.save(), /Hysteria2 密码/)
  e.draft.password = 'demo-password'
  e.draft.key = ''
  await assert.rejects(e.save(), /完整/)
  e.draft.key = key
  e.draft.enc = 'demo-encryption'
  e.draft.flow = 'xtls-rprx-vision'
  await e.save()
  assert.equal(payload(e).protocol, 'hysteria2')
  assert.equal(payload(e).transport_security, '')
  assert.equal(payload(e).cert_pem, cert)
  assert.equal(payload(e).decryption, undefined)
  assert.equal(payload(e).flow, undefined)
  assert.equal(payload(e).xhttp, undefined)
  e.draft.protocol = 'vless'
  e.draft.transport = 'tcp'
  e.draft.security = 'reality'
  await e.save()
  assert.equal(payload(e).protocol, 'vless')
  assert.equal(payload(e).transport_security, '')
  assert.ok(payload(e).reality)
  assert.equal(payload(e).cert_pem, undefined)
  assert.equal(payload(e).hysteria2, undefined)
  e.draft.security = 'encryption'
  await e.save()
  assert.equal(payload(e).transport_security, 'plain')
  assert.equal(payload(e).reality, undefined)
  assert.equal(payload(e).flow, undefined)
})

test('XHTTP request headers normalize and roundtrip only on server XHTTP', async () => {
  assert.match(editorSource, /id="node-xhttp-headers"[^>]*v-model="draft.xhttpHeaders"[^>]*aria-invalid/)
  const e = setup()
  e.draft.transport = 'xhttp'
  await e.save()
  assert.equal(payload(e).xhttp.headers, undefined)
  e.draft.xhttpHeaders = '{ "x-custom-route": "east", "USER-agent": "demo", "accept-language": "zh-CN" }'
  await e.save()
  assert.equal(JSON.stringify(payload(e).xhttp.headers), JSON.stringify({ 'Accept-Language': 'zh-CN', 'User-Agent': 'demo', 'X-Custom-Route': 'east' }))
  const saved = JSON.parse(JSON.stringify(payload(e)))
  e.open({ id: 'server', name: 'Server', tunnel: saved })
  assert.equal(JSON.parse(e.draft.xhttpHeaders)['X-Custom-Route'], 'east')
  await e.save()
  assert.equal(JSON.stringify(payload(e).xhttp.headers), JSON.stringify(saved.xhttp.headers))
  e.draft.transport = 'tcp'
  await e.save()
  assert.equal(payload(e).xhttp, undefined)
  e.open()
  assert.equal(e.draft.xhttpHeaders, '')
  e.draft.transport = 'xhttp'; e.draft.xhttpHeaders = '{}'; e.draft.cert = cert; e.draft.key = key
  await e.save()
  assert.equal(payload(e).xhttp.headers, undefined)
})

test('XHTTP request headers reject malformed, duplicate, reserved, control and oversized values before API', async () => {
  const e = setup()
  e.draft.transport = 'xhttp'
  const invalid = [
    '[]', 'null', '{', '{"User-Agent":42}', '{"User-Agent":null}', '{"User-Agent":"a",}',
    '{"X-Custom-A":"a"} true', '{"X-Custom-A":"a","x-custom-a":"b"}',
    '{"User-Agent":"a","User-Agent":"b"}', '{"Host":"example.com"}',
    '{"Authorization":"secret"}', '{"Referer":"ref"}', '{"X-Padding":"a"}',
    '{"X-Custom-":"a"}', '{"X-Custom_A":"a"}', '{"X-Custom-A":""}',
    '{"X-Custom-A":" leading"}', '{"X-Custom-A":"line\\r\\nnext"}',
    '{"X-Custom-A":"\\u0000"}', '{"X-Custom-A":"\\u007f"}', '{"X-Custom-A":"\\u0085"}',
    '{"X-Custom-A":"\\ud800"}', '{"X-Custom-A":"' + 'é'.repeat(129) + '"}',
    JSON.stringify(Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`X-Custom-${i}`, 'a']))),
    JSON.stringify({ 'X-Custom-A': 'x'.repeat(2050) }),
  ]
  for (const value of invalid) {
    e.draft.xhttpHeaders = value
    await assert.rejects(e.save(), /XHTTP 请求头/)
    assert.match(e.xhttpHeadersError.value, /XHTTP 请求头/)
    assert.equal(e.requests.length, 0)
  }
  e.draft.xhttpHeaders = '{"X-Custom-A":"' + 'é'.repeat(128) + '"}'
  await e.save()
  assert.equal(payload(e).xhttp.headers['X-Custom-A'], 'é'.repeat(128))
  assert.equal(e.xhttpHeadersError.value, '')
})

test('clients cannot submit XHTTP request headers or server-authoritative tunnel settings', async () => {
  const e = setup('client')
  e.open({ id: 'client', name: 'Client', tunnel: { xhttp: { path: '/server/', headers: { 'User-Agent': 'server' } } } })
  e.draft.xhttpHeaders = '{"Host":"invalid"}'
  await e.save()
  assert.equal('tunnel' in body(e), false)
  assert.equal('client_tunnel' in body(e), false)
  assert.doesNotMatch(editorSource.slice(editorSource.indexOf('<template v-else>'), editorSource.indexOf('aria-label="服务端配置"')), /node-xhttp-headers/)
})

test('clients edit metadata only, with no local tunnel or template overrides', async () => {
  const e = setup('client')
  e.open({ id: 'client/id', name: 'Demo client' })
  assert.deepEqual(Array.from(e.pemFields.value), [])
  Object.assign(e.draft, { ca: 'invalid ignored material', enc: 'ignored', name: 'Renamed client' })
  await e.save()
  assert.equal(e.requests[0][0], '/nodes/client%2Fid')
  assert.equal(e.requests[0][1], 'PUT')
  const body = e.requests[0][2]
  assert.equal(body.name, 'Renamed client')
  assert.equal('tunnel' in body, false)
  assert.equal('client_tunnel' in body, false)
  await e.generate('reality')
  assert.equal(e.requests.length, 1)
  e.draft.name = ''
  await assert.rejects(e.save(), /名称/)
})

test('uploads enforce size, kind, empty/read errors; stale reads cannot restore secrets', async () => {
  const e = setup()
  await upload(e, 'cert', '', PEM_MAX_BYTES + 1)
  assert.match(e.uploads.cert.error, /64 KiB/)
  await assert.rejects(e.save(), /64 KiB/)
  await upload(e, 'cert', '')
  assert.match(e.uploads.cert.error, /为空/)
  await upload(e, 'cert', key)
  assert.match(e.uploads.cert.error, /完整/)
  await upload(e, 'cert', cert)
  assert.equal(e.uploads.cert.error, '')
  assert.match(e.uploads.cert.status, /已载入/)
  await e.uploadPEM({ target: { files: [{ size: 10, text: async () => { throw Error('never echo content') } }] } }, 'key')
  assert.match(e.uploads.key.error, /读取失败/)
  let resolve
  const pending = e.uploadPEM({ target: { files: [{ size: 10, text: () => new Promise(done => { resolve = done }) }] } }, 'key')
  assert.equal(e.reading.value, true)
  await assert.rejects(e.save(), /读取完成/)
  e.clearSecrets()
  resolve(key)
  await pending
  assert.equal(e.draft.key, '')
  assert.equal(e.reading.value, false)
})

const tableSource = source('../src/components/NodesTable.vue')
function setupTable(role = 'server') {
  const requests = []
  const desk = reactive({ nodes: [], mappings: [], reload: async () => {}, notify: () => {} })
  const tableScript = tableSource.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
  const context = vm.createContext({ exports: {}, computed, ref, byNameAndId, inject: () => desk, deskKey: {}, defineProps: () => ({ role }), onMounted: callback => callback(), onUnmounted: () => {}, setInterval: () => 7, clearInterval: () => {}, registerPageRefresh: () => () => {}, api: async (...args) => { requests.push(args) } })
  vm.runInContext(transpile(tableScript + '\nglobalThis.table = { tunnelLabel, effectiveSources, openConfig, ask, run, pending, configNode };'), context)
  return { ...context.table, desk, requests }
}

test('labels and read-only effective configuration use authoritative mapped server templates', () => {
  const s = setupTable()
  assert.equal(s.tunnelLabel({ tunnel: { cert_pem: cert, decryption: 'demo' } }), '未配置安全模式')
  assert.equal(s.tunnelLabel({ tunnel: { transport_security: 'tls', decryption: 'demo' } }), 'VLESS / TCP · TLS + Encryption')
  assert.equal(s.tunnelLabel({ tunnel: { protocol: 'hysteria2', hysteria2: { password: 'demo' } } }), 'Hysteria2 / QUIC + TLS')
  const c = setupTable('client')
  const client = { id: 'client' }
  c.desk.nodes.push({ id: 'server', role: 'server', client_tunnel: { ca_pem: cert } }, { id: 'revoked', role: 'server', revoked: true })
  c.desk.mappings.push({ client_id: 'client', server_id: 'server' }, { client_id: 'client', server_id: 'server' }, { client_id: 'client', server_id: 'revoked' }, { client_id: 'other', server_id: 'server' })
  assert.equal(c.effectiveSources(client).length, 1)
  assert.equal(c.effectiveSources(client)[0].client_tunnel.ca_pem, cert)
  assert.equal(c.effectiveSources({ ...client, revoked: true }).length, 0)
  assert.match(tableSource, /JSON.stringify\(source.client_tunnel, null, 2\)[^\n]+readonly/)
  assert.doesNotMatch(editorSource + tableSource + source('../src/types.ts'), /cert_file|key_file|ca_file|pool\?:/)
  assert.doesNotMatch(editorSource + source('../src/format.ts'), /override|v-html|console\./)
  assert.match(tableSource, /查看配置/)
  assert.match(tableSource, /<Modal ref="configModal" title="有效隧道配置（只读）"/)
  assert.match(tableSource, /@click="openConfig\(node\)"/)
  assert.doesNotMatch(tableSource, /<section v-if="role === 'client'" aria-label="有效隧道配置">[\s\S]*JSON.stringify/)
  c.openConfig(client)
  assert.equal(c.configNode.value.id, client.id)
  assert.doesNotMatch(tableSource.slice(tableSource.indexOf('<section v-if="selected"'), tableSource.indexOf('<Modal ref="configModal"')), /JSON.stringify\(source\.client_tunnel/)

})
test('client list omits server-only address and tunnel columns', () => {
  assert.match(tableSource, /<table class="nodes-table" :class="\{ 'nodes-table-client': role === 'client' \}"/)
  assert.match(tableSource, /<th v-if="role === 'server'" scope="col">本地监听 \/ 客户端连接地址<\/th><th v-if="role === 'server'" scope="col">隧道<\/th>/)
  assert.match(tableSource, /<td v-if="role === 'server'">{{ tunnelLabel\(node\) }}<\/td><td>{{ mappings\(node.id\).length }}<\/td>/)
  assert.doesNotMatch(tableSource, /服务端统一下发|<template v-else>—<\/template>/)
  assert.match(tableSource, /<button v-if="role === 'client'"[^>]*>查看配置<\/button>/)
  assert.equal(source('../src/styles.css').includes('.nodes-table, .nodes-table-client { width: max-content; min-width: 100%; }'), true)
})

const ca = cert.replace('ZGVtbw==', 'Y3VzdG9t')
const tlsNode = () => ({ id: 'server', name: 'Server', address: 'example.com', port: 443, connect_endpoints: [{ id: 'primary', name: '首选地址', host: 'example.com', port: 443, enabled: true }], tunnel: { listen_port: 8444, transport_security: 'tls', cert_pem: cert, key_pem: key, ca_pem: cert }, client_tunnel: { transport_security: 'tls', ca_pem: ca } })
const realityNode = () => ({ id: 'reality', name: 'Reality', address: 'example.com', port: 443, connect_endpoints: [{ id: 'primary', name: '首选地址', host: 'example.com', port: 443, enabled: true }], tunnel: { listen_port: 8444, reality: { private_key: 'private', short_ids: 'aa,bb', server_names: 'example.com', dest: 'example.com:443' } }, client_tunnel: { reality: { public_key: 'public', short_id: 'bb', fingerprint: 'firefox', server_names: 'example.com', max_time_diff: '1m' } } })

test('clearing optional encryption and REALITY fields removes saved values and can re-enable', async () => {
  const e = setup()
  const node = realityNode()
  Object.assign(node.tunnel.reality, { mldsa65_seed: 'seed', mldsa65_verify: 'verify', spider_x: '/old', spider_y: 'old', max_time_diff: '1m' })
  node.tunnel.decryption = 'old-encryption'
  node.tunnel.flow = 'xtls-rprx-vision'
  e.open(node)
  Object.assign(e.draft, { mldsa65Seed: '', mldsa65Verify: '', spiderX: '', spiderY: '', enc: '', flow: '' })
  await e.save()
  for (const field of ['mldsa65_seed', 'mldsa65_verify', 'spider_x', 'spider_y']) assert.equal(payload(e).reality[field], undefined)
  assert.equal(payload(e).reality.max_time_diff, '1m')
  assert.equal(payload(e).decryption, undefined)
  assert.equal(payload(e).flow, undefined)
  e.open({ ...node, tunnel: JSON.parse(JSON.stringify(payload(e))) })
  assert.equal(e.draft.mldsa65Seed, '')
  assert.equal(e.draft.enc, '')
  Object.assign(e.draft, { mldsa65Seed: 'new-seed', mldsa65Verify: 'new-verify', enc: 'new-encryption' })
  await e.save()
  assert.equal(payload(e).reality.mldsa65_seed, 'new-seed')
  assert.equal(payload(e).decryption, 'new-encryption')
  e.draft.security = 'tls'; e.draft.cert = cert; e.draft.key = key
  await e.save()
  assert.equal(payload(e).reality, undefined)
})
const body = e => e.requests.at(-1)[2]

test('server metadata and material saves never submit a separate client template', async () => {
  for (const node of [tlsNode(), realityNode()]) {
    const e = setup(); e.open(node)
    e.draft.name = 'Renamed'
    await e.save()
    assert.equal('client_tunnel' in body(e), false)
    assert.equal(body(e).tunnel.ca_pem || '', node.tunnel.ca_pem || '')
    e.draft.enc = 'new-decryption'
    await e.save()
    assert.equal('client_tunnel' in body(e), false)
    assert.equal(body(e).tunnel.decryption, 'new-decryption')
  }
  assert.doesNotMatch(editorSource, /client_tunnel|editingPair|pairDirty|preservePair|editPair|resetPair|下发客户端配置|编辑下发模板|重置为自动派生/)
  assert.match(editorSource, /创建或关联映射后统一下发/)
})

test('backend save errors propagate without changing the server draft', async () => {
  const e = setup('server', async () => { throw Error('backend rejected') })
  e.open(realityNode()); e.draft.privateKey = 'new-private'
  await assert.rejects(e.save(), /backend rejected/)
  assert.equal(e.draft.privateKey, 'new-private')
  assert.equal('client_tunnel' in body(e), false)
})

const generated = {
  reality: { private_key: 'generated-private', public_key: 'generated-public', short_id: 'cc' },
  short_id: { short_id: 'dd' },
  vless: { decryption: 'generated-decryption', encryption: 'generated-encryption' },
  hysteria2: { password: 'generated-password' },
  certificate: { cert_pem: ca, key_pem: key, ca_pem: ca, expires_at: '2030-01-01T00:00:00Z' },
}

test('all generator kinds update server material without saving; bounds match API', async () => {
  const e = setup('server', async (_path, _method, request) => generated[request.kind])
  e.open(realityNode())
  await e.generate('reality')
  assert.equal(e.draft.privateKey, generated.reality.private_key)
  assert.equal(e.draft.shortIDs, 'cc')
  await e.generate('short_id')
  assert.equal(e.draft.shortIDs, 'dd')
  await e.generate('vless')
  assert.equal(e.draft.enc, generated.vless.decryption)
  e.draft.transport = 'hysteria2'
  await e.generate('hysteria2')
  assert.equal(e.draft.password, generated.hysteria2.password)
  await e.generate('certificate')
  assert.equal(e.options.ttl, 30)
  assert.equal(body(e).ttl_days, 30)
  assert.equal(e.draft.cert, ca)
  assert.equal(e.draft.ca, ca)
  assert.equal(e.requests.length, 5)
  assert.ok(e.requests.every(([path, method]) => path === '/nodes/generate' && method === 'POST'))
  assert.equal(e.generation.busy, '')
  assert.match(e.generation.status, /尚未保存/)
  for (const ttl of [0, 366, 1.5, 'invalid']) {
    e.options.ttl = ttl; await e.generate('certificate')
    assert.match(e.generation.error, /1 到 365/)
  }
  assert.equal(e.requests.length, 5)
  e.options.ttl = 365; await e.generate('certificate')
  assert.equal(body(e).ttl_days, 365)
  assert.match(editorSource, /id="cert-ttl"[^>]+max="365"/)
})


test('generation blocks saves and duplicate requests, drops stale results and ignores closed sessions', async () => {
  for (const change of [e => { e.draft.name = 'Changed' }, e => { e.options.mode = 'random' }, e => e.clearSecrets()]) {
    let resolve
    const e = setup('server', () => new Promise(done => { resolve = done }))
    const pending = e.generate('reality')
    assert.equal(e.generation.busy, 'reality')
    await assert.rejects(e.save(), /生成完成/)
    await e.generate('short_id')
    assert.equal(e.requests.length, 1)
    change(e); resolve(generated.reality); await pending
    assert.equal(e.draft.privateKey, '')
    assert.equal(e.generation.busy, '')
    assert.equal(e.generation.error, '')
    assert.ok(!e.generation.status || e.generation.status.includes('过期'))
  }
  let resolve
  const e = setup('server', () => new Promise(done => { resolve = done }))
  const pending = e.generate('certificate'); e.open(tlsNode()); resolve(generated.certificate); await pending
  assert.equal(e.draft.cert, cert)
  assert.equal(e.draft.ca, cert)
  assert.equal(e.generation.status, '')
})

test('generator failures and malformed responses preserve material and hide backend error contents', async () => {
  for (const respond of [async () => { throw Error('SECRET backend detail') }, async () => ({}), async () => ({ ...generated.certificate, key_pem: 'invalid SECRET' })]) {
    const e = setup('server', respond)
    e.open(tlsNode())
    await e.generate('certificate')
    assert.match(e.generation.error, /生成失败/)
    assert.doesNotMatch(e.generation.error, /SECRET/)
    assert.equal(e.generation.busy, '')
    assert.equal(e.draft.cert, cert)
    assert.equal(e.draft.key, key)
    assert.equal(e.draft.ca, cert)
  }
  let reject
  const e = setup('server', () => new Promise((_resolve, fail) => { reject = fail }))
  const pending = e.generate('reality'); e.clearSecrets(); reject(Error('SECRET')); await pending
  assert.equal(e.generation.error, '')
})

test('embedded nodes retain editing but cannot enroll, revoke or delete through table controls', async () => {
  const t = setupTable()
  const embedded = { id: 'embedded', embedded: true }
  t.ask(embedded, 'delete')
  assert.equal(t.pending.value, null)
  t.pending.value = embedded
  assert.equal(await t.run(), false)
  assert.equal(t.requests.length, 0)
  assert.match(tableSource, /v-if="!node.embedded"[^>]+@click="onboarding/)
  assert.match(tableSource, /v-if="!node.embedded"[^>]+@click="ask/)
  assert.match(tableSource, /v-if="!selected.embedded"/)
  assert.match(tableSource, /@click="editor\?\.open\(node\)"/)
  const e = setup(); e.open({ ...tlsNode(), embedded: true }); e.draft.name = 'Embedded renamed'; await e.save()
  assert.equal(body(e).name, 'Embedded renamed')
  assert.equal('embedded' in body(e), false)
  t.ask({ id: 'remote' }, 'delete'); await t.run()
  assert.equal(t.requests[0][1], 'DELETE')
})

test('node and endpoint saves never send removed SNI or priority fields', async () => {
  for (const security of ['tls', 'encryption']) {
    const e = setup()
    e.draft.security = security
    e.draft.enc = 'demo-encryption'
    await e.save()
    assert.equal('server_name' in body(e), false)
    assert.ok(body(e).connect_endpoints.every(endpoint => !('server_name' in endpoint) && !('priority' in endpoint)))
  }
  assert.doesNotMatch(editorSource + tableSource + source('../src/types.ts') + source('../src/format.ts'), /\bserver_name\b|\bserverName\b|\bpriority\b|SNI|优先级/)
  assert.match(editorSource, /endpoint-\$\{index\}-host`">主机\/域名<\/label>/)
  assert.match(editorSource, /endpoint-\$\{index\}-port`">端口<\/label>/)
  assert.doesNotMatch(editorSource, /Client 可达的监听地址|连接地址需要名称、监听地址|Port（连接端口）/)
})

test('API empty nested objects do not enable HY2 or REALITY; only server material is saved', async () => {
  const plain = { ...tlsNode(), tunnel: { listen_port: 8444, transport_security: 'plain', decryption: 'private-encryption' } }
  const hy2 = tlsNode(); hy2.tunnel.hysteria2 = { password: 'hy-password' }
  for (const [node, transport, security, protocol] of [[tlsNode(), 'tcp', 'tls', 'vless'], [plain, 'tcp', 'encryption', 'vless'], [realityNode(), 'tcp', 'reality', 'vless'], [hy2, 'quic', 'tls', 'hysteria2']]) {
    node.tunnel = { reality: {}, hysteria2: {}, ...node.tunnel }
    const e = setup(); e.open(node)
    assert.equal(e.draft.protocol, protocol)
    assert.equal(e.draft.transport, transport)
    assert.equal(e.draft.security, security)
    await e.save()
    assert.equal('client_tunnel' in body(e), false)
  }
})

test('onboarding displays role-specific flag commands and accepts HTTP only for trusted networks', async () => {
  const requests = []; let opens = 0
  const onboardingScript = source('../src/components/NodeOnboarding.vue').match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
  const context = vm.createContext({
    exports: {}, computed, ref, URL, location: { origin: 'https://master.example.com' },
    window: { setInterval: () => 1, clearInterval: () => {} }, onUnmounted: () => {}, defineExpose: () => {},
    api: async (...args) => { requests.push(args); return { prepare: "mkdir -p '/opt/docker/veilink-client-demo/config' '/opt/docker/veilink-client-demo/data' && chown -R 65532:65532 '/opt/docker/veilink-client-demo/config' '/opt/docker/veilink-client-demo/data' && chmod 700 '/opt/docker/veilink-client-demo/config' '/opt/docker/veilink-client-demo/data'", command: "docker run -itd --restart unless-stopped --name 'veilink-client-demo' -v '/opt/docker/veilink-client-demo/config:/config:ro' -v '/opt/docker/veilink-client-demo/data:/data' -e TZ=Asia/Shanghai ghcr.io/aurorax-neo/veilink:latest client -master-addr 'master.example.com:443' -node-id 'remote/id' -enroll-token 'token' -state-dir '/data/state' -control-server-name 'master.example.com'", token: 'token', expires_at: 2000000000, warning: '私有 Master CA 时，在角色子命令后添加 -control-ca /config/ca.pem。' } },
  })
  vm.runInContext(transpile(onboardingScript + '\nglobalThis.onboarding = { open, generate, revoke, node, modal, result, masterURL };'), context)
  const e = context.onboarding
  e.modal.value = { open: () => { opens++ } }
  const embedded = { id: 'embedded', embedded: true }
  e.open(embedded)
  assert.equal(opens, 0)
  assert.equal(e.node.value, null)
  await assert.rejects(e.generate(), /未选择节点/)
  e.node.value = embedded
  await assert.rejects(e.generate(), /内置节点/)
  await assert.rejects(e.revoke(), /内置节点/)
  assert.equal(requests.length, 0)
  e.open({ id: 'remote/id', embedded: false }); await e.generate()
  assert.equal(opens, 1)
  assert.equal(requests[0][0], '/nodes/remote%2Fid/join')
  assert.equal(JSON.stringify(requests[0][2]), JSON.stringify({ master_url: 'https://master.example.com' }))
  assert.match(source('../src/components/NodeOnboarding.vue'), /接入令牌在有效期内可重复用于此节点/)
  assert.doesNotMatch(source('../src/components/NodeOnboarding.vue'), /ttl_seconds|join-ttl|有效期（秒）/)
  assert.match(source('../src/components/NodeOnboarding.vue'), /不影响已接入节点的有效凭据/)
  assert.equal(e.result.value.token, 'token')
  assert.equal(e.result.value.command, "docker run -itd --restart unless-stopped --name 'veilink-client-demo' -v '/opt/docker/veilink-client-demo/config:/config:ro' -v '/opt/docker/veilink-client-demo/data:/data' -e TZ=Asia/Shanghai ghcr.io/aurorax-neo/veilink:latest client -master-addr 'master.example.com:443' -node-id 'remote/id' -enroll-token 'token' -state-dir '/data/state' -control-server-name 'master.example.com'")
  assert.match(e.result.value.prepare, /chown -R 65532:65532/)
  assert.match(e.result.value.warning, /-control-ca \/config\/ca.pem/)
  assert.match(source('../src/components/NodeOnboarding.vue'), /统一镜像 ghcr.io\/aurorax-neo\/veilink:latest.*server 或 client 子命令/)
  assert.doesNotMatch(source('../src/components/NodeOnboarding.vue'), /id="join-prepare"|目录准备命令/)
  assert.match(source('../src/components/NodeOnboarding.vue'), /id="join-command"[^>]+:value="result.command"/)
  e.masterURL.value = 'http://192.168.1.10:8443'
  await e.generate()
  assert.equal(JSON.stringify(requests[1][2]), JSON.stringify({ master_url: 'http://192.168.1.10:8443' }))
  assert.match(source('../src/components/NodeOnboarding.vue'), /HTTP\/h2c 不加密，仅用于可信网络/)
  e.masterURL.value = 'ftp://insecure.example'
  await assert.rejects(e.generate(), /http:\/\/ 或 https:\/\//)
  assert.equal(requests.length, 2)
  e.masterURL.value = 'https://master.example.com'
  e.open(embedded)
  assert.equal(e.result.value, null)
  assert.equal(e.node.value, null)
  assert.equal(opens, 1)
  await assert.rejects(e.generate(), /未选择节点/)
  assert.equal(requests.length, 2)
})

test('listen validation, NAT port independence, and transport copy stay explicit', async () => {
  const e = setup()
  e.draft.listen = '11111'
  await assert.rejects(e.save(), /监听地址必须是 IP/)
  e.draft.listen = '0.0.0.0'
  e.draft.listenPort = '8444'
  Object.assign(e.endpoints[0], { host: 'public.example.com', port: 443 })
  await e.save()
  assert.equal(body(e).tunnel.listen_port, 8444)
  assert.equal(body(e).connect_endpoints[0].port, 443)
  assert.equal('kind' in body(e).connect_endpoints[0], false)
  assert.equal(body(e).connect_endpoints[0].host, 'public.example.com')
  assert.match(editorSource, /Server 回源监听安全/)
  assert.match(editorSource, /Hysteria2 使用 QUIC\/UDP \+ TLS，当前实现不支持 REALITY/)
  assert.match(editorSource, /XHTTP packet-up 可走 HTTP\/HTTPS CDN，允许边缘终止 TLS/)
})

test('reactive server endpoints open as isolated editable copies', async () => {
  const node = reactive(tlsNode())
  const e = setup()
  assert.doesNotThrow(() => e.open(node))
  e.endpoints[0].host = 'edited.example.com'
  assert.equal(node.connect_endpoints[0].host, 'example.com')
  await e.save()
  assert.equal(body(e).connect_endpoints[0].host, 'edited.example.com')
})

test('certificate generation uses current enabled endpoint host', async () => {
  const e = setup('server', async () => generated.certificate)
  e.endpoints[0].enabled = false
  e.addEndpoint()
  e.endpoints[1].host = ' new.example.com '
  await e.generate('certificate')
  assert.equal(body(e).host, 'new.example.com')
  assert.equal('server_name' in body(e), false)
})

test('endpoint edits invalidate pending certificate results', async () => {
  let resolve
  const e = setup('server', () => new Promise(done => { resolve = done }))
  const pending = e.generate('certificate')
  e.endpoints[0].host = 'changed.example.com'
  resolve(generated.certificate)
  await pending
  assert.equal(e.draft.cert, cert)
  assert.match(e.generation.status, /丢弃过期/)
})

test('candidate inputs have unique explicit labels and no protocol classification', () => {
  const candidate = editorSource.match(/<div v-for="\(endpoint, index\) in endpoints"[\s\S]*?添加连接地址/)[0]
  const ids = [...candidate.matchAll(/:id="([^"]+)"/g)].map(match => match[1])
  const labels = [...candidate.matchAll(/:for="([^"]+)"/g)].map(match => match[1])
  assert.equal(ids.length, 4)
  assert.equal(new Set(ids).size, 4)
  assert.deepEqual(labels, ids)
  assert.ok(ids.every(id => id.includes('${index}')))
  assert.doesNotMatch(candidate + tableSource, /endpoint.kind|item.kind|value="(?:direct|nat|cdn)"/)
})

test('multiple connection addresses survive edits and removal without kind', async () => {
  const e = setup()
  e.addEndpoint()
  Object.assign(e.endpoints[1], { host: 'backup.example.com', port: 9443 })
  await e.save()
  assert.equal(body(e).connect_endpoints.length, 2)
  assert.ok(body(e).connect_endpoints.every(endpoint => !('kind' in endpoint)))
  e.open({ ...tlsNode(), ...JSON.parse(JSON.stringify(body(e))) })
  assert.equal(e.endpoints[1].host, 'backup.example.com')
  e.removeEndpoint(0)
  await e.save()
  assert.equal(body(e).connect_endpoints[0].port, 9443)
  assert.equal(body(e).tunnel.listen_port, 8444)
})

test('XHTTP saves JSON packet-up and separates HTTPS candidate from HTTP origin', async () => {
  const e = setup()
  e.draft.transport = 'xhttp'
  e.draft.security = 'encryption'
  await assert.rejects(e.save(), /必须启用 VLESS Encryption/)
  e.draft.enc = 'generated-decryption'
  e.draft.ca = cert
  e.draft.flow = 'xtls-rprx-vision'
  await e.save()
  assert.equal(payload(e).transport_security, 'plain')
  assert.equal(payload(e).xhttp.mode, 'packet-up')
  assert.equal(payload(e).xhttp.path, '/veilink/')
  assert.equal(payload(e).xhttp.tls, true)
  assert.equal(payload(e).xhttp.max_each_post_bytes, 32768)
  assert.equal(payload(e).xhttp.request_timeout_seconds, 15)
  assert.equal(payload(e).xhttp.padding_bytes, 100)
  assert.equal(payload(e).ca_pem, cert)
  assert.equal(payload(e).cert_pem, undefined)
  assert.equal(payload(e).flow, undefined)
  assert.equal(e.requests.at(-1)[2].client_tunnel, undefined)
  e.draft.transport = 'tcp'
  await e.save()
  assert.equal(payload(e).xhttp, undefined)
})

test('XHTTP restores HTTP options and rejects invalid paths and insecure HTTP', async () => {
  const e = setup()
  const node = tlsNode()
  node.tunnel.xhttp = { path: '/cdn/', mode: 'packet-up', tls: false, max_each_post_bytes: 2048, request_timeout_seconds: 30, padding_bytes: 256 }
  e.open(node)
  assert.equal(e.draft.transport, 'xhttp')
  assert.equal(e.draft.xhttpTLS, false)
  assert.equal(e.draft.xhttpPath, '/cdn/')
  assert.equal(e.draft.xhttpPostBytes, 2048)
  assert.equal(e.draft.xhttpTimeout, 30)
  assert.equal(e.draft.xhttpPadding, 256)
  await assert.rejects(e.save(), /必须启用 VLESS Encryption/)
  e.draft.enc = 'generated-decryption'
  for (const path of ['', '/missing', '//', '/a//b/', '/a/../b/', '/a/?x=1', '/a%2fb/', '/' + 'a'.repeat(256) + '/']) {
    e.draft.xhttpPath = path
    await assert.rejects(e.save(), /XHTTP 路径/)
  }
  e.draft.xhttpPath = '/cdn/'
  await e.save()
  assert.equal(payload(e).xhttp.max_each_post_bytes, 2048)
  assert.equal(payload(e).xhttp.request_timeout_seconds, 30)
  assert.equal(payload(e).xhttp.padding_bytes, 256)
  e.draft.xhttpPostBytes = 1000
  await assert.rejects(e.save(), /上行分片/)
  e.draft.xhttpPostBytes = 32768
  e.draft.xhttpTimeout = 61
  await assert.rejects(e.save(), /请求超时/)
  e.draft.xhttpTimeout = 15
  e.draft.xhttpPadding = 1001
  await assert.rejects(e.save(), /XHTTP 填充/)
  assert.equal(payload(e).xhttp.tls, false)
})

test('XHTTP mode selector defaults safely, restores saved modes, and sends only selected modes', async () => {
  assert.match(editorSource, /id="node-xhttp-mode" v-model="draft.xhttpMode"/)
  const modeSelector = editorSource.match(/<select id="node-xhttp-mode"[^>]*>(.*?)<\/select>/s)?.[1]
  assert.ok(modeSelector)
  for (const mode of ['packet-up', 'stream-up', 'stream-one', 'auto']) assert.match(modeSelector, new RegExp(`<option value="${mode}">${mode}</option>`))
  const e = setup()
  assert.equal(e.draft.xhttpMode, 'packet-up')
  e.draft.transport = 'xhttp'
  await e.save()
  assert.equal(payload(e).xhttp.mode, 'packet-up')
  for (const mode of ['stream-up', 'stream-one']) {
    e.draft.xhttpMode = mode
    e.draft.xhttpPostBytes = 0 // Stream modes do not use packet fragmentation.
    await e.save()
    assert.equal(payload(e).xhttp.mode, mode)
    assert.equal(payload(e).xhttp.max_each_post_bytes, undefined)
    const node = tlsNode()
    node.tunnel.xhttp = { path: '/stream/', mode, tls: true }
    e.open(node)
    assert.equal(e.draft.xhttpMode, mode)
    await e.save()
    assert.equal(payload(e).xhttp.mode, mode)
  }
  e.open({ ...tlsNode(), tunnel: { ...tlsNode().tunnel, xhttp: { path: '/legacy/', tls: true } } })
  assert.equal(e.draft.xhttpMode, 'packet-up')
  e.open()
  assert.equal(e.draft.xhttpMode, 'packet-up')
})

test('XHTTP stream modes reject insecure or unsupported transport and invalid modes before API requests', async () => {
  for (const mode of ['stream-up', 'stream-one']) {
    const e = setup()
    e.draft.transport = 'xhttp'
    e.draft.xhttpMode = mode
    e.draft.xhttpTLS = false
    await assert.rejects(e.save(), /流模式仅支持直连 HTTPS/)
    e.draft.xhttpTLS = true
    e.draft.security = 'encryption'
    e.draft.enc = 'generated-decryption'
    await assert.rejects(e.save(), /流模式仅支持直连 HTTPS/)
    e.draft.security = 'tls'
    e.draft.xhttpTLS = true
    e.draft.xhttpVersion = '1.1'
    await assert.rejects(e.save(), /流模式需要 HTTP\/2/)
    e.draft.xhttpVersion = ''
    assert.equal(e.requests.length, 0)
    e.draft.security = 'tls'
    e.draft.xhttpTLS = true
    await e.save()
    assert.equal(payload(e).xhttp.mode, mode)
    assert.equal(payload(e).transport_security, 'tls')
    assert.equal(payload(e).xhttp.tls, true)
    e.draft.xhttpMode = 'auto'
    await e.save()
    assert.equal(payload(e).xhttp.mode, 'auto')
    e.draft.xhttpMode = 'unknown'
    await assert.rejects(e.save(), /XHTTP 模式仅支持/)
    assert.equal(e.requests.length, 2)
  }
  assert.match(editorSource, /支持 TLS 的 HTTP\/2 或 HTTP\/3，以及 REALITY 内的 HTTP\/2/)
  assert.match(editorSource, /不连接 Xray 对端/)
})

test('XHTTP padding range saves, restores, and rejects invalid bounds', async () => {
  const e = setup()
  e.draft.transport = 'xhttp'
  e.draft.xhttpPadding = 120
  e.draft.xhttpPaddingMax = 450
  await e.save()
  assert.equal(payload(e).xhttp.padding_bytes, 120)
  assert.equal(payload(e).xhttp.padding_max_bytes, 450)
  e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
  assert.equal(e.draft.xhttpPadding, 120)
  assert.equal(e.draft.xhttpPaddingMax, 450)
  e.draft.xhttpPaddingMax = 119
  await assert.rejects(e.save(), /填充最大值/)
  e.draft.xhttpPaddingMax = 1001
  await assert.rejects(e.save(), /填充最大值/)
  e.draft.xhttpPaddingMax = 120
  await e.save()
  assert.equal('padding_max_bytes' in payload(e).xhttp, false)
  e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
  assert.equal(e.draft.xhttpPaddingMax, 120)
})

test('XHTTP HTTP/3 version persists explicitly and rejects unsafe origin or mode', async () => {
  const e = setup()
  e.draft.transport = 'xhttp'
  assert.equal(e.draft.xhttpVersion, '')
  await e.save()
  assert.equal('http_version' in payload(e).xhttp, false)
  assert.match(editorSource, /id="node-xhttp-version" v-model="draft.xhttpVersion"/)
  e.draft.xhttpVersion = '3'
  for (const mode of ['packet-up', 'stream-up', 'stream-one']) {
    e.draft.xhttpMode = mode
    await e.save()
    assert.equal(payload(e).xhttp.http_version, '3')
    e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
    assert.equal(e.draft.xhttpVersion, '3')
  }
  const count = e.requests.length
  e.draft.xhttpTLS = false
  await assert.rejects(e.save(), /HTTP\/3|流模式/)
  e.draft.xhttpTLS = true
  e.draft.security = 'encryption'
  await assert.rejects(e.save(), /HTTP\/3|流模式/)
  e.draft.security = 'tls'
  e.draft.xhttpVersion = '1.1'
  await assert.rejects(e.save(), /流模式/)
  e.draft.xhttpVersion = '4'
  await assert.rejects(e.save(), /HTTP 版本无效/)
  assert.equal(e.requests.length, count)
  e.open({ ...tlsNode(), tunnel: { ...tlsNode().tunnel, xhttp: { path: '/legacy/', mode: 'packet-up', tls: true } } })
  assert.equal(e.draft.xhttpVersion, '')
})

test('XHTTP optional headers survive editor roundtrip without leaking stream-only settings to packet-up', async () => {
  assert.match(editorSource, /id="node-xhttp-no-grpc" v-model="draft.xhttpNoGRPCHeader"/)
  assert.match(editorSource, /id="node-xhttp-no-sse" v-model="draft.xhttpNoSSEHeader"/)
  const e = setup()
  e.draft.transport = 'xhttp'
  e.draft.xhttpMode = 'stream-up'
  e.draft.xhttpNoGRPCHeader = true
  e.draft.xhttpNoSSEHeader = true
  await e.save()
  assert.equal(payload(e).xhttp.no_grpc_header, true)
  assert.equal(payload(e).xhttp.no_sse_header, true)
  e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
  assert.equal(e.draft.xhttpNoGRPCHeader, true)
  assert.equal(e.draft.xhttpNoSSEHeader, true)
  await e.save()
  assert.equal(payload(e).xhttp.no_grpc_header, true)
  e.draft.xhttpMode = 'packet-up'
  await e.save()
  assert.equal(payload(e).xhttp.no_grpc_header, undefined)
  assert.equal(payload(e).xhttp.no_sse_header, true)
  e.open()
  assert.equal(e.draft.xhttpNoGRPCHeader, false)
  assert.equal(e.draft.xhttpNoSSEHeader, false)
})

test('XHTTP server request header cap persists, defaults safely, and rejects out-of-range values', async () => {
  assert.match(editorSource, /id="node-xhttp-max-header" v-model.number="draft.xhttpMaxHeaderBytes"/)
  const e = setup()
  e.draft.transport = 'xhttp'
  await e.save()
  assert.equal(payload(e).xhttp.server_max_header_bytes, undefined)
  e.draft.xhttpMaxHeaderBytes = 16384
  await e.save()
  assert.equal(payload(e).xhttp.server_max_header_bytes, 16384)
  e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
  assert.equal(e.draft.xhttpMaxHeaderBytes, 16384)
  for (const invalid of [8191, 32769, 8192.5]) {
    e.draft.xhttpMaxHeaderBytes = invalid
    await assert.rejects(e.save(), /服务端请求头上限/)
  }
  e.open()
  assert.equal(e.draft.xhttpMaxHeaderBytes, 8192)
})

test('XHTTP uplink method defaults to POST and preserves PUT across all modes', async () => {
  assert.match(editorSource, /id="node-xhttp-uplink-method" v-model="draft.xhttpUplinkMethod"/)
  const e = setup()
  e.draft.transport = 'xhttp'
  await e.save()
  assert.equal(payload(e).xhttp.uplink_http_method, undefined)
  for (const mode of ['packet-up', 'stream-up', 'stream-one']) {
    e.draft.xhttpMode = mode
    e.draft.xhttpUplinkMethod = 'PUT'
    await e.save()
    assert.equal(payload(e).xhttp.uplink_http_method, 'PUT')
    e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
    assert.equal(e.draft.xhttpUplinkMethod, 'PUT')
  }
  e.draft.xhttpUplinkMethod = 'GET'
  await assert.rejects(e.save(), /上行方法仅支持 POST 或 PUT/)
  e.open()
  assert.equal(e.draft.xhttpUplinkMethod, 'POST')
})

test('XHTTP explicit h2c accepts only encrypted packet-up and never silently changes protocol', async () => {
  const e = setup()
  e.draft.transport = 'xhttp'
  e.draft.xhttpMode = 'packet-up'
  e.draft.xhttpVersion = '2'
  e.draft.xhttpTLS = false
  await assert.rejects(e.save(), /必须启用 VLESS Encryption/)
  e.draft.enc = 'generated-decryption'
  e.draft.security = 'encryption'
  await e.save()
  assert.equal(payload(e).xhttp.http_version, '2')
  assert.equal(payload(e).xhttp.tls, false)
  assert.equal(payload(e).transport_security, 'plain')
  e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
  assert.equal(e.draft.xhttpVersion, '2')
  assert.equal(e.draft.xhttpTLS, false)
  e.draft.security = 'tls'
  e.draft.cert = cert; e.draft.key = key
  await assert.rejects(e.save(), /h2c/)
  e.draft.security = 'reality'
  await e.save()
  assert.equal(payload(e).xhttp.http_version, '2')
  assert.equal(payload(e).xhttp.tls, false)
  e.draft.security = 'encryption'
  e.draft.xhttpMode = 'stream-up'
  await assert.rejects(e.save(), /流模式/)
  assert.match(editorSource, /h2c 仅限 packet-up\/auto 直连/)
})

test('XHTTP packet-up chunk range saves, restores and clears on stream mode', async () => {
  assert.match(editorSource, /id="node-xhttp-post-bytes-max" v-model.number="draft.xhttpPostBytesMax"/)
  const e = setup()
  e.draft.transport = 'xhttp'
  e.draft.xhttpPostBytes = 2048
  await e.save()
  assert.equal(payload(e).xhttp.post_bytes_max, undefined)
  e.draft.xhttpPostBytesMax = 4096
  await e.save()
  assert.equal(payload(e).xhttp.post_bytes_max, 4096)
  e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
  assert.equal(e.draft.xhttpPostBytesMax, 4096)
  for (const invalid of [-1, 2047, 32769, 1.5]) {
    e.draft.xhttpPostBytesMax = invalid
    await assert.rejects(e.save(), /分片最大值/)
  }
  e.draft.xhttpPostBytesMax = 4096
  e.draft.xhttpMode = 'stream-up'
  await e.save()
  assert.equal(payload(e).xhttp.post_bytes_max, undefined)
  e.open()
  assert.equal(e.draft.xhttpPostBytesMax, 0)
})

test('XHTTP packet-up pacing persists and never leaks into stream modes', async () => {
  assert.match(editorSource, /id="node-xhttp-post-interval" v-model.number="draft.xhttpPostInterval"/)
  assert.match(editorSource, /id="node-xhttp-post-interval-max" v-model.number="draft.xhttpPostIntervalMax"/)
  const e = setup()
  e.draft.transport = 'xhttp'
  await e.save()
  assert.equal(payload(e).xhttp.min_posts_interval_ms, undefined)
  e.draft.xhttpPostInterval = 45
  await e.save()
  assert.equal(payload(e).xhttp.min_posts_interval_ms, 45)
  e.draft.xhttpPostIntervalMax = 75
  await e.save()
  assert.equal(payload(e).xhttp.max_posts_interval_ms, 75)
  e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
  assert.equal(e.draft.xhttpPostInterval, 45)
  assert.equal(e.draft.xhttpPostIntervalMax, 75)
  for (const invalid of [-1, 44, 1001, 1.5]) {
    e.draft.xhttpPostIntervalMax = invalid
    await assert.rejects(e.save(), /分片最大间隔/)
  }
  e.draft.xhttpPostIntervalMax = 75
  for (const invalid of [-1, 1001, 1.5]) {
    e.draft.xhttpPostInterval = invalid
    await assert.rejects(e.save(), /分片最小间隔/)
  }
  e.draft.xhttpPostInterval = 45
  e.draft.xhttpMode = 'stream-up'
  await e.save()
  assert.equal(payload(e).xhttp.min_posts_interval_ms, undefined)
  assert.equal(payload(e).xhttp.max_posts_interval_ms, undefined)
  e.open()
  assert.equal(e.draft.xhttpPostInterval, 0)
  assert.equal(e.draft.xhttpPostIntervalMax, 0)
})

test('XHTTP Host override roundtrips without replacing dial endpoint or TLS identity', async () => {
  assert.match(editorSource, /id="node-xhttp-host" v-model="draft.xhttpHost"/)
  const e = setup()
  e.draft.transport = 'xhttp'
  await e.save()
  assert.equal(payload(e).xhttp.host, undefined)
  const dialHost = e.requests.at(-1)[2].connect_endpoints[0].host
  e.draft.xhttpHost = 'edge.example.com'
  await e.save()
  assert.equal(payload(e).xhttp.host, 'edge.example.com')
  assert.equal(e.requests.at(-1)[2].connect_endpoints[0].host, dialHost)
  e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
  assert.equal(e.draft.xhttpHost, 'edge.example.com')
  for (const invalid of ['Edge.example.com', 'edge.example.com:443', 'edge..example.com', '-bad.example.com']) {
    e.draft.xhttpHost = invalid
    await assert.rejects(e.save(), /XHTTP Host/)
  }
  e.open()
  assert.equal(e.draft.xhttpHost, '')
})

test('XHTTP metadata defaults, valid placements and tables roundtrip on Server only', async () => {
  const e = setup()
  e.draft.transport = 'xhttp'
  await e.save()
  for (const field of ['session_id_placement', 'session_id_key', 'seq_placement', 'seq_key', 'session_id_table', 'session_id_length']) assert.equal(field in payload(e).xhttp, false)
  Object.assign(e.draft, { xhttpSessionPlacement: 'query', xhttpSessionKey: 'sid_1', xhttpSeqPlacement: 'header', xhttpSeqKey: 'X-Veilink-Number', xhttpSessionTable: 'hex', xhttpSessionLength: 32 })
  await e.save()
  const saved = JSON.parse(JSON.stringify(payload(e)))
  assert.equal(saved.xhttp.session_id_placement, 'query')
  assert.equal(saved.xhttp.session_id_key, 'sid_1')
  assert.equal(saved.xhttp.seq_placement, 'header')
  assert.equal(saved.xhttp.seq_key, 'X-Veilink-Number')
  assert.equal(saved.xhttp.session_id_table, 'hex')
  assert.equal(saved.xhttp.session_id_length, 32)
  e.open({ id: 'server', name: 'Server', tunnel: saved })
  assert.equal(e.draft.xhttpSessionPlacement, 'query')
  assert.equal(e.draft.xhttpSeqKey, 'X-Veilink-Number')
  await e.save()
  assert.equal(JSON.stringify(payload(e).xhttp), JSON.stringify(saved.xhttp))
  Object.assign(e.draft, { xhttpSessionPlacement: 'header', xhttpSessionKey: '', xhttpSeqPlacement: 'header', xhttpSeqKey: '', xhttpSessionTable: 'base62', xhttpSessionLength: 24 })
  await e.save()
  assert.equal(payload(e).xhttp.session_id_key, undefined)
  assert.equal(payload(e).xhttp.seq_key, undefined)
  e.draft.xhttpSessionTable = '0123456789ABCDEF-_'
  e.draft.xhttpSessionLength = 32
  await e.save()
  assert.equal(payload(e).xhttp.session_id_table, '0123456789ABCDEF-_')
  e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
  assert.equal(e.draft.xhttpSessionTable, '0123456789ABCDEF-_')
  e.setSessionTable('')
  await e.save()
  assert.equal(payload(e).xhttp.session_id_table, undefined)
  assert.equal(payload(e).xhttp.session_id_length, undefined)
  Object.assign(e.draft, { xhttpSessionPlacement: 'cookie', xhttpSessionKey: 'x_sid', xhttpSeqPlacement: 'cookie', xhttpSeqKey: 'x_number' })
  await e.save()
  assert.equal(payload(e).xhttp.session_id_placement, 'cookie')
  assert.equal(payload(e).xhttp.seq_placement, 'cookie')
  e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
  assert.equal(e.draft.xhttpSessionKey, 'x_sid')
  assert.equal(e.draft.xhttpSeqKey, 'x_number')
  assert.match(editorSource, /id="node-xhttp-session-placement"/)
  assert.match(editorSource, /id="node-xhttp-seq-placement"/)
  assert.match(editorSource, /id="node-xhttp-session-table-kind"/)
})

test('XHTTP metadata rejects unsafe keys, collisions, alphabet and entropy before API', async () => {
  const e = setup(); e.draft.transport = 'xhttp'
  const invalid = [
    [{ xhttpSessionKey: 'sid' }, /路径位置/],
    [{ xhttpSessionPlacement: 'cookie', xhttpSessionKey: 'session' }, /Cookie 键名/],
    [{ xhttpSessionPlacement: 'cookie', xhttpSessionKey: 'x_padding' }, /Cookie 键名/],
    [{ xhttpSessionPlacement: 'wrong' }, /位置无效/],
    ...['x_padding', 'Bad', 'sid-1', 'a'.repeat(41), 'a b'].map(key => [{ xhttpSessionPlacement: 'query', xhttpSessionKey: key }, /查询键名/]),
    ...['X-Veilink-', 'x-veilink-SID', 'X-Veilink-EOF', 'X-Veilink-upload-complete', 'X-Veilink-SID_1', 'X-Veilink-' + 'a'.repeat(39)].map(key => [{ xhttpSessionPlacement: 'header', xhttpSessionKey: key }, /请求头键名/]),
    [{ xhttpSessionPlacement: 'query', xhttpSessionKey: '', xhttpSeqPlacement: 'query', xhttpSeqKey: 'x_session' }, /同一个键名/],
    [{ xhttpSessionPlacement: 'header', xhttpSessionKey: 'X-Veilink-SEQ', xhttpSeqPlacement: 'header', xhttpSeqKey: '' }, /同一个键名/],
    [{ xhttpSessionTable: 'hex', xhttpSessionLength: 24 }, /128 位熵/],
    [{ xhttpSessionTable: 'base62', xhttpSessionLength: 0 }, /24–64/],
    [{ xhttpSessionTable: '', xhttpSessionLength: 32 }, /24–64/],
    [{ xhttpSessionTable: '0123456789abcdef/', xhttpSessionLength: 32 }, /字符表/],
    [{ xhttpSessionTable: '0123456789abcdef0', xhttpSessionLength: 32 }, /字符表/],
    [{ xhttpSessionTable: '0123456789abcdef', xhttpSessionLength: 64.5 }, /24–64/],
    [{ xhttpSessionTable: '0123456789abcdef', xhttpSessionLength: 65 }, /24–64/],
  ]
  for (const [values, error] of invalid) {
    e.open(); Object.assign(e.draft, { name: 'Demo node', cert, key, transport: 'xhttp' }, values)
    await assert.rejects(e.save(), error)
    assert.equal(e.requests.length, 0)
  }
})

test('XHTTP mode switches omit inactive metadata without losing active edits; client cannot submit it', async () => {
  const e = setup(); e.draft.transport = 'xhttp'
  Object.assign(e.draft, { xhttpSessionPlacement: 'query', xhttpSessionKey: 'sid', xhttpSeqPlacement: 'query', xhttpSeqKey: 'seq', xhttpSessionTable: 'hex', xhttpSessionLength: 32 })
  e.draft.xhttpMode = 'auto'; await e.save()
  assert.equal(payload(e).xhttp.seq_key, 'seq')
  e.draft.xhttpMode = 'stream-up'; await e.save()
  assert.equal(payload(e).xhttp.session_id_key, 'sid')
  assert.equal(payload(e).xhttp.seq_key, undefined)
  assert.equal(payload(e).xhttp.seq_placement, undefined)
  e.draft.xhttpMode = 'stream-one'; await e.save()
  for (const field of ['session_id_placement', 'session_id_key', 'seq_placement', 'seq_key', 'session_id_table', 'session_id_length']) assert.equal(field in payload(e).xhttp, false)
  e.draft.xhttpMode = 'packet-up'; await e.save()
  assert.equal(payload(e).xhttp.seq_key, 'seq')
  e.draft.transport = 'tcp'; await e.save()
  assert.equal(payload(e).xhttp, undefined)
  const c = setup('client')
  c.open({ id: 'client', name: 'Client', tunnel: { xhttp: { path: '/cdn/', mode: 'packet-up', session_id_key: 'sid' } } })
  Object.assign(c.draft, { xhttpSessionPlacement: 'query', xhttpSessionKey: 'sid', xhttpSeqPlacement: 'header', xhttpSeqKey: 'X-Veilink-Seq' })
  await c.save()
  assert.equal('tunnel' in body(c), false)
  assert.equal('client_tunnel' in body(c), false)
})

test('XHTTP custom padding placement and method roundtrip without changing legacy defaults', async () => {
  const e = setup()
  e.draft.transport = 'xhttp'
  await e.save()
  for (const field of ['padding_obfs_mode', 'padding_placement', 'padding_key', 'padding_header', 'padding_method']) assert.equal(payload(e).xhttp[field], undefined)
  e.draft.xhttpPaddingObfs = true
  e.setPaddingPlacement('query')
  e.draft.xhttpPaddingMethod = 'tokenish'
  await e.save()
  assert.equal(payload(e).xhttp.padding_placement, 'query')
  assert.equal(payload(e).xhttp.padding_key, 'x_padding')
  assert.equal(payload(e).xhttp.padding_method, 'tokenish')
  assert.equal(payload(e).xhttp.padding_header, undefined)
  e.open({ id: 'server', name: 'Server', tunnel: payload(e) })
  assert.equal(e.draft.xhttpPaddingObfs, true)
  assert.equal(e.draft.xhttpPaddingPlacement, 'query')
  e.setPaddingPlacement('header')
  await e.save()
  assert.equal(payload(e).xhttp.padding_header, 'X-Padding')
  assert.equal(payload(e).xhttp.padding_key, undefined)
  const legacyHeader = JSON.parse(JSON.stringify(payload(e)))
  delete legacyHeader.xhttp.padding_header
  e.open({ id: 'server', name: 'Server', tunnel: legacyHeader })
  assert.equal(e.draft.xhttpPaddingHeader, 'X-Padding')
  await e.save()
  e.setPaddingPlacement('cookie')
  await e.save()
  assert.equal(payload(e).xhttp.padding_key, 'x_padding')
  e.draft.xhttpPaddingObfs = false
  await e.save()
  assert.equal(payload(e).xhttp.padding_placement, undefined)
  e.open()
  assert.equal(e.draft.xhttpPaddingObfs, false)
  assert.match(editorSource, /id="node-xhttp-padding-placement"/)
})

test('XHTTP padding rejects reserved and colliding metadata fields before API', async () => {
  const e = setup()
  e.draft.transport = 'xhttp'; e.draft.xhttpPaddingObfs = true
  for (const [placement, key, header, error] of [
    ['cookie', 'session', 'X-Veilink-Padding', /Cookie 键名/],
    ['query', 'Bad-Key', 'X-Veilink-Padding', /查询键名/],
    ['header', 'x_padding', 'Referer', /不能覆盖 Referer/],
    ['header', 'x_padding', 'X-Veilink-EOF', /请求头名/],
    ['query_in_header', 'x_padding', 'Cookie', /请求头名/],
  ]) {
    e.draft.xhttpPaddingPlacement = placement
    e.draft.xhttpPaddingKey = key
    e.draft.xhttpPaddingHeader = header
    await assert.rejects(e.save(), error)
    assert.equal(e.requests.length, 0)
  }
  e.setPaddingPlacement('cookie')
  e.draft.xhttpSessionPlacement = 'cookie'
  e.draft.xhttpSessionKey = 'x_padding'
  await assert.rejects(e.save(), /不能覆盖会话或序号/)
  e.draft.xhttpSessionKey = ''
  e.draft.xhttpPaddingMethod = 'invalid'
  await assert.rejects(e.save(), /填充方法/)
  assert.equal(e.requests.length, 0)
})

test('XHTTP buffered and concurrent posts default safely and roundtrip in packet-up and auto', async () => {
  const e = setup(); e.draft.transport = 'xhttp'
  assert.equal(e.draft.xhttpMaxBufferedPosts, 0)
  assert.equal(e.draft.xhttpMaxConcurrentPosts, 0)
  await e.save()
  for (const field of ['max_buffered_posts', 'max_concurrent_posts']) assert.equal(field in payload(e).xhttp, false)
  for (const mode of ['packet-up', 'auto']) {
    e.draft.xhttpMode = mode
    for (const [buffered, concurrent] of [[0, 1], [1, 0], [1, 2], [7, 8], [32, 8]]) {
      Object.assign(e.draft, { xhttpMaxBufferedPosts: buffered, xhttpMaxConcurrentPosts: concurrent })
      await e.save()
      assert.equal(payload(e).xhttp.max_buffered_posts, buffered || undefined)
      assert.equal(payload(e).xhttp.max_concurrent_posts, concurrent || undefined)
      e.open({ ...tlsNode(), tunnel: payload(e) })
      assert.equal(e.draft.xhttpMaxBufferedPosts, buffered)
      assert.equal(e.draft.xhttpMaxConcurrentPosts, concurrent)
      await e.save()
      assert.equal(payload(e).xhttp.max_buffered_posts, buffered || undefined)
      assert.equal(payload(e).xhttp.max_concurrent_posts, concurrent || undefined)
    }
  }
  e.open({ ...tlsNode(), tunnel: { ...tlsNode().tunnel, xhttp: { path: '/legacy/', mode: 'packet-up', tls: true } } })
  assert.equal(e.draft.xhttpMaxBufferedPosts, 0)
  assert.equal(e.draft.xhttpMaxConcurrentPosts, 0)
  e.open()
  assert.equal(e.draft.xhttpMaxBufferedPosts, 0)
  assert.equal(e.draft.xhttpMaxConcurrentPosts, 0)
  const controls = editorSource.split('\n').find(line => line.includes('<div v-if=') && line.includes('node-xhttp-max-buffered-posts'))
  assert.match(controls, /v-if="xhttpEffectiveMode === 'packet-up'"/)
  assert.match(controls, /id="node-xhttp-max-buffered-posts" v-model.number="draft.xhttpMaxBufferedPosts"[^>]+max="32"[^>]+step="1"/)
  assert.match(controls, /id="node-xhttp-max-concurrent-posts" v-model.number="draft.xhttpMaxConcurrentPosts"[^>]+:max="Math.min\(8, draft.xhttpMaxBufferedPosts \+ 1\)"[^>]+step="1"/)
})

test('XHTTP buffered and concurrent posts reject invalid bounds and combinations before API', async () => {
  for (const mode of ['packet-up', 'auto']) {
    const e = setup(); e.draft.transport = 'xhttp'; e.draft.xhttpMode = mode
    for (const invalid of [-1, 33, 1.5, NaN, Infinity, '', '2']) {
      e.draft.xhttpMaxBufferedPosts = invalid
      await assert.rejects(e.save(), /缓冲分片上限/)
      assert.equal(e.requests.length, 0)
    }
    e.draft.xhttpMaxBufferedPosts = 32
    for (const invalid of [-1, 9, 1.5, NaN, Infinity, '', '2']) {
      e.draft.xhttpMaxConcurrentPosts = invalid
      await assert.rejects(e.save(), /并发上行上限/)
      assert.equal(e.requests.length, 0)
    }
    for (const [buffered, concurrent] of [[0, 2], [1, 3], [6, 8]]) {
      Object.assign(e.draft, { xhttpMaxBufferedPosts: buffered, xhttpMaxConcurrentPosts: concurrent })
      await assert.rejects(e.save(), /不能超过缓冲分片上限加 1/)
      assert.equal(e.requests.length, 0)
    }
  }
})

test('XHTTP post limits stay out of streams and TCP without losing edits; clients cannot submit them', async () => {
  const e = setup(); e.draft.transport = 'xhttp'
  Object.assign(e.draft, { xhttpMaxBufferedPosts: 7, xhttpMaxConcurrentPosts: 8 })
  for (const mode of ['stream-up', 'stream-one']) {
    e.draft.xhttpMode = mode
    await e.save()
    for (const field of ['max_buffered_posts', 'max_concurrent_posts']) assert.equal(field in payload(e).xhttp, false)
    assert.equal(e.draft.xhttpMaxBufferedPosts, 7)
    assert.equal(e.draft.xhttpMaxConcurrentPosts, 8)
  }
  e.draft.xhttpMode = 'auto'; await e.save()
  assert.equal(payload(e).xhttp.max_buffered_posts, 7)
  assert.equal(payload(e).xhttp.max_concurrent_posts, 8)
  Object.assign(e.draft, { xhttpMode: 'stream-up', xhttpMaxBufferedPosts: -1, xhttpMaxConcurrentPosts: 9 })
  await e.save()
  for (const field of ['max_buffered_posts', 'max_concurrent_posts']) assert.equal(field in payload(e).xhttp, false)
  e.draft.transport = 'tcp'; await e.save()
  assert.equal(payload(e).xhttp, undefined)
  const c = setup('client')
  c.open({ id: 'client', name: 'Client', tunnel: { xhttp: { path: '/cdn/', mode: 'packet-up', tls: true, max_buffered_posts: 7, max_concurrent_posts: 8 } } })
  Object.assign(c.draft, { transport: 'xhttp', xhttpMaxBufferedPosts: -1, xhttpMaxConcurrentPosts: 9 })
  await c.save()
  assert.equal('tunnel' in body(c), false)
  assert.equal('client_tunnel' in body(c), false)
  const clientUI = editorSource.slice(editorSource.indexOf('<template>'), editorSource.indexOf('<template v-else>'))
  assert.doesNotMatch(clientUI, /node-xhttp-max-(buffered|concurrent)-posts/)
})

test('XHTTP stream-up server padding periods default, restore and save fixed or ranged periods', async () => {
  const e = setup(); Object.assign(e.draft, { transport: 'xhttp', xhttpMode: 'stream-up' })
  assert.equal(e.streamUpPeriod.min, '')
  assert.equal(e.streamUpPeriod.max, '')
  for (const [min, max] of [['', ''], [0, 0], [1, ''], [20, 0], [20, 80], [300, 300]]) {
    Object.assign(e.streamUpPeriod, { min, max })
    await e.save()
    assert.equal(payload(e).xhttp.stream_up_server_secs, min || undefined)
    assert.equal(payload(e).xhttp.stream_up_server_max_secs, max || undefined)
    const saved = JSON.parse(JSON.stringify(payload(e)))
    e.open({ ...tlsNode(), tunnel: saved })
    assert.equal(e.streamUpPeriod.min, min || '')
    assert.equal(e.streamUpPeriod.max, max || '')
    await e.save()
    assert.equal(JSON.stringify(payload(e).xhttp), JSON.stringify(saved.xhttp))
  }
  e.open({ ...tlsNode(), tunnel: { ...tlsNode().tunnel, xhttp: { path: '/legacy/', mode: 'stream-up', tls: true, stream_up_server_secs: 0, stream_up_server_max_secs: 0 } } })
  assert.equal(e.streamUpPeriod.min, '')
  assert.equal(e.streamUpPeriod.max, '')
  e.streamUpPeriod.min = 30; e.open()
  assert.equal(e.streamUpPeriod.min, '')
  assert.equal(e.streamUpPeriod.max, '')
  const controls = editorSource.split('\n').find(line => line.includes('<div v-if=') && line.includes('node-xhttp-stream-up-server-secs'))
  assert.match(controls, /v-if="xhttpEffectiveMode === 'stream-up'"/)
  for (const id of ['node-xhttp-stream-up-server-secs', 'node-xhttp-stream-up-server-max-secs']) {
    assert.match(controls, new RegExp(`id="${id}"[^>]+type="number"[^>]+min="0"[^>]+max="300"[^>]+step="1"[^>]+placeholder="默认"`))
  }
  assert.doesNotMatch(controls, /required/)
})

test('XHTTP stream-up server padding periods reject invalid ranges and combinations before API', async () => {
  const e = setup(); Object.assign(e.draft, { transport: 'xhttp', xhttpMode: 'stream-up' })
  for (const min of [-1, 301, 1.5, NaN, Infinity, 'bad', '20']) {
    Object.assign(e.streamUpPeriod, { min, max: '' })
    await assert.rejects(e.save(), /填充周期/)
    assert.equal(e.requests.length, 0)
  }
  for (const max of [-1, 301, 20.5, NaN, Infinity, 'bad', '80', 19]) {
    Object.assign(e.streamUpPeriod, { min: 20, max })
    await assert.rejects(e.save(), /填充最大周期/)
    assert.equal(e.requests.length, 0)
  }
  for (const min of ['', 0]) {
    Object.assign(e.streamUpPeriod, { min, max: 80 })
    await assert.rejects(e.save(), /填充最大周期/)
    assert.equal(e.requests.length, 0)
  }
})

test('XHTTP stream-up server periods never leak into other modes, TCP or Client submissions', async () => {
  const e = setup(); e.draft.transport = 'xhttp'
  Object.assign(e.streamUpPeriod, { min: 20, max: 80 })
  for (const mode of ['packet-up', 'auto', 'stream-one']) {
    e.draft.xhttpMode = mode; await e.save()
    for (const field of ['stream_up_server_secs', 'stream_up_server_max_secs']) assert.equal(field in payload(e).xhttp, false)
    assert.equal(e.streamUpPeriod.min, 20)
    assert.equal(e.streamUpPeriod.max, 80)
  }
  e.draft.xhttpMode = 'stream-up'; await e.save()
  assert.equal(payload(e).xhttp.stream_up_server_secs, 20)
  assert.equal(payload(e).xhttp.stream_up_server_max_secs, 80)
  Object.assign(e.streamUpPeriod, { min: -1, max: 301 })
  e.draft.xhttpMode = 'auto'; await e.save()
  assert.equal(payload(e).xhttp.stream_up_server_secs, undefined)
  e.draft.transport = 'tcp'; await e.save()
  assert.equal(payload(e).xhttp, undefined)
  const c = setup('client')
  c.open({ id: 'client', name: 'Client', tunnel: { xhttp: { path: '/stream/', mode: 'stream-up', tls: true, stream_up_server_secs: 20, stream_up_server_max_secs: 80 } } })
  Object.assign(c.streamUpPeriod, { min: -1, max: 301 })
  await c.save()
  assert.equal('tunnel' in body(c), false)
  assert.equal('client_tunnel' in body(c), false)
  const clientUI = editorSource.slice(editorSource.indexOf('<template>'), editorSource.indexOf('<template v-else>'))
  assert.doesNotMatch(clientUI, /node-xhttp-stream-up-server/)
})

test('XHTTP download endpoint uses enabled endpoint selector, rejects stale IDs, and clears inactive fields', async () => {
  assert.match(editorSource, /<select id="node-xhttp-download-endpoint" v-model="draft.xhttpDownloadEndpoint">/)
  assert.doesNotMatch(editorSource, /id="node-xhttp-download-endpoint"[^>]*<input/)
  const e = setup()
  e.addEndpoint('download.example.com', 9443)
  e.endpoints[1].id = 'down'
  e.endpoints[1].name = '下行入口'
  e.endpoints[1].enabled = true
  e.draft.transport = 'xhttp'
  e.draft.xhttpDownloadEndpoint = 'down'
  await e.save()
  assert.equal(payload(e).xhttp.download_endpoint_id, 'down')
  e.open({ id: 'server', name: 'Server', connect_endpoints: e.requests.at(-1)[2].connect_endpoints, tunnel: payload(e) })
  assert.equal(e.draft.xhttpDownloadEndpoint, 'down')
  e.endpoints[1].enabled = false
  await assert.rejects(e.save(), /当前启用的 XHTTP 分离下行入口/)
  assert.equal(e.requests.length, 1)
  e.endpoints[1].enabled = true
  e.draft.xhttpMode = 'stream-up'
  await e.save()
  assert.equal(payload(e).xhttp.download_endpoint_id, 'down')
  e.draft.xhttpMode = 'stream-one'
  await e.save()
  assert.equal(payload(e).xhttp.download_endpoint_id, undefined)
  e.draft.xhttpMode = 'packet-up'
  e.draft.xhttpDownloadEndpoint = 'unknown'
  await assert.rejects(e.save(), /当前启用的 XHTTP 分离下行入口/)
  const c = setup('client')
  c.open({ id: 'client', name: 'Client', tunnel: { xhttp: { path: '/cdn/', download_endpoint_id: 'down' } } })
  await c.save()
  assert.equal('tunnel' in body(c), false)
})

test('XHTTP REALITY auto serializes effective stream mode and keeps inactive packet edits', async () => {
  assert.match(editorSource, /:required="draft.security === 'encryption' \|\| draft.transport === 'xhttp' && !draft.xhttpTLS && draft.security !== 'reality'"/)
  const e = setup()
  Object.assign(e.draft, { transport: 'xhttp', security: 'reality', xhttpMode: 'auto', xhttpVersion: '2', xhttpDataPlacement: 'header', xhttpChunkSize: 64, xhttpMaxBufferedPosts: 4, xhttpMaxConcurrentPosts: 4, xhttpSessionPlacement: 'query', xhttpSessionKey: 'sid', xhttpSeqPlacement: 'query', xhttpSeqKey: 'seq', xhttpNoGRPCHeader: true })
  await e.save()
  const x = payload(e).xhttp
  assert.equal(x.mode, 'auto')
  assert.equal(x.tls, false)
  assert.equal(x.no_grpc_header, true)
  for (const field of ['max_each_post_bytes', 'uplink_data_placement', 'uplink_chunk_size', 'max_buffered_posts', 'max_concurrent_posts', 'session_id_placement', 'session_id_key', 'seq_placement', 'seq_key']) assert.equal(x[field], undefined)
  e.addEndpoint('download.example.com', 443)
  e.endpoints[1].id = 'down'
  e.draft.xhttpDownloadEndpoint = 'down'
  Object.assign(e.streamUpPeriod, { min: 1, max: 2 })
  await e.save()
  assert.equal(payload(e).xhttp.download_endpoint_id, 'down')
  assert.equal(payload(e).xhttp.session_id_key, 'sid')
  assert.equal(payload(e).xhttp.seq_key, undefined)
  assert.equal(payload(e).xhttp.stream_up_server_secs, 1)
  e.endpoints[1].enabled = false
  await assert.rejects(e.save(), /当前启用/)
  e.draft.xhttpDownloadEndpoint = ''
  e.draft.xhttpVersion = '1.1'
  await assert.rejects(e.save(), /HTTP\/2/)
  Object.assign(e.draft, { security: 'tls', xhttpTLS: true, xhttpVersion: '2' })
  await e.save()
  assert.equal(payload(e).xhttp.max_buffered_posts, 4)
  assert.equal(payload(e).xhttp.uplink_chunk_size, 64)
  assert.equal(payload(e).xhttp.no_grpc_header, undefined)
})

test('XHTTP data keys reject session, sequence and padding collisions before API', async () => {
  for (const placement of ['header', 'cookie']) {
    for (const field of ['session', 'seq', 'padding']) {
      if (field === 'padding' && placement === 'header') continue
      const e = setup()
      Object.assign(e.draft, { transport: 'xhttp', xhttpDataPlacement: placement })
      const key = placement === 'header' ? 'X-Veilink-DATA-0' : 'x_data_0'
      if (field === 'padding') Object.assign(e.draft, { xhttpPaddingObfs: true, xhttpPaddingPlacement: 'cookie', xhttpPaddingKey: key })
      else { e.draft[field === 'session' ? 'xhttpSessionPlacement' : 'xhttpSeqPlacement'] = placement; e.draft[field === 'session' ? 'xhttpSessionKey' : 'xhttpSeqKey'] = key }
      await assert.rejects(e.save(), /不能与会话、序号或填充键冲突/)
      assert.equal(e.requests.length, 0)
    }
  }
  assert.match(editorSource, /<template v-if="xhttpEffectiveMode !== 'stream-one'">/)
  assert.match(editorSource, /<div v-if="draft.xhttpMode !== 'stream-one'"><label for="node-xhttp-download-endpoint">/)
})
