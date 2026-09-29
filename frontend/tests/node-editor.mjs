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
const { validateNode, validatePEM, PEM_MAX_BYTES } = formatContext.exports
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
  vm.runInContext(transpile(script + '\nglobalThis.editor = { open, save, draft, endpoints, addEndpoint, removeEndpoint, uploadPEM, uploads, clearSecrets, pemFields, reading, uploadError, generate, generation, options };'), context)
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
  const context = vm.createContext({ exports: {}, computed, ref, inject: () => desk, deskKey: {}, defineProps: () => ({ role }), onMounted: callback => callback(), onUnmounted: () => {}, setInterval: () => 7, clearInterval: () => {}, api: async (...args) => { requests.push(args) } })
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
  assert.match(source('../src/styles.css'), /\.nodes-table-client \{ min-width: 780px; \}/)
})

const ca = cert.replace('ZGVtbw==', 'Y3VzdG9t')
const tlsNode = () => ({ id: 'server', name: 'Server', address: 'example.com', port: 443, connect_endpoints: [{ id: 'primary', name: '首选地址', host: 'example.com', port: 443, enabled: true }], tunnel: { listen_port: 8444, transport_security: 'tls', cert_pem: cert, key_pem: key, ca_pem: cert }, client_tunnel: { transport_security: 'tls', ca_pem: ca } })
const realityNode = () => ({ id: 'reality', name: 'Reality', address: 'example.com', port: 443, connect_endpoints: [{ id: 'primary', name: '首选地址', host: 'example.com', port: 443, enabled: true }], tunnel: { listen_port: 8444, reality: { private_key: 'private', short_ids: 'aa,bb', server_names: 'example.com', dest: 'example.com:443' } }, client_tunnel: { reality: { public_key: 'public', short_id: 'bb', fingerprint: 'firefox', server_names: 'example.com', max_time_diff: '1m' } } })
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
  assert.match(source('../src/components/NodeOnboarding.vue'), /id="join-prepare"[^>]+:value="result.prepare"/)
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
  node.tunnel.xhttp = { path: '/cdn/', mode: 'packet-up', tls: false }
  e.open(node)
  assert.equal(e.draft.transport, 'xhttp')
  assert.equal(e.draft.xhttpTLS, false)
  assert.equal(e.draft.xhttpPath, '/cdn/')
  await assert.rejects(e.save(), /必须启用 VLESS Encryption/)
  e.draft.enc = 'generated-decryption'
  for (const path of ['', '/missing', '//', '/a//b/', '/a/../b/', '/a/?x=1', '/a%2fb/', '/' + 'a'.repeat(256) + '/']) {
    e.draft.xhttpPath = path
    await assert.rejects(e.save(), /XHTTP 路径/)
  }
  e.draft.xhttpPath = '/cdn/'
  await e.save()
  assert.equal(payload(e).xhttp.tls, false)
})
