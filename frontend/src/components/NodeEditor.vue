<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { api } from '../api'
import { PEM_MAX_BYTES, validateNode, validatePEM } from '../format'
import type { ConnectEndpoint, Node, TunnelConfig } from '../types'
import Modal from './Modal.vue'
import SecretField from './SecretField.vue'

const props = defineProps<{ role: 'server' | 'client'; saved: () => Promise<void> }>()
const modal = ref<InstanceType<typeof Modal> | null>(null)
const server = computed(() => props.role === 'server')
const draft = reactive({ id: '', name: '', address: '', port: '443', serverName: '', listenPort: '443', transport: 'tcp', security: 'tls', flow: '', enc: '', cert: '', key: '', ca: '', listen: '', dest: '', privateKey: '', publicKey: '', shortIDs: '', names: '', password: '' })
const endpoints = reactive<ConnectEndpoint[]>([])
function addEndpoint() { endpoints.push({ id: `endpoint-${Date.now()}-${endpoints.length}`, name: '备用地址', host: '', port: 443, server_name: '', priority: endpoints.length, enabled: true }) }
function removeEndpoint(index: number) { if (endpoints.length > 1) endpoints.splice(index, 1) }
let original: TunnelConfig = {}
let persisted: TunnelConfig = {}
let pairBase: TunnelConfig = {}
const pairedPrivate = ref('')
const pairedDecryption = ref('')
const generatedEncryption = ref('')
const section = ref<'server' | 'client'>('server')
const session = ref(0)
const editingPair = ref(false)
const pairDirty = ref(false)
const hasPersistedPair = ref(false)
const autoPair = ref(false)
const initialMaterial = ref('')
function materialSnapshot() { return JSON.stringify([draft.transport, draft.security, draft.serverName, draft.flow, draft.enc, draft.cert, draft.key, draft.ca, draft.dest, draft.privateKey, draft.shortIDs, draft.names, draft.password]) }
const preservePair = computed(() => hasPersistedPair.value && !autoPair.value && materialSnapshot() === initialMaterial.value)
const pair = reactive({ transport: 'tcp', security: 'tls', publicKey: '', shortID: '', fingerprint: '', encryption: '', ca: '', flow: '', password: '' })
const savedPair = reactive({ ...pair })
const flowAllowed = computed(() => draft.transport === 'tcp' && ['tls', 'reality'].includes(draft.security))
watch(() => draft.transport, transport => { if (transport === 'hysteria2') draft.security = 'tls' }, { flush: 'sync' })
watch(() => pair.transport, transport => { if (transport === 'hysteria2') pair.security = 'tls' }, { flush: 'sync' })
const preview = computed(() => ({
  transport: draft.transport, security: draft.transport === 'hysteria2' ? 'tls' : draft.security,
  publicKey: draft.privateKey === pairedPrivate.value ? draft.publicKey : '',
  shortID: draft.shortIDs.split(',')[0]?.trim() || '', fingerprint: 'chrome',
  encryption: draft.enc === pairedDecryption.value ? generatedEncryption.value : '',
  ca: draft.ca, flow: flowAllowed.value ? draft.flow : '', password: draft.password,
}))
const shownPair = computed(() => pairDirty.value ? pair : preservePair.value ? savedPair : preview.value)
watch(shownPair, value => {
  if (editingPair.value && !pairDirty.value) {
    pairBase = preservePair.value ? structuredClone(persisted) : {}
    Object.assign(pair, value)
  }
}, { flush: 'sync' })
function editPair() {
  if (!pairDirty.value) pairBase = preservePair.value ? structuredClone(persisted) : {}
  Object.assign(pair, shownPair.value); editingPair.value = true
}
function resetPair(derive = true) { editingPair.value = false; pairDirty.value = false; autoPair.value = derive; pairBase = {} }
type PEMField = 'cert' | 'key' | 'ca'
const pemLabels = { cert: '证书 PEM', key: '私钥 PEM', ca: 'CA PEM（可选）' }
const pemFields = computed<PEMField[]>(() => server.value && (draft.transport === 'hysteria2' || draft.security === 'tls') ? ['cert', 'key', 'ca'] : [])
const uploads = reactive<Record<PEMField, { busy: boolean; error: string; status: string; revision: number }>>({
  cert: { busy: false, error: '', status: '', revision: 0 }, key: { busy: false, error: '', status: '', revision: 0 }, ca: { busy: false, error: '', status: '', revision: 0 },
})
const reading = computed(() => Object.values(uploads).some(state => state.busy))
const uploadError = computed(() => pemFields.value.map(field => uploads[field].error).find(Boolean))
type GenerateKind = 'reality' | 'short_id' | 'vless' | 'hysteria2' | 'certificate'
const generation = reactive({ busy: '' as GenerateKind | '', error: '', status: '', revision: 0 })
const options = reactive({ mode: 'native', authentication: 'x25519', ttl: 30 })
function clearUpload(field: PEMField) { Object.assign(uploads[field], { busy: false, error: '', status: '', revision: uploads[field].revision + 1 }) }
function clearSecrets() {
  session.value++
  for (const field of ['cert', 'key', 'ca'] as const) { clearUpload(field); draft[field] = '' }
  draft.privateKey = ''; draft.enc = ''; draft.password = ''; draft.publicKey = ''; original = {}; persisted = {}
  pairedPrivate.value = ''; pairedDecryption.value = ''; generatedEncryption.value = ''
  Object.assign(pair, { publicKey: '', shortID: '', fingerprint: '', encryption: '', ca: '', flow: '', password: '' })
  Object.assign(savedPair, pair); hasPersistedPair.value = false; initialMaterial.value = ''
  resetPair(false)
  Object.assign(generation, { busy: '', error: '', status: '', revision: generation.revision + 1 })
}
async function uploadPEM(event: Event, field: PEMField) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  clearUpload(field)
  const state = uploads[field]
  const revision = state.revision
  if (file.size > PEM_MAX_BYTES) { state.error = '文件不能超过 64 KiB。'; return }
  state.busy = true
  try {
    const text = await file.text()
    if (state.revision !== revision) return
    const problem = validatePEM(text, field) || (!text.trim() ? '文件为空，请选择 PEM 文件。' : '')
    if (problem) { state.error = problem; return }
    draft[field] = text.trim(); state.status = '已载入，保存后生效。'
  } catch { if (state.revision === revision) state.error = '读取失败，请重试或粘贴 PEM。' }
  finally { if (state.revision === revision) state.busy = false }
}
function generationSnapshot() { return JSON.stringify([draft, endpoints, pair, editingPair.value, pairDirty.value, autoPair.value, options, uploads]) }
async function generate(kind: GenerateKind) {
  if (!server.value || generation.busy || reading.value) return
  if (kind === 'certificate' && (!Number.isInteger(Number(options.ttl)) || Number(options.ttl) < 1 || Number(options.ttl) > 365)) {
    generation.error = '证书有效期须为 1 到 365 天的整数。'; generation.status = ''; return
  }
  const primary = endpoints.find(endpoint => endpoint.enabled) || endpoints[0]
  const revision = ++generation.revision
  const snapshot = generationSnapshot()
  generation.busy = kind; generation.error = ''; generation.status = ''
  try {
    const result = await api<Record<string, string>>('/nodes/generate', 'POST', {
      role: 'server', kind,
      ...(kind === 'certificate' ? { server_name: primary?.server_name?.trim() || primary?.host.trim() || '', ttl_days: Number(options.ttl) } : {}),
      ...(kind === 'vless' ? { mode: options.mode, authentication: options.authentication } : {}),
    })
    if (revision !== generation.revision) return
    if (snapshot !== generationSnapshot()) { generation.status = '表单已变更，已丢弃过期生成结果。请重新生成。'; return }
    const required = { reality: ['private_key', 'public_key', 'short_id'], short_id: ['short_id'], vless: ['decryption', 'encryption'], hysteria2: ['password'], certificate: ['cert_pem', 'key_pem', 'ca_pem', 'expires_at'] }[kind]
    if (!result || required.some(field => typeof result[field] !== 'string' || !result[field])) throw new Error('invalid response')
    if (kind === 'reality') { draft.privateKey = result.private_key!; draft.publicKey = result.public_key!; draft.shortIDs = result.short_id!; pairedPrivate.value = draft.privateKey }
    if (kind === 'short_id') draft.shortIDs = result.short_id!
    if (kind === 'vless') { draft.enc = result.decryption!; pairedDecryption.value = draft.enc; generatedEncryption.value = result.encryption! }
    if (kind === 'hysteria2') draft.password = result.password!
    if (kind === 'certificate') {
      for (const field of ['cert', 'key', 'ca'] as const) {
        const value = result[`${field}_pem`]!
        if (validatePEM(value, field)) throw new Error('invalid PEM')
      }
      for (const field of ['cert', 'key', 'ca'] as const) { clearUpload(field); draft[field] = result[`${field}_pem`]! }
    }
    // Keep explicit edits; changing private material must not silently discard user intent.
    if (!pairDirty.value) resetPair()
    generation.status = '已生成配对参数，尚未保存。' + (pairDirty.value ? ' 请核对已编辑的下发配置。' : '')
  } catch {
    if (revision === generation.revision) generation.error = '生成失败，请检查参数、登录状态及生成接口后重试。现有配置未保存。'
  } finally { if (revision === generation.revision) generation.busy = '' }
}
function open(node?: Node) {
  clearSecrets(); section.value = 'server'
  original = structuredClone(node?.tunnel ? JSON.parse(JSON.stringify(node.tunnel)) : {})
  persisted = structuredClone(node?.client_tunnel ? JSON.parse(JSON.stringify(node.client_tunnel)) : {})
  const t = original
  const savedEndpoints = node?.connect_endpoints?.length ? node.connect_endpoints : node?.address ? [{ id: 'primary', name: '首选地址', host: node.address, port: node.port || 443, server_name: node.server_name || node.address, priority: 0, enabled: true }] : []
  endpoints.splice(0, endpoints.length, ...savedEndpoints.map(endpoint => ({ ...endpoint })))
  if (!endpoints.length && server.value) addEndpoint()
  Object.assign(draft, {
    id: node?.id || '', name: node?.name || '', address: node?.address || '', port: String(node?.port || 443), serverName: node?.server_name || '', listenPort: String(t.listen_port || node?.port || 443),
    transport: t.hysteria2?.password ? 'hysteria2' : 'tcp',
    security: t.hysteria2?.password ? 'tls' : t.reality && Object.values(t.reality).some(Boolean) ? 'reality' : t.transport_security === 'plain' ? 'encryption' : 'tls',
    flow: t.flow || '', enc: t.decryption || '', cert: t.cert_pem || '', key: t.key_pem || '', ca: t.ca_pem || '', listen: t.listen_host || '',
    dest: t.reality?.dest || '', privateKey: t.reality?.private_key || '', publicKey: persisted.reality?.public_key || t.reality?.public_key || '',
    shortIDs: t.reality?.short_ids || '', names: t.reality?.server_names || '', password: t.hysteria2?.password || '',
  })
  pairedPrivate.value = draft.privateKey; pairedDecryption.value = draft.enc; generatedEncryption.value = persisted.encryption || ''
  initialMaterial.value = materialSnapshot()
  // Metadata-only saves preserve the exact stored public template.
  hasPersistedPair.value = !!node?.client_tunnel && server.value
  if (hasPersistedPair.value) {
    Object.assign(savedPair, { transport: persisted.hysteria2?.password ? 'hysteria2' : 'tcp', security: persisted.hysteria2?.password ? 'tls' : persisted.reality?.public_key ? 'reality' : persisted.transport_security === 'plain' ? 'encryption' : 'tls', publicKey: persisted.reality?.public_key || '', shortID: persisted.reality?.short_id || '', fingerprint: persisted.reality?.fingerprint || '', encryption: persisted.encryption || '', ca: persisted.ca_pem || '', flow: persisted.flow || '', password: persisted.hysteria2?.password || '' })
  }
  modal.value?.open()
}
function pairedTunnel(): TunnelConfig {
  const p = pair
  // Keep approved public settings not exposed by this editor (for example REALITY names).
  const t: TunnelConfig = { ...pairBase, transport_security: p.transport === 'hysteria2' || p.security === 'reality' ? '' : p.security === 'tls' ? 'tls' : 'plain' }
  delete t.reality; delete t.hysteria2; delete t.encryption; delete t.ca_pem; delete t.flow
  if (p.transport === 'hysteria2') t.hysteria2 = { ...pairBase.hysteria2, password: p.password.trim() }
  else if (p.security === 'reality') t.reality = { ...pairBase.reality, public_key: p.publicKey.trim(), short_id: p.shortID.trim(), fingerprint: p.fingerprint.trim() }
  if (p.encryption.trim()) t.encryption = p.encryption.trim()
  if (p.ca.trim()) { const problem = validatePEM(p.ca, 'ca'); if (problem) throw new Error(problem); t.ca_pem = p.ca.trim() }
  if (p.flow) t.flow = p.flow
  return t
}
async function save() {
  if (reading.value) throw new Error('请等待 PEM 文件读取完成。')
  if (generation.busy) throw new Error('请等待生成完成。')
  const primary = endpoints.find(endpoint => endpoint.enabled) || endpoints[0]
  if (server.value && primary && !primary.host.trim() && draft.address.trim()) {
    primary.host = draft.address.trim(); primary.port = Number(draft.port); primary.server_name = draft.serverName.trim() || draft.address.trim()
  }
  const serverName = server.value ? (primary?.server_name || '').trim() || (primary?.host || '').trim() : ''
  const problem = validateNode({ ...draft, address: primary?.host || '', port: String(primary?.port || ''), serverName, role: props.role })
  if (uploadError.value) throw new Error(uploadError.value)
  if (problem) { section.value = 'server'; throw new Error(problem) }
  if (server.value) {
    if (!endpoints.length || !endpoints.some(endpoint => endpoint.enabled)) throw new Error('至少启用一个客户端连接地址。')
    for (const endpoint of endpoints) {
      if (!endpoint.name?.trim() || !endpoint.host?.trim() || !(endpoint.server_name || '').trim() || Number(endpoint.port) < 1 || Number(endpoint.port) > 65535) throw new Error('连接地址需要名称、Host、端口和 SNI。')
    }
  }
  const tunnel: TunnelConfig = {}
  if (server.value) {
    tunnel.transport_security = draft.transport === 'hysteria2' || draft.security === 'reality' ? '' : draft.security === 'tls' ? 'tls' : 'plain'
    if (draft.transport === 'hysteria2') {
      if (!draft.password.trim()) throw new Error('请输入 Hysteria2 密码。')
      tunnel.hysteria2 = { password: draft.password.trim() }
    }
    if (draft.transport === 'hysteria2' || draft.security === 'tls') {
      tunnel.cert_pem = draft.cert.trim(); tunnel.key_pem = draft.key.trim()
      if (draft.ca.trim()) tunnel.ca_pem = draft.ca.trim()
    } else if (draft.security === 'reality') {
      tunnel.reality = { ...original.reality, dest: draft.dest.trim(), private_key: draft.privateKey.trim(), short_ids: draft.shortIDs.trim(), server_names: draft.names.trim() }
      delete tunnel.reality.public_key
    }
    if (draft.transport === 'tcp' && draft.security === 'encryption' && (!draft.enc.trim() || draft.enc.trim() === 'none')) throw new Error('plain 无 TLS：请输入 VLESS 解密配置，或点击生成配对配置；不能使用 none。')
    if (draft.enc.trim()) tunnel.decryption = draft.enc.trim()
    if (flowAllowed.value && draft.flow) tunnel.flow = draft.flow
    if (draft.listen.trim()) tunnel.listen_host = draft.listen.trim()
    tunnel.listen_port = Number(draft.listenPort)
  }
  await api(draft.id ? `/nodes/${encodeURIComponent(draft.id)}` : '/nodes', draft.id ? 'PUT' : 'POST', {
    name: draft.name.trim(), role: props.role, address: server.value ? primary?.host.trim() : '', port: server.value ? Number(primary?.port) : 0,
    server_name: server.value ? (primary?.server_name || '').trim() : '',
    ...(server.value ? { connect_endpoints: endpoints.map(endpoint => ({ ...endpoint, name: endpoint.name.trim(), host: endpoint.host.trim(), server_name: (endpoint.server_name || '').trim(), port: Number(endpoint.port), priority: Number(endpoint.priority) })), tunnel } : {}),
    ...(server.value && pairDirty.value ? { client_tunnel: pairedTunnel() } : server.value && preservePair.value ? { client_tunnel: persisted } : {}),
  })
  await props.saved()
  return true
}
defineExpose({ open })
</script>

<template>
  <Modal ref="modal" :title="`${draft.id ? '编辑' : '新建'}${server ? '服务端' : '客户端'}`" :submit="save" :disabled="reading || !!uploadError || !!generation.busy" @close="clearSecrets">
    <label for="node-name">名称</label><input id="node-name" v-model="draft.name" maxlength="128" required />
    <p v-if="!server" class="help">客户端仅可修改名称。有效隧道配置由管理中心按映射服务端统一下发；在节点详情查看来源，不支持本地覆盖。</p>
    <template v-else>
      <div class="chips config-switch" aria-label="配置分区">
        <button type="button" :aria-pressed="section === 'server'" @click="section = 'server'">服务端配置</button>
        <button type="button" :aria-pressed="section === 'client'" @click="section = 'client'">下发客户端配置{{ pairDirty ? ' · 已编辑' : '' }}</button>
      </div>
      <section v-if="section === 'server'" :key="session" aria-label="服务端配置">
        <h3>本地监听</h3>
        <div class="grid-2">
          <div><label for="node-listen">监听 IP</label><input id="node-listen" v-model="draft.listen" placeholder="默认 127.0.0.1；公网监听可填 0.0.0.0" /></div>
          <div><label for="node-listen-port">监听端口</label><input id="node-listen-port" v-model="draft.listenPort" type="number" min="1" max="65535" required /></div>
        </div>
        <small class="help">Server 只绑定这里的 IP、端口和传输网络；与客户端连接地址分离。</small>
        <h3>客户端连接地址</h3>
        <small class="help">Host / Port 是 Client 拨号使用的公网可达地址，不是 Server 本地监听地址。SNI 独立设置，须匹配 TLS 证书或 REALITY 域名；多候选按优先级失败切换。</small>
        <div v-for="(endpoint, index) in endpoints" :key="endpoint.id" class="panel paired-fields">
          <div><label :for="`endpoint-${index}-name`">名称</label><input :id="`endpoint-${index}-name`" v-model="endpoint.name" /></div>
          <div class="grid-2"><div><label :for="`endpoint-${index}-host`">Host（公网可达地址）</label><input :id="`endpoint-${index}-host`" v-model="endpoint.host" placeholder="域名或 IP" /></div><div><label :for="`endpoint-${index}-port`">Port（连接端口）</label><input :id="`endpoint-${index}-port`" v-model="endpoint.port" type="number" min="1" max="65535" /></div></div>
          <div class="grid-2"><div><label :for="`endpoint-${index}-sni`">SNI</label><input :id="`endpoint-${index}-sni`" v-model="endpoint.server_name" /></div><div><label :for="`endpoint-${index}-priority`">优先级</label><input :id="`endpoint-${index}-priority`" v-model="endpoint.priority" type="number" /></div></div>
          <div class="actions"><label :for="`endpoint-${index}-enabled`"><input :id="`endpoint-${index}-enabled`" v-model="endpoint.enabled" type="checkbox" /> 启用</label><button type="button" class="btn small danger" :disabled="endpoints.length === 1" @click="removeEndpoint(index)">删除</button></div>
        </div>
        <button type="button" class="btn small" @click="addEndpoint">添加连接地址</button>
        <small class="warning">中间代理须保持原始 TCP 或 UDP/QUIC 的 L4 透传；HTTP-only 或终止、改写协议的 CDN 不支持。</small>
        <div class="grid-2">
          <div><label for="node-security">安全</label><select id="node-security" :value="draft.transport === 'hysteria2' ? 'tls' : draft.security" :disabled="draft.transport === 'hysteria2'" @change="draft.security = ($event.target as HTMLSelectElement).value"><option value="tls">TLS</option><option value="reality">REALITY</option><option value="encryption">Encryption（无 TLS）</option></select></div>
          <div><label for="node-transport">传输</label><select id="node-transport" v-model="draft.transport"><option value="tcp">TCP</option><option value="hysteria2">Hysteria2</option></select></div>
        </div>
        <small v-if="draft.transport === 'hysteria2'" class="help">Hysteria2 基于 QUIC/UDP 且使用 TLS，当前上游和本实现不支持 REALITY。</small>
        <small v-if="draft.transport === 'hysteria2'" class="help">请放行监听端口的 UDP 并核对 NAT 的 UDP 转发；生成密码后保存，客户端密码须一致。证书、信任 CA 和 SNI 仍须匹配；不能启用 Vision。</small>
        <small v-else-if="draft.security === 'tls'" class="help">TLS 使用 TCP：上传配对证书与私钥，或生成自签证书。接入候选的 SNI 须匹配证书；私有 CA 须随模板下发，验证失败时不要关闭证书校验。</small>
        <small v-else-if="draft.security === 'reality'" class="help">REALITY 使用 TCP：填写可达的回落目标与允许的伪装域名，生成密钥对和 Short ID。客户端公钥、Short ID 与域名须匹配；不要同时填写 TLS PEM。</small>
        <small v-else class="help">plain 使用 TCP 且没有外层 TLS，必须启用 VLESS Encryption；不接受证书 PEM、REALITY、Hysteria2 或 Vision。请生成配对配置后保存，而非填 none。</small>
        <template v-if="pemFields.length">
          <div class="field-actions config-switch"><div><label for="cert-ttl">自签证书有效天数</label><input id="cert-ttl" v-model="options.ttl" type="number" min="1" max="365" /></div><button type="button" class="btn small" :disabled="!!generation.busy || reading" @click="generate('certificate')">生成自签证书</button></div>
          <small class="warning">非公共 CA 证书。生成的 CA 会配对下发以建立信任；请核对 TLS 名称。</small>
        </template>
        <template v-for="field in pemFields" :key="field">
          <SecretField v-if="field === 'key'" id="node-key" v-model="draft.key" label="私钥 PEM" multiline required @update:model-value="clearUpload('key')" />
          <template v-else><label :for="`node-${field}`">{{ pemLabels[field] }}</label><textarea :id="`node-${field}`" v-model="draft[field]" class="mono" rows="3" :required="field === 'cert'" :spellcheck="false" autocomplete="off" :aria-invalid="!!uploads[field].error" @input="clearUpload(field)" /></template>
          <input :id="`node-${field}-upload`" type="file" accept=".pem,.crt,.key" :aria-label="`上传${pemLabels[field]}`" :disabled="uploads[field].busy || !!generation.busy" @change="uploadPEM($event, field)" />
          <small class="help">{{ field === 'ca' ? '用于客户端信任此服务端；留空使用系统根证书。' : '粘贴或上传 PEM，单项最多 64 KiB。' }}</small>
          <small class="help" :class="{ 'detail-error': uploads[field].error }" role="status">{{ uploads[field].busy ? '读取中…' : uploads[field].error || uploads[field].status }}</small>
        </template>
        <SecretField v-if="draft.transport === 'hysteria2'" id="node-hy-password" v-model="draft.password" label="Hysteria2 密码" required><button type="button" class="btn small" :disabled="!!generation.busy || reading" @click="generate('hysteria2')">生成密码</button></SecretField>
        <template v-else-if="draft.security === 'reality'">
          <label for="node-dest">回落目标</label><input id="node-dest" v-model="draft.dest" placeholder="example.com:443" />
          <SecretField id="node-private" v-model="draft.privateKey" label="REALITY 私钥"><button type="button" class="btn small" :disabled="!!generation.busy || reading" @click="generate('reality')">生成密钥对</button></SecretField>
          <label for="node-names">伪装域名</label><input id="node-names" v-model="draft.names" placeholder="逗号分隔" />
          <label for="node-short">Short IDs</label><div class="field-actions"><input id="node-short" v-model="draft.shortIDs" placeholder="逗号分隔" /><button type="button" class="btn small" :disabled="!!generation.busy || reading" @click="generate('short_id')">生成 Short ID</button></div>
        </template>
        <SecretField id="node-encryption" v-model="draft.enc" label="VLESS 解密配置" :required="draft.transport === 'tcp' && draft.security === 'encryption'"><button type="button" class="btn small" :disabled="!!generation.busy || reading" @click="generate('vless')">生成配对配置</button></SecretField>
        <small class="help">VLESS Encryption：服务端保存 decryption，客户端只接收配对 encryption，不能互换。TLS、REALITY、Hysteria2 下可选，plain 下必填；重新生成后须保存并等待双方应用新修订。</small>
        <div class="grid-2"><div><label for="vless-mode">生成模式</label><select id="vless-mode" v-model="options.mode"><option v-for="mode in ['native', 'xorpub', 'random']" :key="mode">{{ mode }}</option></select></div><div><label for="vless-auth">认证算法</label><select id="vless-auth" v-model="options.authentication"><option>x25519</option><option>mlkem768</option></select></div></div>
        <template v-if="flowAllowed"><label for="node-flow">Flow</label><select id="node-flow" v-model="draft.flow"><option value="">无</option><option>xtls-rprx-vision</option></select></template>
        <small class="help">Vision 仅用于 TCP + TLS/REALITY。只有独立已认证连接内、满足结构和记录边界的 TLS 1.3 才直拷；启用 Encryption 或无法安全识别时保留加密回退，mux、控制与 UDP 不裸传。选择 Vision 不代表所有流量都会直拷。</small>
      </section>
      <section v-else aria-label="下发客户端配置">
        <p class="help">服务端持有私钥，此处仅下发客户端所需参数。关键配对值必须与服务端一致；管理中心会拒绝不匹配配置。</p>
        <div class="actions config-switch"><button v-if="!editingPair" type="button" class="btn small" @click="editPair">编辑下发模板</button><button type="button" class="btn small" @click="resetPair()">重置为自动派生</button></div>
        <p class="help">{{ pairDirty ? '保存将提交已编辑模板，由管理中心校验配对。' : preservePair ? '显示已保存模板；仅修改名称、地址、端口或监听 IP 时保留。修改安全参数后自动派生。' : '自动派生：保存由管理中心重新生成模板。无法本地推导的值显示为空。' }}</p>
        <fieldset class="paired-fields" @input="pairDirty = true" @change="pairDirty = true">
          <div class="grid-2"><div><label for="pair-security">安全</label><select v-if="editingPair" id="pair-security" v-model="pair.security" :disabled="pair.transport === 'hysteria2'"><option value="tls">TLS</option><option value="reality">REALITY</option><option value="encryption">Encryption</option></select><input v-else id="pair-security" :value="shownPair.security" readonly /></div><div><label for="pair-transport">传输</label><select v-if="editingPair" id="pair-transport" v-model="pair.transport"><option value="tcp">TCP</option><option value="hysteria2">Hysteria2</option></select><input v-else id="pair-transport" :value="shownPair.transport" readonly /></div></div>
          <template v-if="shownPair.security === 'reality' && shownPair.transport === 'tcp'">
            <label for="pair-public">REALITY 公钥</label><input id="pair-public" :value="shownPair.publicKey" :readonly="!editingPair" placeholder="保存后由管理中心派生" @input="pair.publicKey = ($event.target as HTMLInputElement).value" />
            <label for="pair-short">Short ID</label><input id="pair-short" :value="shownPair.shortID" :readonly="!editingPair" @input="pair.shortID = ($event.target as HTMLInputElement).value" />
            <label for="pair-fingerprint">指纹</label><input id="pair-fingerprint" :value="shownPair.fingerprint" :readonly="!editingPair" placeholder="chrome" @input="pair.fingerprint = ($event.target as HTMLInputElement).value" />
          </template>
          <SecretField id="pair-encryption" :model-value="shownPair.encryption" label="VLESS 加密配置" :readonly="!editingPair" @update:model-value="pair.encryption = $event; pairDirty = true" />
          <SecretField v-if="shownPair.transport === 'hysteria2'" id="pair-password" :model-value="shownPair.password" label="Hysteria2 密码" :readonly="!editingPair" @update:model-value="pair.password = $event; pairDirty = true" />
          <template v-if="shownPair.security === 'tls' || shownPair.transport === 'hysteria2'"><label for="pair-ca">信任 CA PEM</label><textarea id="pair-ca" :value="shownPair.ca" :readonly="!editingPair" rows="3" class="mono" placeholder="系统根证书" @input="pair.ca = ($event.target as HTMLTextAreaElement).value" /></template>
          <label for="pair-flow">Flow</label><input id="pair-flow" :value="shownPair.flow" :readonly="!editingPair" placeholder="无" @input="pair.flow = ($event.target as HTMLInputElement).value" />
        </fieldset>
      </section>
      <p v-if="generation.busy || generation.status" class="help" role="status">{{ generation.busy ? '正在生成… 保存将在生成完成后可用。' : generation.status }}</p>
      <p v-if="generation.error" class="error" role="alert">{{ generation.error }}</p>
    </template>
  </Modal>
</template>
