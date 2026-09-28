<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { api } from '../api'
import { PEM_MAX_BYTES, validateNode, validatePEM } from '../format'
import type { ConnectEndpoint, Node, TunnelConfig } from '../types'
import Modal from './Modal.vue'
import SecretField from './SecretField.vue'

const props = defineProps<{ role: 'server' | 'client'; saved: () => Promise<void>; defaultName?: string }>()
const modal = ref<InstanceType<typeof Modal> | null>(null)
const server = computed(() => props.role === 'server')
const draft = reactive({ id: '', name: '', address: '', port: '443', listenPort: '443', protocol: 'vless' as 'vless' | 'hysteria2', transport: 'tcp' as 'tcp' | 'xhttp' | 'quic' | 'hysteria2', security: 'tls', flow: '', enc: '', cert: '', key: '', ca: '', listen: '', dest: '', privateKey: '', shortIDs: '', names: '', password: '', xhttpPath: '/veilink/', xhttpTLS: true })
const endpoints = reactive<ConnectEndpoint[]>([])
let endpointPortAuto = true
let endpointPortDefault = '443'
function addEndpoint(host = '127.0.0.1', port = Number(draft.listenPort) || 443) { endpoints.push({ id: `endpoint-${Date.now()}-${endpoints.length}`, name: endpoints.length ? '备用地址' : '首选地址', host, port, enabled: true }) }
function markEndpointPortEdited(index: number) { if (index === 0) endpointPortAuto = false }
function removeEndpoint(index: number) { if (endpoints.length > 1) endpoints.splice(index, 1) }
let original: TunnelConfig = {}
const session = ref(0)
const flowAllowed = computed(() => draft.protocol === 'vless' && draft.transport === 'tcp' && ['tls', 'reality'].includes(draft.security))
watch(flowAllowed, allowed => { if (!allowed) draft.flow = '' }, { flush: 'sync' })
watch(() => draft.protocol, protocol => {
  if (protocol === 'hysteria2') { draft.transport = 'quic'; draft.security = 'tls' }
  else if (draft.transport === 'quic') draft.transport = 'tcp'
}, { flush: 'sync' })
watch(() => draft.transport, transport => { if (transport === 'quic' || transport === 'hysteria2') { draft.protocol = 'hysteria2'; draft.transport = 'quic'; draft.security = 'tls' } }, { flush: 'sync' })
watch(() => draft.security, security => { if (security === 'reality' && draft.transport === 'xhttp') draft.xhttpTLS = false }, { flush: 'sync' })
watch(() => draft.listenPort, value => {
  if (!server.value || !endpointPortAuto || !/^\d+$/.test(value)) return
  const primary = endpoints[0]
  if (!primary || String(primary.port) !== endpointPortDefault) return
  primary.port = Number(value)
  endpointPortDefault = value
}, { flush: 'sync' })
type PEMField = 'cert' | 'key' | 'ca'
const pemLabels = { cert: '证书 PEM', key: '私钥 PEM', ca: 'CA PEM（可选）' }
const pemFields = computed<PEMField[]>(() => !server.value ? [] : (draft.protocol === 'hysteria2' || draft.security === 'tls') ? ['cert', 'key', 'ca'] : draft.transport === 'xhttp' && draft.xhttpTLS ? ['ca'] : [])
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
  draft.privateKey = ''; draft.enc = ''; draft.password = ''; original = {}
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
function generationSnapshot() { return JSON.stringify([draft, endpoints, options, uploads]) }
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
      ...(kind === 'certificate' ? { host: primary?.host.trim() || '', ttl_days: Number(options.ttl) } : {}),
      ...(kind === 'vless' ? { mode: options.mode, authentication: options.authentication } : {}),
    })
    if (revision !== generation.revision) return
    if (snapshot !== generationSnapshot()) { generation.status = '表单已变更，已丢弃过期生成结果。请重新生成。'; return }
    const required = { reality: ['private_key', 'public_key', 'short_id'], short_id: ['short_id'], vless: ['decryption', 'encryption'], hysteria2: ['password'], certificate: ['cert_pem', 'key_pem', 'ca_pem', 'expires_at'] }[kind]
    if (!result || required.some(field => typeof result[field] !== 'string' || !result[field])) throw new Error('invalid response')
    if (kind === 'reality') { draft.privateKey = result.private_key!; draft.shortIDs = result.short_id! }
    if (kind === 'short_id') draft.shortIDs = result.short_id!
    if (kind === 'vless') draft.enc = result.decryption!
    if (kind === 'hysteria2') draft.password = result.password!
    if (kind === 'certificate') {
      for (const field of ['cert', 'key', 'ca'] as const) {
        const value = result[`${field}_pem`]!
        if (validatePEM(value, field)) throw new Error('invalid PEM')
      }
      for (const field of ['cert', 'key', 'ca'] as const) { clearUpload(field); draft[field] = result[`${field}_pem`]! }
    }
    generation.status = '已生成服务端参数，尚未保存；保存后自动派生客户端配置。'
  } catch {
    if (revision === generation.revision) generation.error = '生成失败，请检查参数、登录状态及生成接口后重试。现有配置未保存。'
  } finally { if (revision === generation.revision) generation.busy = '' }
}
function open(node?: Node) {
  clearSecrets()
  original = structuredClone(node?.tunnel ? JSON.parse(JSON.stringify(node.tunnel)) : {})
  const t = original
  const listenPort = String(t.listen_port || node?.port || 443)
  const savedEndpoints = node?.connect_endpoints?.length ? node.connect_endpoints : node?.address ? [{ id: 'primary', name: '首选地址', host: node.address, port: node.port || 443, enabled: true }] : []
  endpoints.splice(0, endpoints.length, ...savedEndpoints.map(endpoint => ({ ...endpoint })))
  endpointPortAuto = !node && !savedEndpoints.length
  endpointPortDefault = listenPort
  Object.assign(draft, {
    id: node?.id || '', name: node?.name || (props.defaultName || '1'), address: node?.address || '', port: String(node?.port || 443), listenPort,
    protocol: t.protocol || (t.hysteria2?.password ? 'hysteria2' : 'vless'),
    transport: t.protocol === 'hysteria2' || (!t.protocol && t.hysteria2?.password) ? 'quic' : t.xhttp?.path ? 'xhttp' : 'tcp',
    security: t.protocol === 'hysteria2' || t.hysteria2?.password ? 'tls' : t.reality && Object.values(t.reality).some(Boolean) ? 'reality' : t.transport_security === 'plain' ? 'encryption' : 'tls',
    flow: t.flow || '', enc: t.decryption || '', cert: t.cert_pem || '', key: t.key_pem || '', ca: t.ca_pem || '', listen: node ? (t.listen_host || '') : '0.0.0.0',
    dest: t.reality?.dest || '', privateKey: t.reality?.private_key || '',
    shortIDs: t.reality?.short_ids || '', names: t.reality?.server_names || '', password: t.hysteria2?.password || '',
    xhttpPath: t.xhttp?.path || '/veilink/', xhttpTLS: t.xhttp?.tls ?? true,
  })
  if (!endpoints.length && server.value) addEndpoint()
  if (!flowAllowed.value) draft.flow = ''
  modal.value?.open()
}
async function save() {
  if (reading.value) throw new Error('请等待 PEM 文件读取完成。')
  if (generation.busy) throw new Error('请等待生成完成。')
  const primary = endpoints.find(endpoint => endpoint.enabled) || endpoints[0]
  if (server.value && primary && !primary.host.trim() && draft.address.trim()) {
    primary.host = draft.address.trim(); primary.port = Number(draft.port)
  }
  const problem = validateNode({ ...draft, address: primary?.host || '', port: String(primary?.port || ''), role: props.role })
  if (uploadError.value) throw new Error(uploadError.value)
  if (problem) throw new Error(problem)
  if (server.value) {
    if (!endpoints.length || !endpoints.some(endpoint => endpoint.enabled)) throw new Error('至少启用一个客户端连接地址。')
    for (const endpoint of endpoints) {
      if (!endpoint.name?.trim() || !endpoint.host?.trim() || Number(endpoint.port) < 1 || Number(endpoint.port) > 65535) throw new Error('连接地址需要名称、主机/域名和端口。')
    }
  }
  const tunnel: TunnelConfig = {}
  if (server.value) {
    tunnel.protocol = draft.protocol
    tunnel.transport_security = draft.protocol === 'hysteria2' || draft.security === 'reality' ? '' : draft.security === 'tls' ? 'tls' : 'plain'
    if (draft.protocol === 'hysteria2') {
      if (!draft.password.trim()) throw new Error('请输入 Hysteria2 密码。')
      tunnel.hysteria2 = { password: draft.password.trim() }
      tunnel.cert_pem = draft.cert.trim(); tunnel.key_pem = draft.key.trim()
      if (draft.ca.trim()) tunnel.ca_pem = draft.ca.trim()
    } else if (draft.transport === 'xhttp') {
      const path = draft.xhttpPath.trim()
      if (path.length > 256 || !/^\/[A-Za-z0-9/_-]*\/$/.test(path) && path !== '/' || path.includes('//')) throw new Error('XHTTP 路径须以 / 开头和结尾，仅含字母、数字、/、_、-，最多 256 字节。')
      if (draft.security === 'reality' && draft.xhttpTLS) throw new Error('XHTTP + REALITY 时必须关闭连接 HTTPS；REALITY 已提供外层安全。')
      if (draft.security !== 'reality' && (draft.security === 'encryption' || !draft.xhttpTLS) && (!draft.enc.trim() || draft.enc.trim() === 'none')) throw new Error('XHTTP 使用 HTTP 时必须启用 VLESS Encryption。')
      tunnel.xhttp = { path, mode: 'packet-up', tls: draft.xhttpTLS }
      if (draft.xhttpTLS && draft.ca.trim()) {
        const problem = validatePEM(draft.ca, 'ca')
        if (problem) throw new Error(problem)
        tunnel.ca_pem = draft.ca.trim()
      }
    }
    if (draft.protocol === 'vless' && (draft.transport === 'tcp' || draft.transport === 'xhttp') && draft.security === 'tls') {
      tunnel.cert_pem = draft.cert.trim(); tunnel.key_pem = draft.key.trim()
      if (draft.ca.trim()) tunnel.ca_pem = draft.ca.trim()
    } else if (draft.protocol === 'vless' && draft.security === 'reality') {
      tunnel.reality = { ...original.reality, dest: draft.dest.trim(), private_key: draft.privateKey.trim(), short_ids: draft.shortIDs.trim(), server_names: draft.names.trim() }
      delete tunnel.reality.public_key
    }
    if (draft.protocol === 'vless' && draft.transport === 'tcp' && draft.security === 'encryption' && (!draft.enc.trim() || draft.enc.trim() === 'none')) throw new Error('plain 无 TLS：请输入 VLESS 解密配置，或点击生成配对配置；不能使用 none。')
    if (draft.protocol === 'vless' && draft.enc.trim() && draft.enc.trim() !== 'none') tunnel.decryption = draft.enc.trim()
    if (flowAllowed.value && draft.flow) tunnel.flow = draft.flow
    if (draft.listen.trim()) tunnel.listen_host = draft.listen.trim()
    tunnel.listen_port = Number(draft.listenPort)
  }
  await api(draft.id ? `/nodes/${encodeURIComponent(draft.id)}` : '/nodes', draft.id ? 'PUT' : 'POST', {
    name: draft.name.trim(), role: props.role, address: server.value ? primary?.host.trim() : '', port: server.value ? Number(primary?.port) : 0,
    ...(server.value ? { connect_endpoints: endpoints.map(endpoint => ({ id: endpoint.id, name: endpoint.name.trim(), host: endpoint.host.trim(), port: Number(endpoint.port), enabled: endpoint.enabled })), tunnel } : {}),
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
      <p class="help">客户端配置由已保存的服务端配置自动派生，创建或关联映射后统一下发，无需单独编辑。</p>
      <section :key="session" aria-label="服务端配置">
        <h3>本地绑定</h3>
        <div class="grid-2">
          <div><label for="node-listen">监听地址（IP）</label><input id="node-listen" v-model="draft.listen" placeholder="默认 0.0.0.0；仅本机监听可填 127.0.0.1" /></div>
          <div><label for="node-listen-port">监听端口</label><input id="node-listen-port" v-model="draft.listenPort" type="number" min="1" max="65535" required /></div>
        </div>
        <small class="help">Server 只绑定这里的 IP、端口和传输网络；与客户端连接地址分离。</small>
        <h3>客户端连接地址</h3>
        <small class="help">这里填写 Client 拨号使用的可达主机（域名或 IP）与端口，可与 Server 本地绑定地址不同。TLS 证书须覆盖该域名或 IP；REALITY 使用伪装域名。多候选按列表顺序失败切换。</small>
        <div v-for="(endpoint, index) in endpoints" :key="endpoint.id" class="panel paired-fields">
          <div><label :for="`endpoint-${index}-name`">名称</label><input :id="`endpoint-${index}-name`" v-model="endpoint.name" /></div>
          <div class="grid-2"><div><label :for="`endpoint-${index}-host`">主机/域名</label><input :id="`endpoint-${index}-host`" v-model="endpoint.host" placeholder="默认 127.0.0.1" /></div><div><label :for="`endpoint-${index}-port`">端口</label><input :id="`endpoint-${index}-port`" v-model="endpoint.port" type="number" min="1" max="65535" @input="markEndpointPortEdited(index)" /></div></div>
          <div class="actions"><label :for="`endpoint-${index}-enabled`"><input :id="`endpoint-${index}-enabled`" v-model="endpoint.enabled" type="checkbox" /> 启用</label><button type="button" class="btn small danger" :disabled="endpoints.length === 1" @click="removeEndpoint(index)">删除</button></div>
        </div>
        <button type="button" class="btn small" @click="addEndpoint()">添加连接地址</button>
        <small class="warning">TCP / Hysteria2 须 L4 透传；XHTTP packet-up 可走 HTTP/HTTPS CDN，允许边缘终止 TLS，但须路径透传、禁用缓存、流式下行及足够的超时。不保证任意公网 CDN 可用。</small>
        <div class="grid-2">
          <div><label for="node-protocol">协议</label><select id="node-protocol" v-model="draft.protocol"><option value="vless">VLESS</option><option value="hysteria2">Hysteria2</option></select></div>
          <div><label for="node-security">{{ draft.protocol === 'vless' && draft.transport === 'xhttp' ? 'Server 回源监听安全' : '安全' }}</label><select id="node-security" :value="draft.protocol === 'hysteria2' ? 'tls' : draft.security" :disabled="draft.protocol === 'hysteria2'" @change="draft.security = ($event.target as HTMLSelectElement).value"><option value="tls">TLS</option><option v-if="draft.protocol === 'vless'" value="reality">REALITY</option><option v-if="draft.protocol === 'vless'" value="encryption">Encryption（无 TLS）</option></select></div>
        </div>
        <div><label for="node-transport">传输</label><select id="node-transport" v-model="draft.transport" :disabled="draft.protocol === 'hysteria2'"><option value="tcp">TCP</option><option v-if="draft.protocol === 'vless'" value="xhttp">XHTTP</option><option v-if="draft.protocol === 'hysteria2'" value="quic">QUIC</option></select></div>
        <template v-if="draft.protocol === 'vless' && draft.transport === 'xhttp'">
          <label for="node-xhttp-path">XHTTP 路径（packet-up）</label><input id="node-xhttp-path" v-model="draft.xhttpPath" maxlength="256" placeholder="/veilink/" required />
          <label for="node-xhttp-tls"><input id="node-xhttp-tls" v-model="draft.xhttpTLS" type="checkbox" :disabled="draft.security === 'reality'" /> Client 连接地址使用 HTTPS</label>
          <small class="help">仅 HTTP/1.1 packet-up；POST 分片上行、GET 流式下行。REALITY 模式须关闭此处 HTTPS，不能走 CDN 边缘终止 TLS。普通 XHTTP 可使用 HTTPS 边缘/回源；任一段使用 HTTP 时须启用 VLESS Encryption。</small>
        </template>
        <small v-if="draft.protocol === 'hysteria2'" class="help">Hysteria2 使用 QUIC/UDP + TLS，当前实现不支持 REALITY。</small>
        <small v-if="draft.protocol === 'hysteria2'" class="help">请放行监听端口的 UDP 并核对 NAT 的 UDP 转发；生成密码后保存，客户端密码须一致。证书须覆盖连接地址且受下发 CA 信任；不能启用 Vision。</small>
        <small v-else-if="draft.security === 'tls'" class="help">TLS 使用 TCP：上传配对证书与私钥。直连时证书须覆盖连接地址；XHTTP 经 CDN 时由 CDN 校验源站证书，Client 校验边缘证书。不要关闭证书校验。</small>
        <small v-else-if="draft.security === 'reality'" class="help">REALITY 使用 TCP：填写可达的回落目标与允许的伪装域名，生成密钥对和 Short ID。客户端公钥、Short ID 与域名须匹配；不要同时填写 TLS PEM。</small>
        <small v-else class="help">plain 使用 TCP 且没有外层 TLS，必须启用 VLESS Encryption；不接受证书 PEM、REALITY、Hysteria2 或 Vision。请生成配对配置后保存，而非填 none。</small>
        <template v-if="pemFields.includes('cert')">
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
        <SecretField v-if="draft.protocol === 'hysteria2'" id="node-hy-password" v-model="draft.password" label="Hysteria2 密码" required><button type="button" class="btn small" :disabled="!!generation.busy || reading" @click="generate('hysteria2')">生成密码</button></SecretField>
        <template v-else-if="draft.security === 'reality'">
          <label for="node-dest">回落目标</label><input id="node-dest" v-model="draft.dest" placeholder="example.com:443" />
          <SecretField id="node-private" v-model="draft.privateKey" label="REALITY 私钥"><button type="button" class="btn small" :disabled="!!generation.busy || reading" @click="generate('reality')">生成密钥对</button></SecretField>
          <label for="node-names">伪装域名</label><input id="node-names" v-model="draft.names" placeholder="逗号分隔" />
          <label for="node-short">Short IDs</label><div class="field-actions"><input id="node-short" v-model="draft.shortIDs" placeholder="逗号分隔" /><button type="button" class="btn small" :disabled="!!generation.busy || reading" @click="generate('short_id')">生成 Short ID</button></div>
        </template>
        <template v-if="draft.protocol === 'vless'">
          <SecretField id="node-encryption" v-model="draft.enc" label="VLESS 解密配置" :required="draft.security === 'encryption' || draft.transport === 'xhttp' && !draft.xhttpTLS"><button type="button" class="btn small" :disabled="!!generation.busy || reading" @click="generate('vless')">生成配对配置</button></SecretField>
          <small class="help">VLESS Encryption：服务端保存 decryption，客户端只接收配对 encryption，不能互换。TLS、REALITY 下可选，plain 下必填；重新生成后须保存并等待双方应用新修订。</small>
          <div class="grid-2"><div><label for="vless-mode">生成模式</label><select id="vless-mode" v-model="options.mode"><option v-for="mode in ['native', 'xorpub', 'random']" :key="mode">{{ mode }}</option></select></div><div><label for="vless-auth">认证算法</label><select id="vless-auth" v-model="options.authentication"><option>x25519</option><option>mlkem768</option></select></div></div>
          <template v-if="flowAllowed"><label for="node-flow">Flow</label><select id="node-flow" v-model="draft.flow"><option value="">无</option><option>xtls-rprx-vision</option></select></template>
          <small class="help">Vision 仅用于 VLESS TCP + TLS/REALITY。只有独立已认证连接内、满足结构和记录边界的 TLS 1.3 才直拷；启用 Encryption 或无法安全识别时保留加密回退，mux、控制与 UDP 不裸传。</small>
        </template>
      </section>
      <p v-if="generation.busy || generation.status" class="help" role="status">{{ generation.busy ? '正在生成… 保存将在生成完成后可用。' : generation.status }}</p>
      <p v-if="generation.error" class="error" role="alert">{{ generation.error }}</p>
    </template>
  </Modal>
</template>
