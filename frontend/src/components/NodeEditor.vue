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
const draft = reactive({ id: '', name: '', address: '', port: '443', listenPort: '443', protocol: 'vless' as 'vless' | 'hysteria2', transport: 'tcp' as 'tcp' | 'xhttp' | 'quic' | 'hysteria2', security: 'tls', flow: '', enc: '', cert: '', key: '', ca: '', listen: '', dest: '', privateKey: '', shortIDs: '', names: '', password: '', spiderX: '', spiderY: '', mldsa65Verify: '', xhttpPath: '/veilink/', xhttpDownloadEndpoint: '', xhttpHost: '', xhttpHeaders: '', xhttpMode: 'packet-up' as 'packet-up' | 'stream-up' | 'stream-one' | 'auto', xhttpVersion: '' as '' | '1.1' | '2' | '3', xhttpTLS: true, xhttpPostBytes: 32768, xhttpPostBytesMax: 0, xhttpPostInterval: 0, xhttpPostIntervalMax: 0, xhttpMaxBufferedPosts: 0, xhttpMaxConcurrentPosts: 0, xhttpDataPlacement: 'body' as 'body' | 'header' | 'cookie', xhttpDataKey: '', xhttpChunkSize: 0, xhttpMuxConcurrency: 0, xhttpMuxConnections: 0, xhttpMuxReuse: 0, xhttpMuxRequests: 0, xhttpMuxSeconds: 0, xhttpMuxKeepAlive: 0, xhttpTimeout: 15, xhttpPadding: 100, xhttpPaddingMax: 1000, xhttpPaddingObfs: false, xhttpPaddingPlacement: 'query_in_header' as 'query_in_header' | 'query' | 'header' | 'cookie', xhttpPaddingKey: 'x_padding', xhttpPaddingHeader: 'Referer', xhttpPaddingMethod: 'repeat-x' as 'repeat-x' | 'tokenish', xhttpNoGRPCHeader: false, xhttpNoSSEHeader: false, xhttpMaxHeaderBytes: 8192, xhttpUplinkMethod: 'POST' as 'POST' | 'PUT', xhttpSessionPlacement: 'path' as MetaPlacement, xhttpSessionKey: '', xhttpSeqPlacement: 'path' as MetaPlacement, xhttpSeqKey: '', xhttpSessionTable: '', xhttpSessionLength: 0 })
const streamUpPeriod = reactive({ min: '' as number | '', max: '' as number | '' })
type MetaPlacement = 'path' | 'query' | 'header' | 'cookie'
type MetaField = 'session' | 'seq'
function setMetaPlacement(field: MetaField, placement: MetaPlacement) {
  if (field === 'session') { draft.xhttpSessionPlacement = placement; draft.xhttpSessionKey = '' }
  else { draft.xhttpSeqPlacement = placement; draft.xhttpSeqKey = '' }
}
const sessionTableKind = computed(() => ['','hex','base62'].includes(draft.xhttpSessionTable) ? draft.xhttpSessionTable : 'custom')
function setSessionTable(kind: string) {
  draft.xhttpSessionTable = kind === 'custom' ? '0123456789ABCDEFGHIJKLMNOPQRSTUV' : kind
  draft.xhttpSessionLength = kind ? 32 : 0
}
function xhttpMetaFields(): Partial<NonNullable<TunnelConfig['xhttp']>> {
  const fields: Partial<NonNullable<TunnelConfig['xhttp']>> = {}
  if (draft.xhttpMode === 'stream-one') return fields
  const check = (placement: MetaPlacement, key: string, label: string) => {
    if (!['path', 'query', 'header', 'cookie'].includes(placement)) throw new Error(`${label}位置无效。`)
    if (placement === 'path' && key) throw new Error(`${label}路径位置不能填写键名。`)
    if (placement === 'query' && key && (!/^[a-z0-9_]{1,40}$/.test(key) || key === 'x_padding')) throw new Error(`${label}查询键名须为 1–40 位小写字母、数字或下划线，且不能为 x_padding。`)
    if (placement === 'cookie' && key && (!/^x_[a-z0-9_]{1,38}$/.test(key) || key.length > 40 || key === 'x_padding')) throw new Error(`${label}Cookie 键名须以 x_ 开头，最多 40 位小写字母、数字或下划线。`)
    if (placement === 'header' && key && (!/^X-Veilink-[A-Za-z0-9-]+$/.test(key) || key.length > 48 || /^X-Veilink-(EOF|Upload-Complete)$/i.test(key))) throw new Error(`${label}请求头键名须以 X-Veilink- 开头，最多 48 位且不能使用保留名称。`)
  }
  check(draft.xhttpSessionPlacement, draft.xhttpSessionKey, '会话 ID')
  if (draft.xhttpSessionPlacement !== 'path') fields.session_id_placement = draft.xhttpSessionPlacement
  if (draft.xhttpSessionKey) fields.session_id_key = draft.xhttpSessionKey
  if (['packet-up', 'auto'].includes(draft.xhttpMode)) {
    check(draft.xhttpSeqPlacement, draft.xhttpSeqKey, '序号')
    if (draft.xhttpSeqPlacement !== 'path') fields.seq_placement = draft.xhttpSeqPlacement
    if (draft.xhttpSeqKey) fields.seq_key = draft.xhttpSeqKey
    if (draft.xhttpSessionPlacement === draft.xhttpSeqPlacement && draft.xhttpSessionPlacement !== 'path') {
      const sessionKey = draft.xhttpSessionKey || (draft.xhttpSessionPlacement === 'header' ? 'X-Veilink-Session' : 'x_session')
      const seqKey = draft.xhttpSeqKey || (draft.xhttpSeqPlacement === 'header' ? 'X-Veilink-Seq' : 'x_seq')
      if (sessionKey.toLowerCase() === seqKey.toLowerCase()) throw new Error('会话 ID 与序号在相同位置不能使用同一个键名。')
    }
  }
  const table = draft.xhttpSessionTable
  const length = draft.xhttpSessionLength
  if (table || length) {
    if (!table || !Number.isInteger(length) || length < 24 || length > 64) throw new Error('会话 ID 自定义字符表需配合 24–64 位长度。')
    const chars = table === 'hex' ? '0123456789abcdef' : table === 'base62' ? '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' : table
    if (chars.length < 16 || chars.length > 64 || !/^[A-Za-z0-9_-]+$/.test(chars) || new Set(chars).size !== chars.length) throw new Error('会话 ID 字符表须为 16–64 个互异的 URL 安全 ASCII 字符。')
    if (length * Math.log2(chars.length) < 128) throw new Error('会话 ID 长度与字符表须提供至少 128 位熵。')
    fields.session_id_table = table
    fields.session_id_length = length
  }
  return fields
}
function setPaddingPlacement(placement: typeof draft.xhttpPaddingPlacement) {
  draft.xhttpPaddingPlacement = placement
  draft.xhttpPaddingKey = 'x_padding'
  draft.xhttpPaddingHeader = placement === 'query_in_header' ? 'Referer' : 'X-Padding'
}
function xhttpPaddingFields(): Partial<NonNullable<TunnelConfig['xhttp']>> {
  if (!draft.xhttpPaddingObfs) return {}
  const placement = draft.xhttpPaddingPlacement
  const key = draft.xhttpPaddingKey
  const header = draft.xhttpPaddingHeader
  if (!['query_in_header', 'query', 'header', 'cookie'].includes(placement)) throw new Error('XHTTP 填充位置无效。')
  if (!['repeat-x', 'tokenish'].includes(draft.xhttpPaddingMethod)) throw new Error('XHTTP 填充方法无效。')
  if (placement === 'query' || placement === 'query_in_header') {
    if (!/^[a-z0-9_]{1,40}$/.test(key)) throw new Error('XHTTP 填充查询键名无效。')
  }
  if (placement === 'cookie' && !/^x_[a-z0-9_]{1,38}$/.test(key)) throw new Error('XHTTP 填充 Cookie 键名须为私有 x_ 名称。')
  if (placement === 'header' || placement === 'query_in_header') {
    if (header !== 'Referer' && header !== 'X-Padding' && (!/^X-Custom-[A-Za-z0-9-]+$/.test(header) || header.length > 48)) throw new Error('XHTTP 填充请求头名无效。')
    if (placement === 'header' && header === 'Referer') throw new Error('XHTTP 请求头填充不能覆盖 Referer。')
  }
  const sessionKey = draft.xhttpSessionKey || (draft.xhttpSessionPlacement === 'header' ? 'X-Veilink-Session' : 'x_session')
  const seqKey = draft.xhttpSeqKey || (draft.xhttpSeqPlacement === 'header' ? 'X-Veilink-Seq' : 'x_seq')
  for (const [position, configured] of [[draft.xhttpSessionPlacement, sessionKey], ...(['packet-up', 'auto'].includes(draft.xhttpMode) ? [[draft.xhttpSeqPlacement, seqKey]] : [])]) {
    if (position === placement && (placement === 'cookie' || placement === 'query') && configured === key) throw new Error('XHTTP 填充键名不能覆盖会话或序号。')
    if (position === 'header' && (placement === 'header' || placement === 'query_in_header') && configured.toLowerCase() === header.toLowerCase()) throw new Error('XHTTP 填充请求头不能覆盖会话或序号。')
  }
  return { padding_obfs_mode: true, padding_placement: placement, ...(placement === 'header' ? {} : { padding_key: key }), ...((placement === 'header' || placement === 'query_in_header') ? { padding_header: header } : {}), padding_method: draft.xhttpPaddingMethod }
}
const xhttpHeadersError = ref('')
// Read the object token by token: JSON.parse alone silently discards duplicate keys.
function parseXHTTPHeaders(text: string): Record<string, string> | undefined {
  if (!text.trim()) return undefined
  const fail = (message: string): never => { throw new Error(`XHTTP 请求头：${message}`) }
  if (new TextEncoder().encode(text).length > 2048) fail('JSON 对象不能超过 2048 字节。')
  let position = 0
  const space = () => { while (position < text.length && /[ \t\r\n]/.test(text[position])) position++ }
  const stringToken = /"(?:\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4})|[^"\\\u0000-\u001f])*"/y
  const readString = (): string => {
    stringToken.lastIndex = position
    const match = stringToken.exec(text)
    if (!match) return fail('须为字符串键和字符串值的 JSON 对象。')
    position = stringToken.lastIndex
    return JSON.parse(match[0]) as string
  }
  space()
  if (text[position++] !== '{') fail('须为 JSON 对象。')
  const headers: Record<string, string> = Object.create(null)
  const seen = new Set<string>()
  space()
  if (text[position] === '}') { position++; space(); if (position !== text.length) fail('JSON 对象后不能有额外内容。'); return undefined }
  while (position < text.length) {
    space()
    const name = readString()
    const lower = name.toLowerCase()
    if (name.length > 64 || !(/^(user-agent|accept-language)$/.test(lower) || /^x-custom-[a-z0-9-]+$/.test(lower))) fail(`不允许请求头 ${name}。`)
    if (seen.has(lower)) fail(`请求头 ${name} 重复。`)
    seen.add(lower)
    if (seen.size > 8) fail('最多 8 个字段。')
    space()
    if (text[position++] !== ':') fail('JSON 对象缺少冒号。')
    space()
    const value = readString()
    const bytes = new TextEncoder().encode(value).length
    if (bytes < 1 || bytes > 256 || value.trim() !== value || /\p{Cc}/u.test(value) || /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)) fail(`请求头 ${name} 的值无效。`)
    const canonical = lower.replace(/(^|-)[a-z]/g, part => part.toUpperCase())
    headers[canonical] = value
    space()
    const delimiter = text[position++]
    if (delimiter === '}') {
      space()
      if (position !== text.length) fail('JSON 对象后不能有额外内容。')
      const sorted = Object.fromEntries(Object.entries(headers).sort(([a], [b]) => a.localeCompare(b)))
      if (new TextEncoder().encode(JSON.stringify(sorted)).length > 2048) fail('JSON 对象不能超过 2048 字节。')
      return sorted
    }
    if (delimiter !== ',') fail('JSON 对象格式无效。')
    space()
    if (text[position] === '}') fail('JSON 对象不能有尾随逗号。')
  }
  return fail('JSON 对象未闭合。')
}
const endpoints = reactive<ConnectEndpoint[]>([])
const downloadEndpoints = computed(() => endpoints.filter(endpoint => endpoint.enabled))
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
type GenerateKind = 'reality' | 'short_id' | 'mldsa65' | 'vless' | 'hysteria2' | 'certificate'
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
function generationSnapshot() { return JSON.stringify([draft, endpoints, options, uploads, streamUpPeriod]) }
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
    const required = { reality: ['private_key', 'public_key', 'short_id'], short_id: ['short_id'], mldsa65: ['private_key', 'public_key'], vless: ['decryption', 'encryption'], hysteria2: ['password'], certificate: ['cert_pem', 'key_pem', 'ca_pem', 'expires_at'] }[kind]
    if (!result || required.some(field => typeof result[field] !== 'string' || !result[field])) throw new Error('invalid response')
    if (kind === 'reality') { draft.privateKey = result.private_key!; draft.shortIDs = result.short_id! }
    if (kind === 'short_id') draft.shortIDs = result.short_id!
    if (kind === 'mldsa65') draft.mldsa65Verify = result.public_key!
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
    shortIDs: t.reality?.short_ids || '', names: t.reality?.server_names || '', spiderX: t.reality?.spider_x || '', spiderY: t.reality?.spider_y || '', mldsa65Verify: t.reality?.mldsa65_verify || '', password: t.hysteria2?.password || '',
    xhttpPath: t.xhttp?.path || '/veilink/', xhttpDownloadEndpoint: t.xhttp?.download_endpoint_id || '', xhttpHost: t.xhttp?.host || '', xhttpHeaders: t.xhttp?.headers ? JSON.stringify(t.xhttp.headers) : '', xhttpMode: t.xhttp?.mode || 'packet-up', xhttpVersion: t.xhttp?.http_version || '', xhttpTLS: t.xhttp?.tls ?? true, xhttpPostBytes: t.xhttp?.max_each_post_bytes || 32768, xhttpPostBytesMax: t.xhttp?.post_bytes_max || 0, xhttpPostInterval: t.xhttp?.min_posts_interval_ms || 0, xhttpPostIntervalMax: t.xhttp?.max_posts_interval_ms || 0, xhttpTimeout: t.xhttp?.request_timeout_seconds || 15, xhttpPadding: t.xhttp?.padding_bytes || 100, xhttpPaddingMax: t.xhttp?.padding_max_bytes || (t.xhttp ? (t.xhttp.padding_bytes || 100) : 1000), xhttpPaddingObfs: t.xhttp?.padding_obfs_mode || false, xhttpPaddingPlacement: t.xhttp?.padding_placement || 'query_in_header', xhttpPaddingKey: t.xhttp?.padding_key || 'x_padding', xhttpPaddingHeader: t.xhttp?.padding_header || (t.xhttp?.padding_placement === 'header' ? 'X-Padding' : 'Referer'), xhttpPaddingMethod: t.xhttp?.padding_method || 'repeat-x', xhttpNoGRPCHeader: t.xhttp?.no_grpc_header || false, xhttpNoSSEHeader: t.xhttp?.no_sse_header || false, xhttpMaxHeaderBytes: t.xhttp?.server_max_header_bytes || 8192, xhttpUplinkMethod: t.xhttp?.uplink_http_method || 'POST', xhttpSessionPlacement: t.xhttp?.session_id_placement || 'path', xhttpSessionKey: t.xhttp?.session_id_key || '', xhttpSeqPlacement: t.xhttp?.seq_placement || 'path', xhttpSeqKey: t.xhttp?.seq_key || '', xhttpSessionTable: t.xhttp?.session_id_table || '', xhttpSessionLength: t.xhttp?.session_id_length || 0,
  })
  draft.xhttpMaxBufferedPosts = t.xhttp?.max_buffered_posts ?? 0
  draft.xhttpMaxConcurrentPosts = t.xhttp?.max_concurrent_posts ?? 0
  draft.xhttpDataPlacement = t.xhttp?.uplink_data_placement || 'body'
  draft.xhttpDataKey = t.xhttp?.uplink_data_key || ''
  draft.xhttpChunkSize = t.xhttp?.uplink_chunk_size || 0
  draft.xhttpMuxConcurrency = t.xhttp?.xmux?.max_concurrency || 0; draft.xhttpMuxConnections = t.xhttp?.xmux?.max_connections || 0; draft.xhttpMuxReuse = t.xhttp?.xmux?.c_max_reuse_times || 0; draft.xhttpMuxRequests = t.xhttp?.xmux?.h_max_request_times || 0; draft.xhttpMuxSeconds = t.xhttp?.xmux?.h_max_reusable_secs || 0; draft.xhttpMuxKeepAlive = t.xhttp?.xmux?.keep_alive_period || 0
  streamUpPeriod.min = t.xhttp?.stream_up_server_secs || ''
  streamUpPeriod.max = t.xhttp?.stream_up_server_max_secs || ''
  xhttpHeadersError.value = ''
  if (!endpoints.length && server.value) addEndpoint()
  if (!flowAllowed.value) draft.flow = ''
  modal.value?.open()
}
function checkXHTTPHeaders(): Record<string, string> | undefined {
  xhttpHeadersError.value = ''
  try { return parseXHTTPHeaders(draft.xhttpHeaders) }
  catch (error) { xhttpHeadersError.value = (error as Error).message; throw error }
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
      const httpHost = draft.xhttpHost.trim()
      if (httpHost && (httpHost.length > 253 || !httpHost.includes('.') || httpHost.split('.').some(label => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-') || !/^[a-z0-9-]+$/.test(label)))) throw new Error('XHTTP Host 须为小写域名或 IPv4，不含端口。')
      if (['packet-up', 'auto'].includes(draft.xhttpMode) && draft.xhttpDownloadEndpoint && !downloadEndpoints.value.some(endpoint => endpoint.id === draft.xhttpDownloadEndpoint)) throw new Error('请选择当前启用的 XHTTP 分离下行入口。')
      if (!['packet-up', 'stream-up', 'stream-one', 'auto'].includes(draft.xhttpMode)) throw new Error('XHTTP 模式仅支持 packet-up、stream-up、stream-one 或 auto。')
      if (!['', '1.1', '2', '3'].includes(draft.xhttpVersion)) throw new Error('XHTTP HTTP 版本无效。')
      if (['stream-up', 'stream-one'].includes(draft.xhttpMode) && draft.security !== 'reality' && (draft.security !== 'tls' || !draft.xhttpTLS || draft.xhttpVersion === '1.1')) throw new Error('XHTTP 流模式仅支持直连 HTTPS + TLS 回源的 HTTP/2 或 HTTP/3（或 REALITY）。')
      if (draft.xhttpVersion === '3' && (draft.security !== 'tls' || !draft.xhttpTLS)) throw new Error('XHTTP HTTP/3 仅支持直连 HTTPS + TLS 回源。')
      if (draft.xhttpVersion === '2' && !draft.xhttpTLS && (['stream-up', 'stream-one'].includes(draft.xhttpMode) || draft.security !== 'encryption')) throw new Error('XHTTP h2c 仅允许 packet-up、直连 HTTP 与 Encryption 回源；必须启用 VLESS Encryption。')
      if (draft.security === 'reality' && draft.xhttpTLS) throw new Error('XHTTP + REALITY 时必须关闭连接 HTTPS；REALITY 已提供外层安全。')
      if (draft.security !== 'reality' && (draft.security === 'encryption' || !draft.xhttpTLS) && (!draft.enc.trim() || draft.enc.trim() === 'none')) throw new Error('XHTTP 使用 HTTP 时必须启用 VLESS Encryption。')
      if (['packet-up', 'auto'].includes(draft.xhttpMode) && (!Number.isInteger(draft.xhttpPostBytes) || draft.xhttpPostBytes < 1024 || draft.xhttpPostBytes > 32768)) throw new Error('XHTTP 上行分片须为 1024–32768 字节。')
      if (['packet-up', 'auto'].includes(draft.xhttpMode) && (!Number.isInteger(draft.xhttpPostBytesMax) || draft.xhttpPostBytesMax < 0 || draft.xhttpPostBytesMax > 32768 || (draft.xhttpPostBytesMax > 0 && draft.xhttpPostBytesMax < draft.xhttpPostBytes))) throw new Error('XHTTP 分片最大值须为 0（固定）或介于最小值和 32768 字节之间。')
      if (['packet-up', 'auto'].includes(draft.xhttpMode) && (!Number.isInteger(draft.xhttpPostInterval) || draft.xhttpPostInterval < 0 || draft.xhttpPostInterval > 1000)) throw new Error('XHTTP 分片最小间隔须为 0–1000 毫秒。')
      if (['packet-up', 'auto'].includes(draft.xhttpMode) && (!Number.isInteger(draft.xhttpPostIntervalMax) || draft.xhttpPostIntervalMax < 0 || draft.xhttpPostIntervalMax > 1000 || (draft.xhttpPostIntervalMax > 0 && (draft.xhttpPostInterval === 0 || draft.xhttpPostIntervalMax < draft.xhttpPostInterval)))) throw new Error('XHTTP 分片最大间隔须为 0（固定）或介于最小间隔和 1000 毫秒之间。')
      if (['packet-up', 'auto'].includes(draft.xhttpMode) && (!Number.isInteger(draft.xhttpMaxBufferedPosts) || draft.xhttpMaxBufferedPosts < 0 || draft.xhttpMaxBufferedPosts > 32)) throw new Error('XHTTP 缓冲分片上限须为 0（默认）或 1–32 的整数。')
      if (['packet-up', 'auto'].includes(draft.xhttpMode) && (!Number.isInteger(draft.xhttpMaxConcurrentPosts) || draft.xhttpMaxConcurrentPosts < 0 || draft.xhttpMaxConcurrentPosts > 8)) throw new Error('XHTTP 并发上行上限须为 0（默认 1）或 1–8 的整数。')
      if (['packet-up', 'auto'].includes(draft.xhttpMode) && draft.xhttpMaxConcurrentPosts > draft.xhttpMaxBufferedPosts + 1) throw new Error('XHTTP 并发上行上限不能超过缓冲分片上限加 1。')
      if (['packet-up', 'auto', 'stream-up', 'stream-one'].includes(draft.xhttpMode)) {
        for (const value of [draft.xhttpMuxConcurrency, draft.xhttpMuxConnections, draft.xhttpMuxReuse, draft.xhttpMuxRequests, draft.xhttpMuxSeconds, draft.xhttpMuxKeepAlive]) if (!Number.isInteger(value) || value < 0) throw new Error('XHTTP xmux 参数须为非负整数。')
        if (draft.xhttpMuxConcurrency > 1024 || draft.xhttpMuxConnections > 128 || draft.xhttpMuxReuse > 100000 || draft.xhttpMuxRequests > 100000 || draft.xhttpMuxSeconds > 86400 || draft.xhttpMuxKeepAlive > 3600) throw new Error('XHTTP xmux 参数超出范围。')
      }
      if (['packet-up', 'auto'].includes(draft.xhttpMode)) {
        if (!['body', 'header', 'cookie'].includes(draft.xhttpDataPlacement)) throw new Error('XHTTP 上行数据位置无效。')
        if (draft.xhttpDataPlacement !== 'body' && draft.xhttpDataKey && (draft.xhttpDataPlacement === 'header' ? (!draft.xhttpDataKey.startsWith('X-Veilink-') || draft.xhttpDataKey.toLowerCase() === 'x-veilink-eof') : (!/^x_[a-z0-9_]+$/.test(draft.xhttpDataKey)))) throw new Error('XHTTP 上行数据键名无效。')
        if (!Number.isInteger(draft.xhttpChunkSize) || draft.xhttpChunkSize < 0 || draft.xhttpChunkSize > 8192 || (draft.xhttpChunkSize > 0 && draft.xhttpChunkSize < 64)) throw new Error('XHTTP 上行编码块须为 0 或 64–8192。')
        if (draft.xhttpDataPlacement === 'body' && (draft.xhttpDataKey || draft.xhttpChunkSize)) throw new Error('XHTTP body 位置不能配置数据键或编码块。')
      }
      const streamUpMin = streamUpPeriod.min === '' ? 0 : streamUpPeriod.min
      const streamUpMax = streamUpPeriod.max === '' ? 0 : streamUpPeriod.max
      if (draft.xhttpMode === 'stream-up') {
        if (!Number.isInteger(streamUpMin) || streamUpMin < 0 || streamUpMin > 300) throw new Error('XHTTP 填充周期须为空、0 或 1–300 秒的整数。')
        if (!Number.isInteger(streamUpMax) || streamUpMax < 0 || streamUpMax > 300 || (streamUpMax > 0 && (streamUpMin === 0 || streamUpMax < streamUpMin))) throw new Error('XHTTP 填充最大周期须为空、0 或介于已指定周期和 300 秒之间的整数。')
      }
      if (!Number.isInteger(draft.xhttpTimeout) || draft.xhttpTimeout < 5 || draft.xhttpTimeout > 60) throw new Error('XHTTP 请求超时须为 5–60 秒。')
      if (!Number.isInteger(draft.xhttpPadding) || draft.xhttpPadding < 1 || draft.xhttpPadding > 1000) throw new Error('XHTTP 填充最小值须为 1–1000 字节。')
      if (!Number.isInteger(draft.xhttpPaddingMax) || draft.xhttpPaddingMax < draft.xhttpPadding || draft.xhttpPaddingMax > 1000) throw new Error('XHTTP 填充最大值须不小于最小值且不超过 1000 字节。')
      if (!['POST', 'PUT'].includes(draft.xhttpUplinkMethod)) throw new Error('XHTTP 上行方法仅支持 POST 或 PUT。')
      if (!Number.isInteger(draft.xhttpMaxHeaderBytes) || draft.xhttpMaxHeaderBytes < 8192 || draft.xhttpMaxHeaderBytes > 32768) throw new Error('XHTTP 服务端请求头上限须为 8192–32768 字节。')
      const headers = checkXHTTPHeaders()
      tunnel.xhttp = { path, ...(draft.xhttpDownloadEndpoint ? { download_endpoint_id: draft.xhttpDownloadEndpoint } : {}), ...(httpHost ? { host: httpHost } : {}), ...(headers ? { headers } : {}), mode: draft.xhttpMode, tls: draft.xhttpTLS, ...(draft.xhttpVersion ? { http_version: draft.xhttpVersion } : {}), ...(['packet-up', 'auto'].includes(draft.xhttpMode) ? { max_each_post_bytes: draft.xhttpPostBytes, ...(draft.xhttpPostBytesMax ? { post_bytes_max: draft.xhttpPostBytesMax } : {}), ...(draft.xhttpPostInterval ? { min_posts_interval_ms: draft.xhttpPostInterval } : {}), ...(draft.xhttpPostIntervalMax ? { max_posts_interval_ms: draft.xhttpPostIntervalMax } : {}) } : {}), request_timeout_seconds: draft.xhttpTimeout, padding_bytes: draft.xhttpPadding, ...(draft.xhttpPaddingMax !== draft.xhttpPadding ? { padding_max_bytes: draft.xhttpPaddingMax } : {}), ...xhttpPaddingFields(), ...(['stream-up', 'stream-one'].includes(draft.xhttpMode) && draft.xhttpNoGRPCHeader ? { no_grpc_header: true } : {}), ...(draft.xhttpNoSSEHeader ? { no_sse_header: true } : {}), ...(draft.xhttpMaxHeaderBytes !== 8192 ? { server_max_header_bytes: draft.xhttpMaxHeaderBytes } : {}), ...(draft.xhttpUplinkMethod !== 'POST' ? { uplink_http_method: draft.xhttpUplinkMethod } : {}), ...xhttpMetaFields(), ...((draft.xhttpMode === 'packet-up' || draft.xhttpMode === 'auto') && draft.xhttpDataPlacement !== 'body' ? { uplink_data_placement: draft.xhttpDataPlacement, ...(draft.xhttpDataKey ? { uplink_data_key: draft.xhttpDataKey } : {}), ...(draft.xhttpChunkSize ? { uplink_chunk_size: draft.xhttpChunkSize } : {}) } : {}), ...((draft.xhttpMuxConcurrency || draft.xhttpMuxConnections || draft.xhttpMuxReuse || draft.xhttpMuxRequests || draft.xhttpMuxSeconds || draft.xhttpMuxKeepAlive) ? { xmux: { ...(draft.xhttpMuxConcurrency ? { max_concurrency: draft.xhttpMuxConcurrency } : {}), ...(draft.xhttpMuxConnections ? { max_connections: draft.xhttpMuxConnections } : {}), ...(draft.xhttpMuxReuse ? { c_max_reuse_times: draft.xhttpMuxReuse } : {}), ...(draft.xhttpMuxRequests ? { h_max_request_times: draft.xhttpMuxRequests } : {}), ...(draft.xhttpMuxSeconds ? { h_max_reusable_secs: draft.xhttpMuxSeconds } : {}), ...(draft.xhttpMuxKeepAlive ? { keep_alive_period: draft.xhttpMuxKeepAlive } : {}) } } : {}) }
      if (!['packet-up', 'auto'].includes(draft.xhttpMode)) delete tunnel.xhttp.download_endpoint_id
      if (['packet-up', 'auto'].includes(draft.xhttpMode)) {
        if (draft.xhttpMaxBufferedPosts) tunnel.xhttp.max_buffered_posts = draft.xhttpMaxBufferedPosts
        if (draft.xhttpMaxConcurrentPosts) tunnel.xhttp.max_concurrent_posts = draft.xhttpMaxConcurrentPosts
      }
      if (draft.xhttpMode === 'stream-up') {
        if (streamUpMin) tunnel.xhttp.stream_up_server_secs = streamUpMin
        if (streamUpMax) tunnel.xhttp.stream_up_server_max_secs = streamUpMax
      }
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
      tunnel.reality = { ...original.reality, dest: draft.dest.trim(), private_key: draft.privateKey.trim(), short_ids: draft.shortIDs.trim(), server_names: draft.names.trim(), ...(draft.spiderX.trim() ? { spider_x: draft.spiderX.trim() } : {}), ...(draft.spiderY.trim() ? { spider_y: draft.spiderY.trim() } : {}), ...(draft.mldsa65Verify.trim() ? { mldsa65_verify: draft.mldsa65Verify.trim() } : {}) }
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
        <small class="warning">TCP / Hysteria2 须 L4 透传；XHTTP packet-up 可走 HTTP/HTTPS CDN，允许边缘终止 TLS，但须路径透传、禁用缓存、流式下行及足够的超时。HTTP/3 需要 UDP 端口直连、HTTPS 和 TLS 回源；流模式须直连 HTTP/2 或 HTTP/3。不保证任意公网 CDN 可用。</small>
        <div class="grid-2">
          <div><label for="node-protocol">协议</label><select id="node-protocol" v-model="draft.protocol"><option value="vless">VLESS</option><option value="hysteria2">Hysteria2</option></select></div>
          <div><label for="node-security">{{ draft.protocol === 'vless' && draft.transport === 'xhttp' ? 'Server 回源监听安全' : '安全' }}</label><select id="node-security" :value="draft.protocol === 'hysteria2' ? 'tls' : draft.security" :disabled="draft.protocol === 'hysteria2'" @change="draft.security = ($event.target as HTMLSelectElement).value"><option value="tls">TLS</option><option v-if="draft.protocol === 'vless'" value="reality">REALITY</option><option v-if="draft.protocol === 'vless'" value="encryption">Encryption（无 TLS）</option></select></div>
        </div>
        <div><label for="node-transport">传输</label><select id="node-transport" v-model="draft.transport" :disabled="draft.protocol === 'hysteria2'"><option value="tcp">TCP</option><option v-if="draft.protocol === 'vless'" value="xhttp">XHTTP</option><option v-if="draft.protocol === 'hysteria2'" value="quic">QUIC</option></select></div>
        <template v-if="draft.protocol === 'vless' && draft.transport === 'xhttp'">
          <label for="node-xhttp-mode">XHTTP 模式</label><select id="node-xhttp-mode" v-model="draft.xhttpMode"><option value="packet-up">packet-up（默认）</option><option value="stream-up">stream-up</option><option value="stream-one">stream-one</option><option value="auto">auto（自动：REALITY→stream-one，否则 packet-up）</option></select>
          <label for="node-xhttp-version">HTTP 版本</label><select id="node-xhttp-version" v-model="draft.xhttpVersion"><option value="">默认协商</option><option v-if="['packet-up', 'auto'].includes(draft.xhttpMode)" value="1.1">HTTP/1.1</option><option value="2">HTTP/2（HTTPS 或加密 h2c）</option><option value="3">HTTP/3（UDP 直连）</option></select>
          <label for="node-xhttp-uplink-method">上行 HTTP 方法</label><select id="node-xhttp-uplink-method" v-model="draft.xhttpUplinkMethod"><option value="POST">POST（默认）</option><option value="PUT">PUT</option></select>
          <label for="node-xhttp-path">XHTTP 路径</label><input id="node-xhttp-path" v-model="draft.xhttpPath" maxlength="256" placeholder="/veilink/" required />
          <label for="node-xhttp-host">HTTP Host 覆写（可选）</label><input id="node-xhttp-host" v-model="draft.xhttpHost" maxlength="253" placeholder="edge.example.com" /><small class="help">仅改变 HTTP Host，Server 校验该值；连接地址和 TLS 证书验证名不变，前置代理须保留 Host。</small>
          <label for="node-xhttp-headers">请求头（JSON 对象，可选）</label><textarea id="node-xhttp-headers" v-model="draft.xhttpHeaders" class="mono" rows="4" :spellcheck="false" :aria-invalid="!!xhttpHeadersError" aria-describedby="node-xhttp-headers-error" placeholder='{"User-Agent":"Veilink","X-Custom-Route":"east"}' @input="xhttpHeadersError = ''" /><small v-if="xhttpHeadersError" id="node-xhttp-headers-error" class="detail-error" role="alert">{{ xhttpHeadersError }}</small>
          <template v-if="draft.xhttpMode !== 'stream-one'">
            <div class="grid-2">
              <div><label for="node-xhttp-session-placement">会话 ID 位置</label><select id="node-xhttp-session-placement" :value="draft.xhttpSessionPlacement" @change="setMetaPlacement('session', ($event.target as HTMLSelectElement).value as MetaPlacement)"><option value="path">路径（默认）</option><option value="query">查询参数</option><option value="header">请求头</option><option value="cookie">Cookie</option></select></div>
              <div v-if="draft.xhttpSessionPlacement !== 'path'"><label for="node-xhttp-session-key">会话 ID 键名</label><input id="node-xhttp-session-key" v-model="draft.xhttpSessionKey" :maxlength="draft.xhttpSessionPlacement === 'header' ? 48 : 40" :placeholder="draft.xhttpSessionPlacement === 'header' ? 'X-Veilink-Session（默认）' : 'x_session（默认）'" :spellcheck="false" /></div>
            </div>
            <div v-if="['packet-up', 'auto'].includes(draft.xhttpMode)" class="grid-2">
              <div><label for="node-xhttp-seq-placement">序号位置</label><select id="node-xhttp-seq-placement" :value="draft.xhttpSeqPlacement" @change="setMetaPlacement('seq', ($event.target as HTMLSelectElement).value as MetaPlacement)"><option value="path">路径（默认）</option><option value="query">查询参数</option><option value="header">请求头</option><option value="cookie">Cookie</option></select></div>
              <div v-if="draft.xhttpSeqPlacement !== 'path'"><label for="node-xhttp-seq-key">序号键名</label><input id="node-xhttp-seq-key" v-model="draft.xhttpSeqKey" :maxlength="draft.xhttpSeqPlacement === 'header' ? 48 : 40" :placeholder="draft.xhttpSeqPlacement === 'header' ? 'X-Veilink-Seq（默认）' : 'x_seq（默认）'" :spellcheck="false" /></div>
            </div>
            <div class="grid-2">
              <div><label for="node-xhttp-session-table-kind">会话 ID 字符表</label><select id="node-xhttp-session-table-kind" :value="sessionTableKind" @change="setSessionTable(($event.target as HTMLSelectElement).value)"><option value="">UUID（默认）</option><option value="hex">hex</option><option value="base62">base62</option><option value="custom">自定义</option></select></div>
              <div v-if="sessionTableKind"><label for="node-xhttp-session-length">会话 ID 长度</label><input id="node-xhttp-session-length" v-model.number="draft.xhttpSessionLength" type="number" min="24" max="64" step="1" required /></div>
            </div>
            <div v-if="sessionTableKind === 'custom'"><label for="node-xhttp-session-table">自定义字符表</label><input id="node-xhttp-session-table" v-model="draft.xhttpSessionTable" minlength="16" maxlength="64" :spellcheck="false" required /></div>
          </template>
          <div v-if="['packet-up', 'auto'].includes(draft.xhttpMode)"><label for="node-xhttp-download-endpoint">分离下行入口（可选）</label><select id="node-xhttp-download-endpoint" v-model="draft.xhttpDownloadEndpoint"><option value="">与上行相同</option><option v-for="endpoint in downloadEndpoints" :key="endpoint.id" :value="endpoint.id">{{ endpoint.name }} · {{ endpoint.host }}:{{ endpoint.port }}</option></select></div>
          <label for="node-xhttp-tls"><input id="node-xhttp-tls" v-model="draft.xhttpTLS" type="checkbox" :disabled="draft.security === 'reality'" /> Client 连接地址使用 HTTPS</label>
          <div class="grid-2"><div v-if="['packet-up', 'auto'].includes(draft.xhttpMode)"><label for="node-xhttp-post-bytes">上行分片（字节）</label><input id="node-xhttp-post-bytes" v-model.number="draft.xhttpPostBytes" type="number" min="1024" max="32768" step="1" required /></div><div><label for="node-xhttp-timeout">请求超时（秒）</label><input id="node-xhttp-timeout" v-model.number="draft.xhttpTimeout" type="number" min="5" max="60" step="1" required /></div><div><label for="node-xhttp-padding">填充最小值（字节）</label><input id="node-xhttp-padding" v-model.number="draft.xhttpPadding" type="number" min="1" max="1000" step="1" required /></div><div><label for="node-xhttp-padding-max">填充最大值（字节）</label><input id="node-xhttp-padding-max" v-model.number="draft.xhttpPaddingMax" type="number" min="1" max="1000" step="1" required /></div></div>
          <label for="node-xhttp-padding-obfs"><input id="node-xhttp-padding-obfs" v-model="draft.xhttpPaddingObfs" type="checkbox" /> 自定义填充位置与方法</label>
          <template v-if="draft.xhttpPaddingObfs">
            <div class="grid-2"><div><label for="node-xhttp-padding-placement">填充位置</label><select id="node-xhttp-padding-placement" :value="draft.xhttpPaddingPlacement" @change="setPaddingPlacement(($event.target as HTMLSelectElement).value as typeof draft.xhttpPaddingPlacement)"><option value="query_in_header">请求头内查询参数</option><option value="query">查询参数</option><option value="header">请求头</option><option value="cookie">Cookie</option></select></div><div><label for="node-xhttp-padding-method">填充方法</label><select id="node-xhttp-padding-method" v-model="draft.xhttpPaddingMethod"><option value="repeat-x">重复 X</option><option value="tokenish">随机字符</option></select></div></div>
            <div v-if="draft.xhttpPaddingPlacement !== 'header'"><label for="node-xhttp-padding-key">填充键名</label><input id="node-xhttp-padding-key" v-model="draft.xhttpPaddingKey" maxlength="40" :spellcheck="false" /></div>
            <div v-if="draft.xhttpPaddingPlacement === 'header' || draft.xhttpPaddingPlacement === 'query_in_header'"><label for="node-xhttp-padding-header">填充请求头</label><input id="node-xhttp-padding-header" v-model="draft.xhttpPaddingHeader" maxlength="48" :spellcheck="false" /></div>
          </template>
          <div v-if="['packet-up', 'auto'].includes(draft.xhttpMode)"><label for="node-xhttp-post-bytes-max">分片最大值（字节，0 为固定）</label><input id="node-xhttp-post-bytes-max" v-model.number="draft.xhttpPostBytesMax" type="number" min="0" max="32768" step="1" required /></div>
          <div v-if="['packet-up', 'auto'].includes(draft.xhttpMode)" class="grid-2"><div><label for="node-xhttp-post-interval">分片最小间隔（毫秒）</label><input id="node-xhttp-post-interval" v-model.number="draft.xhttpPostInterval" type="number" min="0" max="1000" step="1" required /></div><div><label for="node-xhttp-post-interval-max">最大间隔（毫秒，0 为固定）</label><input id="node-xhttp-post-interval-max" v-model.number="draft.xhttpPostIntervalMax" type="number" min="0" max="1000" step="1" required /></div></div>
          <div v-if="['packet-up', 'auto'].includes(draft.xhttpMode)" class="grid-2"><div><label for="node-xhttp-data-placement">上行数据位置</label><select id="node-xhttp-data-placement" v-model="draft.xhttpDataPlacement"><option value="body">body（默认）</option><option value="header">私有请求头</option><option value="cookie">私有 Cookie</option></select></div><div><label for="node-xhttp-data-key">数据键（可选）</label><input id="node-xhttp-data-key" v-model="draft.xhttpDataKey" placeholder="默认" /></div></div><div v-if="['packet-up', 'auto'].includes(draft.xhttpMode)" class="grid-2"><div><label for="node-xhttp-chunk-size">编码块大小（0 为默认）</label><input id="node-xhttp-chunk-size" v-model.number="draft.xhttpChunkSize" type="number" min="0" max="8192" step="1" /></div></div>
		  <div class="grid-2"><div><label for="node-xhttp-mux-concurrency">xmux 单连接并发（0 为默认）</label><input id="node-xhttp-mux-concurrency" v-model.number="draft.xhttpMuxConcurrency" type="number" min="0" max="1024" step="1" /></div><div><label for="node-xhttp-mux-connections">xmux 连接目标（0 为默认）</label><input id="node-xhttp-mux-connections" v-model.number="draft.xhttpMuxConnections" type="number" min="0" max="128" step="1" /></div><div><label for="node-xhttp-mux-reuse">连接复用次数（0 为无限）</label><input id="node-xhttp-mux-reuse" v-model.number="draft.xhttpMuxReuse" type="number" min="0" max="100000" step="1" /></div><div><label for="node-xhttp-mux-requests">请求次数（0 为无限）</label><input id="node-xhttp-mux-requests" v-model.number="draft.xhttpMuxRequests" type="number" min="0" max="100000" step="1" /></div><div><label for="node-xhttp-mux-seconds">可复用时长（秒，0 为无限）</label><input id="node-xhttp-mux-seconds" v-model.number="draft.xhttpMuxSeconds" type="number" min="0" max="86400" step="1" /></div><div><label for="node-xhttp-mux-keepalive">保活周期（秒，0 为关闭）</label><input id="node-xhttp-mux-keepalive" v-model.number="draft.xhttpMuxKeepAlive" type="number" min="0" max="3600" step="1" /></div></div>
          <div v-if="['packet-up', 'auto'].includes(draft.xhttpMode)" class="grid-2"><div><label for="node-xhttp-max-buffered-posts">缓冲分片上限（0 为默认）</label><input id="node-xhttp-max-buffered-posts" v-model.number="draft.xhttpMaxBufferedPosts" type="number" min="0" max="32" step="1" required /></div><div><label for="node-xhttp-max-concurrent-posts">并发上行上限（0 为默认 1）</label><input id="node-xhttp-max-concurrent-posts" v-model.number="draft.xhttpMaxConcurrentPosts" type="number" min="0" :max="Math.min(8, draft.xhttpMaxBufferedPosts + 1)" step="1" required /></div></div>
          <div v-if="draft.xhttpMode === 'stream-up'" class="grid-2"><div><label for="node-xhttp-stream-up-server-secs">服务端填充周期（秒）</label><input id="node-xhttp-stream-up-server-secs" v-model.number="streamUpPeriod.min" type="number" min="0" max="300" step="1" placeholder="默认" /></div><div><label for="node-xhttp-stream-up-server-max-secs">最大周期（秒）</label><input id="node-xhttp-stream-up-server-max-secs" v-model.number="streamUpPeriod.max" type="number" min="0" max="300" step="1" placeholder="默认" /></div></div>
          <label v-if="['stream-up', 'stream-one'].includes(draft.xhttpMode)" for="node-xhttp-no-grpc"><input id="node-xhttp-no-grpc" v-model="draft.xhttpNoGRPCHeader" type="checkbox" /> 流式上行不发送 application/grpc 头</label>
          <label for="node-xhttp-no-sse"><input id="node-xhttp-no-sse" v-model="draft.xhttpNoSSEHeader" type="checkbox" /> 下行不发送 text/event-stream 头</label>
          <label for="node-xhttp-max-header">服务端请求头上限（字节）</label><input id="node-xhttp-max-header" v-model.number="draft.xhttpMaxHeaderBytes" type="number" min="8192" max="32768" step="1" required />
          <small v-if="draft.xhttpMode === 'packet-up'" class="help">原生 packet-up：有序上行分片、GET 流式下行。HTTP/3 需要 UDP 端口直连；REALITY 须关闭连接 HTTPS。任一段使用 HTTP 时须启用 VLESS Encryption。</small>
          <small v-else-if="draft.xhttpMode === 'stream-up'" class="help">原生 stream-up：单条流式上行请求、GET 流式下行。仅支持直连 HTTPS 的 HTTP/2 或 HTTP/3，Server 回源须选择 TLS。</small>
          <small v-else-if="draft.xhttpMode === 'stream-one'" class="help">原生 stream-one：单条双向流式请求。仅支持直连 HTTPS 的 HTTP/2 或 HTTP/3，Server 回源须选择 TLS。</small>
          <small v-else class="help">auto 在非 REALITY 安全组合下选 packet-up；REALITY 需要 stream-one，但当前流式回源不支持该组合，因此会明确拒绝而不降级。</small>
          <small v-if="!draft.xhttpPaddingObfs" class="help">请求建连超时默认 15 秒；Referer 请求填充与 X-Padding 响应填充在最小/最大值之间随机选择，相同值表示固定填充。旧配置未设置最大值时保持固定长度；新建默认 100–1000。h2c 仅限 packet-up/auto 直连、Encryption 回源并启用 VLESS Encryption；不经 CDN 隐式协商或降级。尚不支持 xmux；Veilink 节点之间通信，不连接 Xray 对端。</small>
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
          <label for="node-spiderx">伪装爬取起点（SpiderX）</label><input id="node-spiderx" v-model="draft.spiderX" placeholder="/（验证失败时伪装浏览用）" />
          <label for="node-spidery">伪装爬取参数（SpiderY）</label><input id="node-spidery" v-model="draft.spiderY" placeholder="10 个逗号分隔整数，留空用默认" />
          <label for="node-mldsa65">ML-DSA-65 验证公钥</label><div class="field-actions"><input id="node-mldsa65" v-model="draft.mldsa65Verify" placeholder="后量子额外验证，可选" /><button type="button" class="btn small" :disabled="!!generation.busy || reading" @click="generate('mldsa65')">生成密钥对</button></div>
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
