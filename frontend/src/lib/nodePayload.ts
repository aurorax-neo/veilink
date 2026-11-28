import { validateNode, validatePEM } from '../format'
import type { ConnectEndpoint, Node, TunnelConfig, XhttpConfig } from '../types'

export type MetaPlacement = 'path' | 'query' | 'header' | 'cookie'
export type PaddingPlacement = 'query_in_header' | 'query' | 'header' | 'cookie'
export type XhttpMode = 'packet-up' | 'stream-up' | 'stream-one' | 'auto'

export interface NodeDraft {
  id: string
  name: string
  mode: 'online' | 'offline'
  address: string
  port: string
  listenPort: string
  protocol: 'vless' | 'hysteria2'
  transport: 'tcp' | 'xhttp' | 'quic'
  security: 'tls' | 'reality' | 'encryption'
  flow: string
  enc: string
  cert: string
  key: string
  ca: string
  listen: string
  dest: string
  privateKey: string
  shortIDs: string
  names: string
  password: string
  spiderX: string
  spiderY: string
  mldsa65Verify: string
  mldsa65Seed: string
  xhttpPath: string
  xhttpDownloadEndpoint: string
  xhttpHost: string
  xhttpHeaders: string
  xhttpMode: XhttpMode
  xhttpVersion: '' | '1.1' | '2' | '3'
  xhttpTLS: boolean
  xhttpPostBytes: number
  xhttpPostBytesMax: number
  xhttpPostInterval: number
  xhttpPostIntervalMax: number
  xhttpMaxBufferedPosts: number
  xhttpMaxConcurrentPosts: number
  xhttpDataPlacement: 'body' | 'header' | 'cookie'
  xhttpDataKey: string
  xhttpChunkSize: number
  xhttpMuxConcurrency: number
  xhttpMuxConnections: number
  xhttpMuxReuse: number
  xhttpMuxRequests: number
  xhttpMuxSeconds: number
  xhttpMuxKeepAlive: number
  xhttpTimeout: number
  xhttpPadding: number
  xhttpPaddingMax: number
  xhttpPaddingObfs: boolean
  xhttpPaddingPlacement: PaddingPlacement
  xhttpPaddingKey: string
  xhttpPaddingHeader: string
  xhttpPaddingMethod: 'repeat-x' | 'tokenish'
  xhttpNoGRPCHeader: boolean
  xhttpNoSSEHeader: boolean
  xhttpMaxHeaderBytes: number
  xhttpUplinkMethod: 'POST' | 'PUT' | 'OPTIONS'
  xhttpSessionPlacement: MetaPlacement
  xhttpSessionKey: string
  xhttpSeqPlacement: MetaPlacement
  xhttpSeqKey: string
  xhttpSessionTable: string
  xhttpSessionLength: number
  streamUpMin: number | ''
  streamUpMax: number | ''
}

export interface NodeGenOptions {
  mode: 'native' | 'xorpub' | 'random'
  authentication: 'x25519' | 'mlkem768'
  ttl: number
}

export function effectiveXhttpMode(draft: Pick<NodeDraft, 'xhttpMode' | 'security' | 'xhttpDownloadEndpoint'>): 'packet-up' | 'stream-up' | 'stream-one' {
  if (draft.xhttpMode !== 'auto') return draft.xhttpMode
  if (draft.security === 'reality') return draft.xhttpDownloadEndpoint ? 'stream-up' : 'stream-one'
  return 'packet-up'
}

export function isFlowAllowed(draft: Pick<NodeDraft, 'protocol' | 'transport' | 'security'>): boolean {
  return draft.protocol === 'vless' && draft.transport === 'tcp' && (draft.security === 'tls' || draft.security === 'reality')
}

export function inferVlessOptions(dec?: string): { mode: 'native' | 'xorpub' | 'random'; authentication: 'x25519' | 'mlkem768' } {
  const parts = (dec || '').trim().split('.')
  if (parts.length >= 4 && parts[0] === 'mlkem768x25519plus') {
    const mode = (['native', 'xorpub', 'random'].includes(parts[1]) ? parts[1] : 'native') as 'native' | 'xorpub' | 'random'
    const authentication = parts[3] && parts[3].length > 50 ? 'mlkem768' : 'x25519'
    return { mode, authentication }
  }
  return { mode: 'native', authentication: 'x25519' }
}

export function inferCertTtlDays(pem?: string): number {
  const body = (pem || '').replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/g, '')
  if (!body) return 30
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
  let bits = 0
  let value = 0
  let raw = ''
  for (let i = 0; i < body.length; i++) {
    const idx = alphabet.indexOf(body[i])
    if (idx < 0) continue
    value = (value << 6) | idx
    bits += 6
    if (bits >= 8) {
      bits -= 8
      raw += String.fromCharCode((value >>> bits) & 0xff)
    }
  }
  const toMs = (tag: number, str: string): number => {
    const full = tag === 0x17 ? `${Number(str.slice(0, 2)) >= 50 ? '19' : '20'}${str}` : str
    return Date.UTC(
      Number(full.slice(0, 4)),
      Number(full.slice(4, 6)) - 1,
      Number(full.slice(6, 8)),
      Number(full.slice(8, 10)),
      Number(full.slice(10, 12)),
      Number(full.slice(12, 14)),
    )
  }
  const match = raw.match(/([\x17\x18])[\x0d\x0f](\d{12,14}Z)([\x17\x18])[\x0d\x0f](\d{12,14}Z)/)
  if (!match) return 30
  const days = Math.round((toMs(match[3].charCodeAt(0), match[4]) - toMs(match[1].charCodeAt(0), match[2])) / 86_400_000)
  return days >= 1 && days <= 365 ? days : 30
}

// Strict tokenizer rejecting duplicate keys and disallowed header names.
export function parseXHTTPHeaders(text: string): Record<string, string> | undefined {
  if (!text.trim()) return undefined
  const fail = (message: string): never => {
    throw new Error(`XHTTP 请求头：${message}`)
  }
  if (new TextEncoder().encode(text).length > 2048) fail('JSON 对象不能超过 2048 字节。')
  let position = 0
  const space = () => {
    while (position < text.length && /[ \t\r\n]/.test(text[position])) position++
  }
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
  if (text[position] === '}') {
    position++
    space()
    if (position !== text.length) fail('JSON 对象后不能有额外内容。')
    return undefined
  }
  while (position < text.length) {
    space()
    const name = readString()
    const lower = name.toLowerCase()
    if (name.length > 64 || !(/^(user-agent|accept-language)$/.test(lower) || /^x-custom-[a-z0-9-]+$/.test(lower))) {
      fail(`不允许请求头 ${name}。`)
    }
    if (seen.has(lower)) fail(`请求头 ${name} 重复。`)
    seen.add(lower)
    if (seen.size > 8) fail('最多 8 个字段。')
    space()
    if (text[position++] !== ':') fail('JSON 对象缺少冒号。')
    space()
    const value = readString()
    const bytes = new TextEncoder().encode(value).length
    if (
      bytes < 1 ||
      bytes > 256 ||
      value.trim() !== value ||
      /\p{Cc}/u.test(value) ||
      /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value)
    ) {
      fail(`请求头 ${name} 的值无效。`)
    }
    const canonical = lower.replace(/(^|-)[a-z]/g, (part) => part.toUpperCase())
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

export function nodeToDraft(node: Node | undefined, defaultName = '1'): {
  draft: NodeDraft
  endpoints: ConnectEndpoint[]
  options: NodeGenOptions
  originalTunnel: TunnelConfig
} {
  const originalTunnel: TunnelConfig = node?.tunnel ? JSON.parse(JSON.stringify(node.tunnel)) : {}
  const t = originalTunnel
  const vlessOpts = inferVlessOptions(t.decryption)
  const options: NodeGenOptions = {
    mode: vlessOpts.mode,
    authentication: vlessOpts.authentication,
    ttl: inferCertTtlDays(t.cert_pem),
  }
  const listenPort = String(t.listen_port || node?.port || 443)
  const savedEndpoints: ConnectEndpoint[] = node?.connect_endpoints?.length
    ? node.connect_endpoints.map((ep) => ({ ...ep }))
    : node?.address
      ? [{ id: 'primary', name: '首选地址', host: node.address, port: node.port || 443, enabled: true }]
      : [{ id: `endpoint-${Date.now()}-0`, name: '首选地址', host: '127.0.0.1', port: Number(listenPort) || 443, enabled: true }]

  const nextProtocol: 'vless' | 'hysteria2' = t.protocol === 'hysteria2' || (!t.protocol && t.hysteria2?.password) ? 'hysteria2' : 'vless'
  const nextTransport: 'tcp' | 'xhttp' | 'quic' = nextProtocol === 'hysteria2' ? 'quic' : t.xhttp?.path ? 'xhttp' : 'tcp'
  const nextSecurity: 'tls' | 'reality' | 'encryption' =
    nextProtocol === 'hysteria2'
      ? 'tls'
      : t.reality && Object.values(t.reality).some(Boolean)
        ? 'reality'
        : t.transport_security === 'plain'
          ? 'encryption'
          : 'tls'

  const draft: NodeDraft = {
    id: node?.id || '',
    name: node?.name || defaultName,
    mode: !node?.embedded && node?.mode === 'offline' ? 'offline' : 'online',
    address: node?.address || '',
    port: String(node?.port || 443),
    listenPort,
    protocol: nextProtocol,
    transport: nextTransport,
    security: nextSecurity,
    flow: isFlowAllowed({ protocol: nextProtocol, transport: nextTransport, security: nextSecurity }) ? t.flow || '' : '',
    enc: t.decryption || '',
    cert: t.cert_pem || '',
    key: t.key_pem || '',
    ca: t.ca_pem || '',
    listen: node ? t.listen_host || '' : '0.0.0.0',
    dest: t.reality?.dest || '',
    privateKey: t.reality?.private_key || '',
    shortIDs: t.reality?.short_ids || t.reality?.short_id || '',
    names: t.reality?.server_names || '',
    password: t.hysteria2?.password || '',
    spiderX: t.reality?.spider_x || '',
    spiderY: t.reality?.spider_y || '',
    mldsa65Verify: t.reality?.mldsa65_verify || '',
    mldsa65Seed: t.reality?.mldsa65_seed || '',
    xhttpPath: t.xhttp?.path || '/veilink/',
    xhttpDownloadEndpoint: t.xhttp?.download_endpoint_id || '',
    xhttpHost: t.xhttp?.host || '',
    xhttpHeaders: t.xhttp?.headers
      ? typeof t.xhttp.headers === 'string'
        ? t.xhttp.headers
        : JSON.stringify(t.xhttp.headers)
      : '',
    xhttpMode: t.xhttp?.mode || 'packet-up',
    xhttpVersion: t.xhttp?.http_version || '',
    xhttpTLS: t.xhttp?.tls ?? nextSecurity !== 'reality',
    xhttpPostBytes: t.xhttp?.max_each_post_bytes || 32768,
    xhttpPostBytesMax: t.xhttp?.post_bytes_max || 0,
    xhttpPostInterval: t.xhttp?.min_posts_interval_ms || 0,
    xhttpPostIntervalMax: t.xhttp?.max_posts_interval_ms || 0,
    xhttpMaxBufferedPosts: t.xhttp?.max_buffered_posts ?? 0,
    xhttpMaxConcurrentPosts: t.xhttp?.max_concurrent_posts ?? 0,
    xhttpDataPlacement: t.xhttp?.uplink_data_placement || 'body',
    xhttpDataKey: t.xhttp?.uplink_data_key || '',
    xhttpChunkSize: t.xhttp?.uplink_chunk_size || 0,
    xhttpMuxConcurrency: t.xhttp?.xmux?.max_concurrency || 0,
    xhttpMuxConnections: t.xhttp?.xmux?.max_connections || 0,
    xhttpMuxReuse: t.xhttp?.xmux?.c_max_reuse_times || 0,
    xhttpMuxRequests: t.xhttp?.xmux?.h_max_request_times || 0,
    xhttpMuxSeconds: t.xhttp?.xmux?.h_max_reusable_secs || 0,
    xhttpMuxKeepAlive: t.xhttp?.xmux?.keep_alive_period || 0,
    xhttpTimeout: t.xhttp?.request_timeout_seconds || 15,
    xhttpPadding: t.xhttp?.padding_bytes || 100,
    xhttpPaddingMax: t.xhttp?.padding_max_bytes || (t.xhttp?.padding_bytes ? t.xhttp.padding_bytes : 1000),
    xhttpPaddingObfs: t.xhttp?.padding_obfs_mode || false,
    xhttpPaddingPlacement: t.xhttp?.padding_placement || 'query_in_header',
    xhttpPaddingKey: t.xhttp?.padding_key || 'x_padding',
    xhttpPaddingHeader: t.xhttp?.padding_header || (t.xhttp?.padding_placement === 'header' ? 'X-Padding' : 'Referer'),
    xhttpPaddingMethod: t.xhttp?.padding_method || 'repeat-x',
    xhttpNoGRPCHeader: t.xhttp?.no_grpc_header || false,
    xhttpNoSSEHeader: t.xhttp?.no_sse_header || false,
    xhttpMaxHeaderBytes: t.xhttp?.server_max_header_bytes || 8192,
    xhttpUplinkMethod: t.xhttp?.uplink_http_method || 'POST',
    xhttpSessionPlacement: t.xhttp?.session_id_placement || 'path',
    xhttpSessionKey: t.xhttp?.session_id_key || '',
    xhttpSeqPlacement: t.xhttp?.seq_placement || 'path',
    xhttpSeqKey: t.xhttp?.seq_key || '',
    xhttpSessionTable: t.xhttp?.session_id_table || '',
    xhttpSessionLength: t.xhttp?.session_id_length || 0,
    streamUpMin: t.xhttp?.stream_up_server_secs || '',
    streamUpMax: t.xhttp?.stream_up_server_max_secs || '',
  }

  return { draft, endpoints: savedEndpoints, options, originalTunnel }
}

function buildXhttpMetaFields(draft: NodeDraft, effMode: 'packet-up' | 'stream-up' | 'stream-one'): Partial<XhttpConfig> {
  const fields: Partial<XhttpConfig> = {}
  if (effMode === 'stream-one') return fields
  const check = (placement: MetaPlacement, key: string, label: string) => {
    if (!['path', 'query', 'header', 'cookie'].includes(placement)) throw new Error(`${label}位置无效。`)
    if (placement === 'path' && key) throw new Error(`${label}路径位置不能填写键名。`)
    if (placement === 'query' && key && (!/^[a-z0-9_]{1,40}$/.test(key) || key === 'x_padding')) {
      throw new Error(`${label}查询键名须为 1–40 位小写字母、数字或下划线，且不能为 x_padding。`)
    }
    if (placement === 'cookie' && key && (!/^x_[a-z0-9_]{1,38}$/.test(key) || key.length > 40 || key === 'x_padding')) {
      throw new Error(`${label}Cookie 键名须以 x_ 开头，最多 40 位小写字母、数字或下划线。`)
    }
    if (
      placement === 'header' &&
      key &&
      (!/^X-Veilink-[A-Za-z0-9-]+$/.test(key) || key.length > 48 || /^X-Veilink-(EOF|Upload-Complete)$/i.test(key))
    ) {
      throw new Error(`${label}请求头键名须以 X-Veilink- 开头，最多 48 位且不能使用保留名称。`)
    }
  }
  check(draft.xhttpSessionPlacement, draft.xhttpSessionKey, '会话 ID')
  if (draft.xhttpSessionPlacement !== 'path') fields.session_id_placement = draft.xhttpSessionPlacement
  if (draft.xhttpSessionKey) fields.session_id_key = draft.xhttpSessionKey
  if (effMode === 'packet-up') {
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
    if (!table || !Number.isInteger(length) || length < 24 || length > 64) {
      throw new Error('会话 ID 自定义字符表需配合 24–64 位长度。')
    }
    const chars =
      table === 'hex'
        ? '0123456789abcdef'
        : table === 'base62'
          ? '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
          : table
    if (chars.length < 16 || chars.length > 64 || !/^[A-Za-z0-9_-]+$/.test(chars) || new Set(chars).size !== chars.length) {
      throw new Error('会话 ID 字符表须为 16–64 个互异的 URL 安全 ASCII 字符。')
    }
    if (length * Math.log2(chars.length) < 128) throw new Error('会话 ID 长度与字符表须提供至少 128 位熵。')
    fields.session_id_table = table
    fields.session_id_length = length
  }
  return fields
}

function buildXhttpPaddingFields(draft: NodeDraft, effMode: 'packet-up' | 'stream-up' | 'stream-one'): Partial<XhttpConfig> {
  if (!draft.xhttpPaddingObfs) return {}
  const placement = draft.xhttpPaddingPlacement
  const key = draft.xhttpPaddingKey
  const header = draft.xhttpPaddingHeader
  if (!['query_in_header', 'query', 'header', 'cookie'].includes(placement)) throw new Error('XHTTP 填充位置无效。')
  if (!['repeat-x', 'tokenish'].includes(draft.xhttpPaddingMethod)) throw new Error('XHTTP 填充方法无效。')
  if (placement === 'query' || placement === 'query_in_header') {
    if (!/^[a-z0-9_]{1,40}$/.test(key)) throw new Error('XHTTP 填充查询键名无效。')
  }
  if (placement === 'cookie' && !/^x_[a-z0-9_]{1,38}$/.test(key)) {
    throw new Error('XHTTP 填充 Cookie 键名须为私有 x_ 名称。')
  }
  if (placement === 'header' || placement === 'query_in_header') {
    if (header !== 'Referer' && header !== 'X-Padding' && (!/^X-Custom-[A-Za-z0-9-]+$/.test(header) || header.length > 48)) {
      throw new Error('XHTTP 填充请求头名无效。')
    }
    if (placement === 'header' && header === 'Referer') throw new Error('XHTTP 请求头填充不能覆盖 Referer。')
  }
  const sessionKey = draft.xhttpSessionKey || (draft.xhttpSessionPlacement === 'header' ? 'X-Veilink-Session' : 'x_session')
  const seqKey = draft.xhttpSeqKey || (draft.xhttpSeqPlacement === 'header' ? 'X-Veilink-Seq' : 'x_seq')
  const activeMeta =
    effMode === 'stream-one'
      ? []
      : [[draft.xhttpSessionPlacement, sessionKey], ...(effMode === 'packet-up' ? [[draft.xhttpSeqPlacement, seqKey]] : [])]
  for (const [position, configured] of activeMeta) {
    if (position === placement && (placement === 'cookie' || placement === 'query') && configured === key) {
      throw new Error('XHTTP 填充键名不能覆盖会话或序号。')
    }
    if (position === 'header' && (placement === 'header' || placement === 'query_in_header') && configured.toLowerCase() === header.toLowerCase()) {
      throw new Error('XHTTP 填充请求头不能覆盖会话或序号。')
    }
  }
  return {
    padding_obfs_mode: true,
    padding_placement: placement,
    ...(placement === 'header' ? {} : { padding_key: key }),
    ...(placement === 'header' || placement === 'query_in_header' ? { padding_header: header } : {}),
    padding_method: draft.xhttpPaddingMethod,
  }
}

export function buildNodeSavePayload(
  role: 'server' | 'client',
  draft: NodeDraft,
  endpoints: ConnectEndpoint[],
  originalTunnel: TunnelConfig,
): Record<string, unknown> {
  const isServer = role === 'server'
  const workingEndpoints = endpoints.map((ep) => ({ ...ep }))
  const primary = workingEndpoints.find((ep) => ep.enabled) || workingEndpoints[0]
  if (isServer && primary && !primary.host.trim() && draft.address.trim()) {
    primary.host = draft.address.trim()
    primary.port = Number(draft.port)
  }

  const problem = validateNode({
    ...draft,
    address: primary?.host || '',
    port: String(primary?.port || ''),
    role,
  })
  if (problem) throw new Error(problem)
  if (draft.mode && draft.mode !== 'online' && draft.mode !== 'offline') {
    throw new Error('节点模式仅支持 online 或 offline。')
  }
  const modeField = draft.mode === 'offline' ? { mode: 'offline' as const } : {}

  if (!isServer) {
    return { name: draft.name.trim(), role, ...modeField, address: '', port: 0 }
  }

  if (!workingEndpoints.length || !workingEndpoints.some((ep) => ep.enabled)) {
    throw new Error('至少启用一个客户端连接地址。')
  }
  for (const ep of workingEndpoints) {
    if (!ep.name?.trim() || !ep.host?.trim() || Number(ep.port) < 1 || Number(ep.port) > 65535) {
      throw new Error('连接地址需要名称、主机/域名和端口。')
    }
  }

  const tunnel: TunnelConfig = {}
  const effMode = effectiveXhttpMode(draft)
  const downloadEndpoints = workingEndpoints.filter((ep) => ep.enabled)

  tunnel.protocol = draft.protocol
  tunnel.transport_security =
    draft.protocol === 'hysteria2' || draft.security === 'reality' ? '' : draft.security === 'tls' ? 'tls' : 'plain'

  if (draft.protocol === 'hysteria2') {
    if (!draft.password.trim()) throw new Error('请输入 Hysteria2 密码。')
    tunnel.hysteria2 = { password: draft.password.trim() }
    tunnel.cert_pem = draft.cert.trim()
    tunnel.key_pem = draft.key.trim()
    if (draft.ca.trim()) tunnel.ca_pem = draft.ca.trim()
  } else if (draft.transport === 'xhttp') {
    const path = draft.xhttpPath.trim()
    if (path.length > 256 || (!/^\/[A-Za-z0-9/_-]*\/$/.test(path) && path !== '/') || path.includes('//')) {
      throw new Error('XHTTP 路径须以 / 开头和结尾，仅含字母、数字、/、_、-，最多 256 字节。')
    }
    const httpHost = draft.xhttpHost.trim()
    if (
      httpHost &&
      (httpHost.length > 253 ||
        !httpHost.includes('.') ||
        httpHost.split('.').some((label) => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-') || !/^[a-z0-9-]+$/.test(label)))
    ) {
      throw new Error('XHTTP Host 须为小写域名或 IPv4，不含端口。')
    }
    if (effMode !== 'stream-one' && draft.xhttpDownloadEndpoint && !downloadEndpoints.some((ep) => ep.id === draft.xhttpDownloadEndpoint)) {
      throw new Error('请选择当前启用的 XHTTP 分离下行入口。')
    }
    if (!['packet-up', 'stream-up', 'stream-one', 'auto'].includes(draft.xhttpMode)) {
      throw new Error('XHTTP 模式仅支持 packet-up、stream-up、stream-one 或 auto。')
    }
    if (!['', '1.1', '2', '3'].includes(draft.xhttpVersion)) throw new Error('XHTTP HTTP 版本无效。')
    if (effMode !== 'packet-up' && draft.xhttpVersion === '1.1') throw new Error('XHTTP 流模式需要 HTTP/2 或 HTTP/3。')
    if (
      (effMode === 'stream-up' || effMode === 'stream-one') &&
      draft.security !== 'reality' &&
      (draft.security !== 'tls' || !draft.xhttpTLS || draft.xhttpVersion === '1.1')
    ) {
      throw new Error('XHTTP 流模式仅支持直连 HTTPS + TLS 回源的 HTTP/2 或 HTTP/3（或 REALITY）。')
    }
    if (draft.xhttpVersion === '3' && (draft.security !== 'tls' || !draft.xhttpTLS)) {
      throw new Error('XHTTP HTTP/3 仅支持直连 HTTPS + TLS 回源。')
    }
    if (
      draft.xhttpVersion === '2' &&
      !draft.xhttpTLS &&
      draft.security !== 'reality' &&
      (effMode !== 'packet-up' || draft.security !== 'encryption')
    ) {
      throw new Error('XHTTP h2c 仅允许 packet-up、直连 HTTP 与 Encryption 回源；必须启用 VLESS Encryption。')
    }
    if (draft.security === 'reality' && draft.xhttpTLS) {
      throw new Error('XHTTP + REALITY 时必须关闭连接 HTTPS；REALITY 已提供外层安全。')
    }
    if (draft.security !== 'reality' && (draft.security === 'encryption' || !draft.xhttpTLS) && (!draft.enc.trim() || draft.enc.trim() === 'none')) {
      throw new Error('XHTTP 使用 HTTP 时必须启用 VLESS Encryption。')
    }
    if (effMode === 'packet-up') {
      if (!Number.isInteger(draft.xhttpPostBytes) || draft.xhttpPostBytes < 1024 || draft.xhttpPostBytes > 32768) {
        throw new Error('XHTTP 上行分片须为 1024–32768 字节。')
      }
      if (
        !Number.isInteger(draft.xhttpPostBytesMax) ||
        draft.xhttpPostBytesMax < 0 ||
        draft.xhttpPostBytesMax > 32768 ||
        (draft.xhttpPostBytesMax > 0 && draft.xhttpPostBytesMax < draft.xhttpPostBytes)
      ) {
        throw new Error('XHTTP 分片最大值须为 0（固定）或介于最小值和 32768 字节之间。')
      }
      if (!Number.isInteger(draft.xhttpPostInterval) || draft.xhttpPostInterval < 0 || draft.xhttpPostInterval > 1000) {
        throw new Error('XHTTP 分片最小间隔须为 0–1000 毫秒。')
      }
      if (
        !Number.isInteger(draft.xhttpPostIntervalMax) ||
        draft.xhttpPostIntervalMax < 0 ||
        draft.xhttpPostIntervalMax > 1000 ||
        (draft.xhttpPostIntervalMax > 0 && (draft.xhttpPostInterval === 0 || draft.xhttpPostIntervalMax < draft.xhttpPostInterval))
      ) {
        throw new Error('XHTTP 分片最大间隔须为 0（固定）或介于最小间隔和 1000 毫秒之间。')
      }
      if (!Number.isInteger(draft.xhttpMaxBufferedPosts) || draft.xhttpMaxBufferedPosts < 0 || draft.xhttpMaxBufferedPosts > 32) {
        throw new Error('XHTTP 缓冲分片上限须为 0（默认）或 1–32 的整数。')
      }
      if (!Number.isInteger(draft.xhttpMaxConcurrentPosts) || draft.xhttpMaxConcurrentPosts < 0 || draft.xhttpMaxConcurrentPosts > 8) {
        throw new Error('XHTTP 并发上行上限须为 0（默认 1）或 1–8 的整数。')
      }
      if (draft.xhttpMaxConcurrentPosts > draft.xhttpMaxBufferedPosts + 1) {
        throw new Error('XHTTP 并发上行上限不能超过缓冲分片上限加 1。')
      }
      if (!['body', 'header', 'cookie'].includes(draft.xhttpDataPlacement)) throw new Error('XHTTP 上行数据位置无效。')
      if (
        draft.xhttpDataPlacement !== 'body' &&
        draft.xhttpDataKey &&
        (draft.xhttpDataPlacement === 'header'
          ? !/^X-Veilink-[A-Za-z0-9-]{1,48}$/.test(draft.xhttpDataKey) || draft.xhttpDataKey.toLowerCase() === 'x-veilink-eof'
          : !/^x_[a-z0-9_]{1,48}$/.test(draft.xhttpDataKey))
      ) {
        throw new Error('XHTTP 上行数据键名无效。')
      }
      if (
        !Number.isInteger(draft.xhttpChunkSize) ||
        draft.xhttpChunkSize < 0 ||
        draft.xhttpChunkSize > 8192 ||
        (draft.xhttpChunkSize > 0 && draft.xhttpChunkSize < 64)
      ) {
        throw new Error('XHTTP 上行编码块须为 0 或 64–8192。')
      }
      if (draft.xhttpDataPlacement === 'body' && (draft.xhttpDataKey || draft.xhttpChunkSize)) {
        throw new Error('XHTTP body 位置不能配置数据键或编码块。')
      }
      if (draft.xhttpDataPlacement !== 'body') {
        const placement = draft.xhttpDataPlacement
        const prefix = (draft.xhttpDataKey || (placement === 'header' ? 'X-Veilink-Data' : 'x_data')) + (placement === 'header' ? '-' : '_')
        const metaKeys = [
          [draft.xhttpSessionPlacement, draft.xhttpSessionKey || (draft.xhttpSessionPlacement === 'header' ? 'X-Veilink-Session' : 'x_session')],
          [draft.xhttpSeqPlacement, draft.xhttpSeqKey || (draft.xhttpSeqPlacement === 'header' ? 'X-Veilink-Seq' : 'x_seq')],
          ...(draft.xhttpPaddingObfs && draft.xhttpPaddingPlacement === 'cookie' ? [['cookie', draft.xhttpPaddingKey]] : []),
        ]
        if (metaKeys.some(([pos, key]) => pos === placement && (placement === 'header' ? key.toLowerCase().startsWith(prefix.toLowerCase()) : key.startsWith(prefix)))) {
          throw new Error('XHTTP 数据键不能与会话、序号或填充键冲突。')
        }
      }
    }
    for (const v of [
      draft.xhttpMuxConcurrency,
      draft.xhttpMuxConnections,
      draft.xhttpMuxReuse,
      draft.xhttpMuxRequests,
      draft.xhttpMuxSeconds,
      draft.xhttpMuxKeepAlive,
    ]) {
      if (!Number.isInteger(v) || v < 0) throw new Error('XHTTP xmux 参数须为非负整数。')
    }
    if (
      draft.xhttpMuxConcurrency > 1024 ||
      draft.xhttpMuxConnections > 128 ||
      draft.xhttpMuxReuse > 100000 ||
      draft.xhttpMuxRequests > 100000 ||
      draft.xhttpMuxSeconds > 86400 ||
      draft.xhttpMuxKeepAlive > 3600
    ) {
      throw new Error('XHTTP xmux 参数超出范围。')
    }
    const streamUpMin = draft.streamUpMin === '' ? 0 : Number(draft.streamUpMin)
    const streamUpMax = draft.streamUpMax === '' ? 0 : Number(draft.streamUpMax)
    if (effMode === 'stream-up') {
      if (!Number.isInteger(streamUpMin) || streamUpMin < 0 || streamUpMin > 300) {
        throw new Error('XHTTP 填充周期须为空、0 或 1–300 秒的整数。')
      }
      if (!Number.isInteger(streamUpMax) || streamUpMax < 0 || streamUpMax > 300 || (streamUpMax > 0 && (streamUpMin === 0 || streamUpMax < streamUpMin))) {
        throw new Error('XHTTP 填充最大周期须为空、0 或介于已指定周期和 300 秒之间的整数。')
      }
    }
    if (!Number.isInteger(draft.xhttpTimeout) || draft.xhttpTimeout < 5 || draft.xhttpTimeout > 60) {
      throw new Error('XHTTP 请求超时须为 5–60 秒。')
    }
    if (!Number.isInteger(draft.xhttpPadding) || draft.xhttpPadding < 1 || draft.xhttpPadding > 1000) {
      throw new Error('XHTTP 填充最小值须为 1–1000 字节。')
    }
    if (!Number.isInteger(draft.xhttpPaddingMax) || draft.xhttpPaddingMax < draft.xhttpPadding || draft.xhttpPaddingMax > 1000) {
      throw new Error('XHTTP 填充最大值须不小于最小值且不超过 1000 字节。')
    }
    if (!['POST', 'PUT', 'OPTIONS'].includes(draft.xhttpUplinkMethod)) {
      throw new Error('XHTTP 上行方法仅支持 POST、PUT 或 OPTIONS。')
    }
    if (!Number.isInteger(draft.xhttpMaxHeaderBytes) || draft.xhttpMaxHeaderBytes < 8192 || draft.xhttpMaxHeaderBytes > 32768) {
      throw new Error('XHTTP 服务端请求头上限须为 8192–32768 字节。')
    }
    const headers = parseXHTTPHeaders(draft.xhttpHeaders)
    const xmuxHas =
      draft.xhttpMuxConcurrency ||
      draft.xhttpMuxConnections ||
      draft.xhttpMuxReuse ||
      draft.xhttpMuxRequests ||
      draft.xhttpMuxSeconds ||
      draft.xhttpMuxKeepAlive
    tunnel.xhttp = {
      path,
      ...(effMode !== 'stream-one' && draft.xhttpDownloadEndpoint ? { download_endpoint_id: draft.xhttpDownloadEndpoint } : {}),
      ...(httpHost ? { host: httpHost } : {}),
      ...(headers ? { headers } : {}),
      mode: draft.xhttpMode,
      tls: draft.xhttpTLS,
      ...(draft.xhttpVersion ? { http_version: draft.xhttpVersion } : {}),
      ...(effMode === 'packet-up'
        ? {
            max_each_post_bytes: draft.xhttpPostBytes,
            ...(draft.xhttpPostBytesMax ? { post_bytes_max: draft.xhttpPostBytesMax } : {}),
            ...(draft.xhttpPostInterval ? { min_posts_interval_ms: draft.xhttpPostInterval } : {}),
            ...(draft.xhttpPostIntervalMax ? { max_posts_interval_ms: draft.xhttpPostIntervalMax } : {}),
            ...(draft.xhttpMaxBufferedPosts ? { max_buffered_posts: draft.xhttpMaxBufferedPosts } : {}),
            ...(draft.xhttpMaxConcurrentPosts ? { max_concurrent_posts: draft.xhttpMaxConcurrentPosts } : {}),
            ...(draft.xhttpDataPlacement !== 'body'
              ? {
                  uplink_data_placement: draft.xhttpDataPlacement,
                  ...(draft.xhttpDataKey ? { uplink_data_key: draft.xhttpDataKey } : {}),
                  ...(draft.xhttpChunkSize ? { uplink_chunk_size: draft.xhttpChunkSize } : {}),
                }
              : {}),
          }
        : {}),
      ...(effMode === 'stream-up'
        ? {
            ...(streamUpMin ? { stream_up_server_secs: streamUpMin } : {}),
            ...(streamUpMax ? { stream_up_server_max_secs: streamUpMax } : {}),
          }
        : {}),
      request_timeout_seconds: draft.xhttpTimeout,
      padding_bytes: draft.xhttpPadding,
      ...(draft.xhttpPaddingMax !== draft.xhttpPadding ? { padding_max_bytes: draft.xhttpPaddingMax } : {}),
      ...buildXhttpPaddingFields(draft, effMode),
      ...((effMode === 'stream-up' || effMode === 'stream-one') && draft.xhttpNoGRPCHeader ? { no_grpc_header: true } : {}),
      ...(draft.xhttpNoSSEHeader ? { no_sse_header: true } : {}),
      ...(draft.xhttpMaxHeaderBytes !== 8192 ? { server_max_header_bytes: draft.xhttpMaxHeaderBytes } : {}),
      ...(draft.xhttpUplinkMethod !== 'POST' ? { uplink_http_method: draft.xhttpUplinkMethod } : {}),
      ...buildXhttpMetaFields(draft, effMode),
      ...(xmuxHas
        ? {
            xmux: {
              ...(draft.xhttpMuxConcurrency ? { max_concurrency: draft.xhttpMuxConcurrency } : {}),
              ...(draft.xhttpMuxConnections ? { max_connections: draft.xhttpMuxConnections } : {}),
              ...(draft.xhttpMuxReuse ? { c_max_reuse_times: draft.xhttpMuxReuse } : {}),
              ...(draft.xhttpMuxRequests ? { h_max_request_times: draft.xhttpMuxRequests } : {}),
              ...(draft.xhttpMuxSeconds ? { h_max_reusable_secs: draft.xhttpMuxSeconds } : {}),
              ...(draft.xhttpMuxKeepAlive ? { keep_alive_period: draft.xhttpMuxKeepAlive } : {}),
            },
          }
        : {}),
    }
    if (draft.xhttpTLS && draft.ca.trim()) {
      const caErr = validatePEM(draft.ca, 'ca')
      if (caErr) throw new Error(caErr)
      tunnel.ca_pem = draft.ca.trim()
    }
  }

  if (draft.protocol === 'vless' && (draft.transport === 'tcp' || draft.transport === 'xhttp') && draft.security === 'tls') {
    tunnel.cert_pem = draft.cert.trim()
    tunnel.key_pem = draft.key.trim()
    if (draft.ca.trim()) tunnel.ca_pem = draft.ca.trim()
  } else if (draft.protocol === 'vless' && draft.security === 'reality') {
    tunnel.reality = {
      ...originalTunnel.reality,
      dest: draft.dest.trim(),
      private_key: draft.privateKey.trim(),
      short_ids: draft.shortIDs.trim(),
      server_names: draft.names.trim(),
      ...(draft.spiderX.trim() ? { spider_x: draft.spiderX.trim() } : {}),
      ...(draft.spiderY.trim() ? { spider_y: draft.spiderY.trim() } : {}),
      ...(draft.mldsa65Verify.trim() ? { mldsa65_verify: draft.mldsa65Verify.trim() } : {}),
      ...(draft.mldsa65Seed.trim() ? { mldsa65_seed: draft.mldsa65Seed.trim() } : {}),
    }
    delete tunnel.reality.public_key
    for (const [field, val] of [
      ['spider_x', draft.spiderX],
      ['spider_y', draft.spiderY],
      ['mldsa65_verify', draft.mldsa65Verify],
      ['mldsa65_seed', draft.mldsa65Seed],
    ] as const) {
      if (!val.trim()) delete tunnel.reality[field]
    }
  }

  if (draft.protocol === 'vless' && draft.transport === 'tcp' && draft.security === 'encryption' && (!draft.enc.trim() || draft.enc.trim() === 'none')) {
    throw new Error('plain 无 TLS：请输入 VLESS 解密配置，或点击生成配对配置；不能使用 none。')
  }
  if (draft.protocol === 'vless' && draft.enc.trim() && draft.enc.trim() !== 'none') {
    tunnel.decryption = draft.enc.trim()
  }
  if (isFlowAllowed(draft) && draft.flow) tunnel.flow = draft.flow
  if (draft.listen.trim()) tunnel.listen_host = draft.listen.trim()
  tunnel.listen_port = Number(draft.listenPort)

  return {
    name: draft.name.trim(),
    role,
    ...modeField,
    address: primary!.host.trim(),
    port: Number(primary!.port),
    connect_endpoints: workingEndpoints.map((ep) => ({
      id: ep.id,
      name: ep.name.trim(),
      host: ep.host.trim(),
      port: Number(ep.port),
      enabled: ep.enabled,
    })),
    tunnel,
  }
}
