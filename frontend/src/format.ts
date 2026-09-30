import type { Mapping, Node } from './types'

export type Tone = '' | 'good' | 'warn' | 'bad'

const actions: Record<string, string> = {
  'node.save': '保存节点',
  'node.revoke': '吊销或删除节点',
  'mapping.save': '保存映射',
  'mapping.delete': '删除映射',
}

export function actionLabel(action: string): string {
  return actions[action] || action
}

export function endpoint(host: string, port: number): string {
  const shown = host.includes(':') ? `[${host}]` : host
  return `${shown}:${port}`
}

export function nodeName(nodes: Node[], id: string): string {
  return nodes.find((n) => n.id === id)?.name || id
}

// Stable even when the API returns map-backed rows in a different order.
export function byNameAndId<T extends { name: string; id: string }>(a: T, b: T): number {
  return (a.name || '').localeCompare(b.name || '', 'zh-CN') || a.id.localeCompare(b.id)
}

export function heartbeatOnline(node: Node, now = Date.now()): boolean {
  return !node.revoked && node.last_seen > 0 && now / 1000 >= node.last_seen && now / 1000 - node.last_seen < 90
}

export function presence(node: Node, now = Date.now()): { text: string; tone: Tone } {
  if (node.revoked) return { text: '已吊销', tone: 'bad' }
  if (heartbeatOnline(node, now)) return { text: '近期在线', tone: 'good' }
  if (!node.last_seen) return { text: '尚未连接', tone: '' }
  if (now / 1000 < node.last_seen) return { text: '时钟超前', tone: 'warn' }
  return { text: '心跳超时', tone: 'warn' }
}

export function revisionState(node: Node): { text: string; tone: Tone } {
  if (node.revoked) return { text: '不再同步', tone: '' }
  if (node.error) return { text: '应用失败', tone: 'bad' }
  if (!node.desired_revision) return { text: '尚无配置', tone: '' }
  if (!node.applied_revision) return { text: '待应用', tone: 'warn' }
  if (node.applied_revision === node.desired_revision) return { text: '已应用', tone: 'good' }
  return { text: '待应用', tone: 'warn' }
}

export function attentionReasons(node: Node, now = Date.now()): string[] {
  if (node.revoked) return []
  const reasons: string[] = []
  if (node.error) reasons.push('应用失败')
  if (node.applied_revision !== node.desired_revision) reasons.push('配置待应用')
  if (!heartbeatOnline(node, now)) reasons.push(node.last_seen ? '心跳超过 90 秒' : '尚未上报心跳')
  return reasons
}

export function needsAttention(node: Node, now = Date.now()): boolean {
  return attentionReasons(node, now).length > 0
}

export function seenText(unix: number, now = Date.now()): string {
  if (!unix) return '尚未上报'
  const abs = new Date(unix * 1000).toLocaleString('zh-CN', { hour12: false })
  const delta = Math.round(now / 1000 - unix)
  if (delta < -5) return `${abs}（比本机时钟晚 ${-delta} 秒）`
  if (delta < 90) return `${abs}（${Math.max(delta, 0)} 秒前）`
  const minutes = Math.floor(delta / 60)
  if (minutes < 120) return `${abs}（${minutes} 分钟前）`
  const hours = Math.floor(minutes / 60)
  if (hours < 48) return `${abs}（${hours} 小时前）`
  return abs
}

export function looksLikeIP(value: string): boolean {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) return value.split('.').every((part) => Number(part) <= 255)
  return value.includes(':') && /^[0-9a-fA-F:.]+$/.test(value)
}

function normalizedIP(value: string): string | null {
  const input = value.trim().toLowerCase()
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(input)) return input.split('.').map(part => String(Number(part))).join('.')
  if (!input.includes(':') || !/^[0-9a-f:.]+$/.test(input)) return null
  const parts = input.split('::')
  if (parts.length > 2) return null
  const expand = (side: string) => side ? side.split(':').flatMap(part => {
    if (!part.includes('.')) return [part]
    const bytes = part.split('.').map(Number)
    return bytes.length === 4 && bytes.every(byte => byte >= 0 && byte <= 255) ? [((bytes[0] << 8) | bytes[1]).toString(16), ((bytes[2] << 8) | bytes[3]).toString(16)] : ['invalid']
  }) : []
  const left = expand(parts[0]), right = expand(parts[1] || '')
  const missing = 8 - left.length - right.length
  if ((parts.length === 2 ? missing < 1 : missing !== 0) || [...left, ...right].some(part => !/^[0-9a-f]{1,4}$/.test(part))) return null
  return [...left, ...Array(missing).fill('0'), ...right].map(part => part.padStart(4, '0')).join(':')
}

function listenOverlap(a: string, b: string): boolean {
  const first = normalizedIP(a), second = normalizedIP(b)
  if (!first || !second) return false
  const wildcard = (value: string) => value === '0.0.0.0' || value === '0000:0000:0000:0000:0000:0000:0000:0000'
  return first === second || wildcard(first) || wildcard(second)
}

function validHost(value: string, allowName: boolean): boolean {
  const host = value.trim()
  if (!host || host.length > 253 || /[\s/\\@]/.test(host) || host.includes('://')) return false
  if (looksLikeIP(host)) return true
  return allowName && !host.includes(':')
}

function portNumber(value: string): number | null {
  if (!/^\d+$/.test(value)) return null
  const port = Number(value)
  return port >= 1 && port <= 65535 ? port : null
}

export const PEM_MAX_BYTES = 64 * 1024

// Envelope validation only; the server verifies X.509 parsing and key matching.
export function validatePEM(value: string, kind: 'cert' | 'key' | 'ca'): string | null {
  const label = { cert: '证书', key: '私钥', ca: 'CA' }[kind]
  if (new TextEncoder().encode(value).length > PEM_MAX_BYTES) return `${label}不能超过 64 KiB。`
  const text = value.trim()
  if (!text) return null
  const pattern = /-----BEGIN (CERTIFICATE|PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END \1-----/g
  const blocks = [...text.matchAll(pattern)]
  const complete = blocks.length > 0 && !text.replace(pattern, '').trim()
  const correctKind = blocks.every(block => kind === 'key' ? block[1] !== 'CERTIFICATE' : block[1] === 'CERTIFICATE')
  if (!complete || !correctKind || (kind === 'key' && blocks.length !== 1)) return `${label}需要完整 PEM（含 BEGIN / END）；私钥须未加密。`
  return null
}

export function validateNode(input: { name: string; role: string; address: string; port: string; listen: string; listenPort?: string; protocol?: string; transport: string; security: string; cert: string; key: string; ca: string }): string | null {
  const name = input.name.trim()
  if (!name || name.length > 128) return '节点名称需要 1 到 128 个字符。'
  if (input.role !== 'server' && input.role !== 'client') return '角色只能是公网网关或内网节点。'
  if (input.role === 'server') {
    if (!validHost(input.address, true)) return '网关地址要是域名或 IP，不要带协议和端口。'
    if (portNumber(input.port) === null) return '客户端接入端口要在 1 到 65535 之间。'
  }
  if (input.role === 'client') return null
  if (input.listen.trim() && !looksLikeIP(input.listen.trim())) return '隧道监听地址必须是 IP，例如 0.0.0.0、127.0.0.1 或 ::。'
  if (portNumber(input.listenPort || '') === null) return '本地监听端口要在 1 到 65535 之间。'
  const protocol = input.protocol || (input.transport === 'hysteria2' ? 'hysteria2' : 'vless')
  const tls = protocol === 'hysteria2' || input.transport === 'hysteria2' || input.security === 'tls'
  if (protocol === 'hysteria2' && (input.transport !== 'quic' && input.transport !== 'hysteria2' || input.security !== 'tls')) return 'Hysteria2 只能使用 QUIC 和 TLS。'
  if (protocol === 'hysteria2' && input.transport === 'xhttp') return 'Hysteria2 不支持 XHTTP。'
  if (protocol === 'hysteria2' && input.security === 'reality') return 'Hysteria2 不支持 REALITY。'
  if (tls) {
    if (!input.cert.trim() || !input.key.trim()) return 'TLS / Hysteria2 需要完整的证书和私钥 PEM。'
    for (const kind of ['cert', 'key'] as const) {
      const problem = validatePEM(input[kind], kind)
      if (problem) return problem
    }
  }
  if (tls) {
    const problem = validatePEM(input.ca, 'ca')
    if (problem) return problem
  }
  return null
}

export function validateMapping(
  input: { name: string; serverId: string; clientId: string; connectEndpointId?: string; pool: number; listenHost: string; listenPort: string; targetHost: string; targetPort: string; network?: string; enabled?: boolean },
  nodes: Node[],
  mappings: Mapping[],
  selfId = '',
): string | null {
  const name = input.name.trim()
  if (!name || name.length > 128) return '映射名称需要 1 到 128 个字符。'
  const net = (input.network || 'tcp').toLowerCase()
  if (net !== 'tcp' && net !== 'udp') return '网络协议只能是 TCP 或 UDP。'
  const server = nodes.find((node) => node.id === input.serverId && node.role === 'server' && !node.revoked)
  const client = nodes.find((node) => node.id === input.clientId && node.role === 'client' && !node.revoked)
  if (!server || !client) return '请选择可用的服务端和客户端。'
  const candidates = server.connect_endpoints?.length ? server.connect_endpoints : server.address && server.port ? [{ id: 'primary', enabled: true }] : []
  if (!candidates.some(candidate => candidate.enabled)) return '所选服务端没有启用的客户端连接地址，请先编辑服务端。'
  if (input.connectEndpointId && !candidates.some(candidate => candidate.enabled && candidate.id === input.connectEndpointId)) return '所选连接地址已停用、删除或不属于此服务端，请重新选择。'
  if (!Number.isInteger(input.pool) || input.pool < 1 || input.pool > 32) return 'Pool 范围为 1–32。'
  if (!looksLikeIP(input.listenHost.trim())) return '公网监听地址必须是 IP。0.0.0.0 表示全部 IPv4 接口。'
  const listenPort = portNumber(input.listenPort)
  const targetPort = portNumber(input.targetPort)
  if (listenPort === null || targetPort === null) return '端口要在 1 到 65535 之间。'
  if (!validHost(input.targetHost, true)) return '内网目标要是节点能访问的域名或 IP，不要带协议和端口。'
  const tunnelNet = server.tunnel?.hysteria2?.password ? 'udp' : 'tcp'
  const tunnelHost = server.tunnel?.listen_host?.trim() || '127.0.0.1'
  const tunnelPort = server.tunnel?.listen_port
  const mappingHost = input.listenHost.trim()
  const overlap = listenOverlap(mappingHost, tunnelHost)
  if (net === tunnelNet && listenPort === tunnelPort && overlap) return '监听地址与服务端本地隧道监听冲突。'
  if (input.enabled === false) return null
  const listenHost = input.listenHost.trim()
  const clash = mappings.find((mapping) => {
    if (!mapping.enabled || mapping.id === selfId || mapping.listen_port !== listenPort) return false
    const mappingNet = (mapping.network || 'tcp').toLowerCase()
    if (mappingNet !== net) return false
    if (mapping.server_id !== input.serverId) return false
    return listenOverlap(mapping.listen_host, listenHost)
  })
  if (clash) return `与已启用的「${clash.name}」在同一网关和端口上重叠。`
  return null
}

export async function copyText(value: string): Promise<void> {
  if (!navigator.clipboard?.writeText) throw new Error('无法写入剪贴板，请手动选择文本。')
  await navigator.clipboard.writeText(value)
}

export function logLevelTone(level: string): Tone {
  switch (level) {
    case 'ERROR': return 'bad'
    case 'WARN': return 'warn'
    default: return 'good'
  }
}
