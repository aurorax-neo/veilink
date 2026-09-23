import type { Binding, Mapping, Node } from './types'

export type Tone = '' | 'good' | 'warn' | 'bad'

const actions: Record<string, string> = {
  'node.save': '保存节点',
  'node.revoke': '吊销或删除节点',
  'binding.create': '创建绑定',
  'binding.delete': '删除绑定',
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

export function bindingLabel(nodes: Node[], binding: Binding): string {
  return `${nodeName(nodes, binding.server_id)} → ${nodeName(nodes, binding.client_id)}`
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
  if (node.applied_revision === node.desired_revision) return { text: '版本一致', tone: 'good' }
  return { text: '待生效', tone: 'warn' }
}

export function attentionReasons(node: Node, now = Date.now()): string[] {
  if (node.revoked) return []
  const reasons: string[] = []
  if (node.error) reasons.push('应用失败')
  if (node.applied_revision !== node.desired_revision) reasons.push('版本未对齐')
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

export function validateNode(input: { name: string; role: string; address: string; port: string; serverName: string }): string | null {
  const name = input.name.trim()
  if (!name || name.length > 128) return '节点名称需要 1 到 128 个字符。'
  if (input.role !== 'server' && input.role !== 'client') return '角色只能是公网网关或内网节点。'
  if (input.role === 'client') return null
  if (!validHost(input.address, true)) return '网关地址要是域名或 IP，不要带协议和端口。'
  if (portNumber(input.port) === null) return 'VLESS 端口要在 1 到 65535 之间。'
  if (!validHost(input.serverName, true)) return 'TLS 服务器名称要是域名或 IP，不要带协议和端口。'
  return null
}

export function validateMapping(
  input: { name: string; bindingId: string; listenHost: string; listenPort: string; targetHost: string; targetPort: string; network?: string; enabled?: boolean },
  nodes: Node[],
  bindings: Binding[],
  mappings: Mapping[],
  selfId = '',
): string | null {
  const name = input.name.trim()
  if (!name || name.length > 128) return '映射名称需要 1 到 128 个字符。'
  const net = (input.network || 'tcp').toLowerCase()
  if (net !== 'tcp' && net !== 'udp') return '网络协议只能是 TCP 或 UDP。'
  const binding = bindings.find((item) => item.id === input.bindingId)
  if (!binding) return '请选择一条网关绑定。'
  if (!looksLikeIP(input.listenHost.trim())) return '公网监听地址必须是 IP。0.0.0.0 表示全部 IPv4 接口。'
  const listenPort = portNumber(input.listenPort)
  const targetPort = portNumber(input.targetPort)
  if (listenPort === null || targetPort === null) return '端口要在 1 到 65535 之间。'
  if (!validHost(input.targetHost, true)) return '内网目标要是节点能访问的域名或 IP，不要带协议和端口。'
  const server = nodes.find((node) => node.id === binding.server_id)
  if (net === 'tcp' && server && listenPort === server.port) return '公网监听端口不能与该网关的 VLESS 端口相同。'
  if (input.enabled === false) return null
  const listenHost = input.listenHost.trim()
  const clash = mappings.find((mapping) => {
    if (!mapping.enabled || mapping.id === selfId || mapping.listen_port !== listenPort) return false
    const mappingNet = (mapping.network || 'tcp').toLowerCase()
    if (mappingNet !== net) return false
    const other = bindings.find((item) => item.id === mapping.binding_id)
    if (!other || other.server_id !== binding.server_id) return false
    return mapping.listen_host === listenHost || mapping.listen_host === '0.0.0.0' || mapping.listen_host === '::' || listenHost === '0.0.0.0' || listenHost === '::'
  })
  if (clash) return `与已启用的「${clash.name}」在同一网关和端口上重叠。`
  return null
}

export async function copyText(value: string): Promise<void> {
  if (!navigator.clipboard?.writeText) throw new Error('无法写入剪贴板，请手动选择文本。')
  await navigator.clipboard.writeText(value)
}
