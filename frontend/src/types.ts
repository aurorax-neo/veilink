export interface RealityConfig {
  dest?: string
  private_key?: string
  public_key?: string
  short_id?: string
  short_ids?: string
  server_names?: string
  fingerprint?: string
  max_time_diff?: string
}

export interface Hysteria2Config {
  password?: string
}

export interface TunnelConfig {
  cert_file?: string
  key_file?: string
  ca_file?: string
  listen_host?: string
  flow?: string
  decryption?: string
  encryption?: string
  pool?: number
  reality?: RealityConfig
  hysteria2?: Hysteria2Config
}

export interface Node {
  id: string
  name: string
  role: 'server' | 'client' | string
  address: string
  port: number
  server_name: string
  tunnel?: TunnelConfig
  revoked: boolean
  desired_revision: number
  applied_revision: number
  last_seen: number
  error: string
}

export interface Binding {
  id: string
  server_id: string
  client_id: string
  domain: string
}

export interface Mapping {
  id: string
  name: string
  binding_id: string
  listen_host: string
  listen_port: number
  target_host: string
  target_port: number
  network?: string
  enabled: boolean
}

export interface Audit {
  at: number
  action: string
  object: string
}

export type PageId = 'overview' | 'nodes' | 'bindings' | 'mappings' | 'audit'

export const pages: Record<PageId, { title: string; kicker: string; lead: string }> = {
  overview: {
    title: '运行概览',
    kicker: 'CONTROL PLANE',
    lead: '心跳、配置版本和已登记通路。在线不是目标可达。',
  },
  nodes: {
    title: '节点',
    kicker: 'NODES',
    lead: '公网网关与内网节点分开登记。令牌只生成一次。',
  },
  bindings: {
    title: '网关绑定',
    kicker: 'BINDINGS',
    lead: '一条绑定是一对网关和内网节点，身份由管理中心生成，不能直接修改。',
  },
  mappings: {
    title: 'TCP 映射',
    kicker: 'MAPPINGS',
    lead: '从公网监听地址转到内网目标。启停都会下发配置，并可能断开现有连接。',
  },
  audit: {
    title: '审计',
    kicker: 'AUDIT',
    lead: '最近的管理写操作。删除节点与吊销共用同一条审计动作。',
  },
}

export function pageFromHash(hash = location.hash): PageId {
  const id = hash.replace(/^#\/?/, '') as PageId
  return id in pages ? id : 'overview'
}
