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

export interface LogEntry {
  at: number
  level: string
  message: string
  source: string
  node_id?: string
}

export interface Stats {
  online_servers: number
  online_clients: number
  total_nodes: number
  active_mappings: number
  total_bindings: number
}

export type PageId = 'dashboard' | 'servers' | 'clients' | 'proxies' | 'bindings' | 'logs' | 'audit'

export const pages: Record<PageId, { title: string; kicker: string; lead: string; icon: string }> = {
  dashboard: {
    title: '仪表盘',
    kicker: 'DASHBOARD',
    lead: '系统概览和拓扑状态。',
    icon: '◉',
  },
  servers: {
    title: '服务端',
    kicker: 'SERVERS',
    lead: '公网网关节点。承载反向隧道入口和端口映射。',
    icon: '▲',
  },
  clients: {
    title: '客户端',
    kicker: 'CLIENTS',
    lead: '内网节点。主动连出到网关，转发流量到本地目标。',
    icon: '●',
  },
  proxies: {
    title: '端口映射',
    kicker: 'PROXIES',
    lead: '从公网监听地址转到内网目标。TCP 和 UDP 映射。',
    icon: '⇌',
  },
  bindings: {
    title: '绑定',
    kicker: 'BINDINGS',
    lead: '网关与内网节点的配对关系。',
    icon: '⊞',
  },
  logs: {
    title: '日志',
    kicker: 'LOGS',
    lead: '管理中心和节点的运行日志。',
    icon: '☰',
  },
  audit: {
    title: '审计',
    kicker: 'AUDIT',
    lead: '管理写操作记录。',
    icon: '✎',
  },
}

export function pageFromHash(hash = location.hash): PageId {
  const id = hash.replace(/^#\/?/, '') as PageId
  return id in pages ? id : 'dashboard'
}
