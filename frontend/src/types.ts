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

export interface ConnectEndpoint {
  id: string
  name: string
  host: string
  port: number
  enabled: boolean
}

export interface TunnelConfig {
  protocol?: 'vless' | 'hysteria2' | ''
  transport_security?: 'tls' | 'plain' | ''
  cert_pem?: string
  key_pem?: string
  ca_pem?: string
  listen_host?: string
  listen_port?: number
  flow?: string
  decryption?: string
  encryption?: string
  reality?: RealityConfig
  hysteria2?: Hysteria2Config
  xhttp?: { path: string; mode: 'packet-up'; tls: boolean }
}

export interface Node {
  id: string
  name: string
  role: 'server' | 'client' | string
  address: string
  port: number
  connect_endpoints?: ConnectEndpoint[]
  tunnel?: TunnelConfig
  client_tunnel?: TunnelConfig
  embedded?: boolean
  software_version?: string
  software_commit?: string
  revoked: boolean
  desired_revision: number
  applied_revision: number
  last_seen: number
  error: string
}

export interface Mapping {
  id: string
  name: string
  server_id: string
  client_id: string
  connect_endpoint_id?: string
  pool: number
  mux: boolean
  mux_type?: string
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
}

export type PageId = 'dashboard' | 'servers' | 'clients' | 'proxies' | 'logs' | 'audit'

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
