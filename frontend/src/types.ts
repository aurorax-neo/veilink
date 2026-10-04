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
  xhttp?: { host?: string; path: string; download_endpoint_id?: string; mode: 'packet-up' | 'stream-up' | 'stream-one' | 'auto'; tls: boolean; headers?: Record<string, string>; http_version?: '1.1' | '2' | '3'; max_each_post_bytes?: number; post_bytes_max?: number; max_buffered_posts?: number; max_concurrent_posts?: number; uplink_data_placement?: 'body' | 'header' | 'cookie'; uplink_data_key?: string; uplink_chunk_size?: number; xmux?: { max_concurrency?: number; max_connections?: number; c_max_reuse_times?: number; h_max_request_times?: number; h_max_reusable_secs?: number; keep_alive_period?: number }; stream_up_server_secs?: number; stream_up_server_max_secs?: number; request_timeout_seconds?: number; padding_bytes?: number; padding_max_bytes?: number; padding_obfs_mode?: boolean; padding_placement?: 'query_in_header' | 'query' | 'header' | 'cookie'; padding_key?: string; padding_header?: string; padding_method?: 'repeat-x' | 'tokenish'; no_grpc_header?: boolean; no_sse_header?: boolean; server_max_header_bytes?: number; uplink_http_method?: 'POST' | 'PUT'; min_posts_interval_ms?: number; max_posts_interval_ms?: number; session_id_placement?: 'path' | 'query' | 'header' | 'cookie'; session_id_key?: string; seq_placement?: 'path' | 'query' | 'header' | 'cookie'; seq_key?: string; session_id_table?: string; session_id_length?: number }
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
  disabled?: boolean
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
export interface TrafficRow {
  mapping_id: string
  up_bytes: number
  down_bytes: number
  reported_at: string | null
  has_transfer: boolean
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

export type PageId = 'dashboard' | 'servers' | 'clients' | 'proxies' | 'logs' | 'audit' | 'settings'

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
  settings: {
    title: '设置',
    kicker: 'SETTINGS',
    lead: '前端版本与下载加速配置。',
    icon: '⚙',
  },
}

export function pageFromHash(hash = location.hash): PageId {
  const id = hash.replace(/^#\/?/, '') as PageId
  return id in pages ? id : 'dashboard'
}
