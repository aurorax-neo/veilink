export interface RealityConfig {
  dest?: string
  private_key?: string
  public_key?: string
  short_id?: string
  short_ids?: string
  server_names?: string
  fingerprint?: string
  max_time_diff?: string
  spider_x?: string
  spider_y?: string
  mldsa65_verify?: string
  mldsa65_seed?: string
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

export interface XhttpConfig {
  host?: string
  path: string
  download_endpoint_id?: string
  mode: 'packet-up' | 'stream-up' | 'stream-one' | 'auto'
  tls: boolean
  headers?: Record<string, string>
  http_version?: '1.1' | '2' | '3'
  max_each_post_bytes?: number
  post_bytes_max?: number
  max_buffered_posts?: number
  max_concurrent_posts?: number
  uplink_data_placement?: 'body' | 'header' | 'cookie'
  uplink_data_key?: string
  uplink_chunk_size?: number
  xmux?: {
    max_concurrency?: number
    max_connections?: number
    c_max_reuse_times?: number
    h_max_request_times?: number
    h_max_reusable_secs?: number
    keep_alive_period?: number
  }
  stream_up_server_secs?: number
  stream_up_server_max_secs?: number
  request_timeout_seconds?: number
  padding_bytes?: number
  padding_max_bytes?: number
  padding_obfs_mode?: boolean
  padding_placement?: 'query_in_header' | 'query' | 'header' | 'cookie'
  padding_key?: string
  padding_header?: string
  padding_method?: 'repeat-x' | 'tokenish'
  no_grpc_header?: boolean
  no_sse_header?: boolean
  server_max_header_bytes?: number
  uplink_http_method?: 'POST' | 'PUT' | 'OPTIONS'
  min_posts_interval_ms?: number
  max_posts_interval_ms?: number
  session_id_placement?: 'path' | 'query' | 'header' | 'cookie'
  session_id_key?: string
  seq_placement?: 'path' | 'query' | 'header' | 'cookie'
  seq_key?: string
  session_id_table?: string
  session_id_length?: number
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
  xhttp?: XhttpConfig
}

export interface Node {
  id: string
  name: string
  role: 'server' | 'client' | string
  mode?: 'online' | 'offline' | ''
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
  exported_revision?: number
  last_seen: number
  error: string
}

export interface Mapping {
  bandwidth_limit?: string
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

export interface EndpointStatus {
  acknowledged: boolean
  reason: string
  linked?: boolean
}

export interface MappingStatus {
  server: EndpointStatus
  client: EndpointStatus
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
  online_servers?: number
  online_clients?: number
  online_nodes?: number
  offline_nodes?: number
  total_nodes: number
  total_mappings?: number
  enabled_mappings?: number
  active_mappings?: number
}

export interface AuthUser {
  email: string
  role?: string
  created_at: string
  updated_at?: string
  last_login?: string
  active_sessions?: number
}

export interface AuthStatusResponse {
  installed: boolean
  locked: boolean
  single_admin_only: boolean
  secret_file_hint: string
  authenticated: boolean
  user?: AuthUser | null
}

export interface WebStatus {
  mode: string
  active_version: string
  serving: boolean
  prebundled: boolean
}

export interface MasterServiceConfig {
  listen_addr: string
  scheme: 'http' | 'https'
  cert_file: string
  key_file: string
}

export interface JoinResult {
  prepare?: string
  command: string
  binary_command?: string
  offline_command?: string
  offline_binary_command?: string
  bootstrap_state?: string
  state_json?: string
  expires_at: number
  token: string
  warning: string
}

export interface OfflineExportResult {
  mode: 'offline'
  node_id: string
  role: string
  revision: number
  exported_revision: number
  filename: string
  config_path: string
  prepare: string
  command: string
  file_command: string
  binary_command: string
  inline_binary_command: string
  offline_state: string
  state_json: string
}

export type PageId = 'dashboard' | 'servers' | 'clients' | 'proxies' | 'logs' | 'audit' | 'settings'
export type LocaleCode = 'zh-CN' | 'en' | 'de' | 'id' | 'th' | 'vi' | 'ar'
export type ThemeMode = 'dark' | 'light'

export const PAGE_IDS: readonly PageId[] = [
  'dashboard',
  'servers',
  'clients',
  'proxies',
  'logs',
  'audit',
  'settings',
] as const

export function pageFromHash(hash = typeof location !== 'undefined' ? location.hash : ''): PageId {
  const id = hash.replace(/^#\/?/, '') as PageId
  if ((PAGE_IDS as readonly string[]).includes(id)) {
    try {
      globalThis.sessionStorage?.setItem('veilink_page', id)
      globalThis.localStorage?.setItem('veilink_page', id)
    } catch { /* ignore */ }
    return id
  }
  try {
    const saved = (globalThis.sessionStorage?.getItem('veilink_page') || globalThis.localStorage?.getItem('veilink_page')) as PageId | null
    if (saved && (PAGE_IDS as readonly string[]).includes(saved)) return saved
  } catch { /* ignore */ }
  return 'dashboard'
}

export function readStoredTab<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const saved = (globalThis.sessionStorage?.getItem(key) ?? globalThis.localStorage?.getItem(key)) as T | null
    if (saved !== null && allowed.includes(saved)) return saved
  } catch { /* ignore */ }
  return fallback
}

export function writeStoredTab(key: string, value: string): void {
  try {
    globalThis.sessionStorage?.setItem(key, value)
    globalThis.localStorage?.setItem(key, value)
  } catch { /* ignore */ }
}
