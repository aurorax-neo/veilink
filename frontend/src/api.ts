// 同源 API 封装：/api/v1 前缀 + 管理员邮箱/密码会话认证（HttpOnly Cookie + Bearer）+ 首次安装引导锁

const API_PREFIX = '/api/v1'
const SESSION_STORAGE = 'veilink_session_token'

export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

function browserStorage(kind: 'session' | 'local'): Storage | null {
  try {
    const root = typeof window !== 'undefined' ? window : globalThis
    const store = kind === 'session' ? root.sessionStorage : root.localStorage
    return store ?? null
  } catch {
    return null
  }
}

export function getSessionToken(): string | null {
  return browserStorage('session')?.getItem(SESSION_STORAGE) || null
}

export function setSessionToken(token: string): void {
  browserStorage('session')?.setItem(SESSION_STORAGE, token)
  browserStorage('local')?.removeItem(SESSION_STORAGE)
  browserStorage('local')?.removeItem('veilink_api_key')
  browserStorage('session')?.removeItem('veilink_api_key')
}

export function clearSessionToken(): void {
  browserStorage('session')?.removeItem(SESSION_STORAGE)
  browserStorage('local')?.removeItem(SESSION_STORAGE)
  browserStorage('session')?.removeItem('veilink_api_key')
  browserStorage('local')?.removeItem('veilink_api_key')
}

export function buildUrl(path: string): string {
  return `/${path.replace(/^\/+/, '')}`
}

let onUnauthorized: () => void = () => {}

export function setUnauthorized(handler: () => void) {
  onUnauthorized = handler
}

const PUBLIC_AUTH_PATHS = new Set(['/auth/status', '/auth/setup', '/auth/login'])

export async function api<T>(path: string, method = 'GET', data?: unknown): Promise<T> {
  const token = getSessionToken()
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (token) headers['Authorization'] = `Bearer ${token}`
  if (method !== 'GET' && data !== undefined) headers['Content-Type'] = 'application/json'

  const res = await fetch(buildUrl(`${API_PREFIX}${path}`), {
    method,
    headers,
    credentials: 'same-origin',
    body: data !== undefined ? JSON.stringify(data) : undefined,
  })

  const isPublicAuth = PUBLIC_AUTH_PATHS.has(path)

  if (res.status === 401 && !isPublicAuth) {
    clearSessionToken()
    onUnauthorized()
    throw new ApiError('登录会话已失效，请重新登录', 401)
  }

  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: string }
    if (body?.error && typeof body.error === 'string' && body.error.trim()) {
      throw new ApiError(body.error, res.status)
    }
    if (res.status === 400 && (method === 'POST' || method === 'PUT') && /^\/nodes(?:\/[^/]+)?$/.test(path)) {
      throw new ApiError(
        '节点保存失败：请核对字段、端口和配对模板。TLS 核对证书/私钥、CA 与连接地址；plain 必须有 VLESS Encryption；REALITY 核对密钥、Short ID 与域名；Hysteria2 核对 TLS 与密码且不能配 REALITY；XHTTP 核对路径、模式与安全组合；Vision 仅支持 TCP + TLS/REALITY。',
        400,
      )
    }
    const hints: Record<number, string> = {
      400: '请求无效或资源冲突，请检查字段、端口占用及关联配置。',
      401: '认证失败，请核对凭据后重试。',
      403: '没有执行该操作的权限或安装已锁定。',
      404: '请求的资源不存在。',
      409: '请求状态冲突，请刷新页面后重试。',
      429: '尝试过于频繁，请稍后再试。',
    }
    throw new ApiError(hints[res.status] || `请求失败 (${res.status})`, res.status)
  }

  const localNowMs = Date.now()
  let serverTimeMs: number | null = null
  const rawServerMs = res.headers?.get?.('x-server-time-ms')
  if (rawServerMs) {
    const parsedMs = Number(rawServerMs)
    if (Number.isFinite(parsedMs) && parsedMs > 0) serverTimeMs = parsedMs
  }
  if (serverTimeMs === null) {
    const rawDate = res.headers?.get?.('date')
    if (rawDate) {
      const parsedDate = Date.parse(rawDate)
      if (Number.isFinite(parsedDate) && parsedDate > 0) {
        // HTTP Date header has 1-second resolution; add 999ms so sub-second heartbeats never appear in the future.
        serverTimeMs = parsedDate + 999
      }
    }
  }
  const clockHost = globalThis as {
    __VEILINK_CLOCK_OFFSET_MS__?: number
    __VEILINK_SERVER_FLOOR_MS__?: number
  }
  if (serverTimeMs !== null) {
    clockHost.__VEILINK_CLOCK_OFFSET_MS__ = serverTimeMs - localNowMs
    clockHost.__VEILINK_SERVER_FLOOR_MS__ = Math.max(clockHost.__VEILINK_SERVER_FLOOR_MS__ || 0, serverTimeMs)
  }

  if (res.status === 204) return null as T
  const text = await res.text()
  if (!text) return null as T
  const parsed = JSON.parse(text)
  const effectiveNowMs =
    serverTimeMs !== null
      ? serverTimeMs
      : Date.now() + (typeof clockHost.__VEILINK_CLOCK_OFFSET_MS__ === 'number' ? clockHost.__VEILINK_CLOCK_OFFSET_MS__ : 0)
  const nowSec = Math.floor(effectiveNowMs / 1000)
  const clampLastSeen = (item: unknown) => {
    if (item && typeof item === 'object' && typeof (item as Record<string, unknown>).last_seen === 'number') {
      const rec = item as Record<string, number>
      if (rec.last_seen > nowSec) rec.last_seen = nowSec
    }
  }
  if (Array.isArray(parsed)) parsed.forEach(clampLastSeen)
  else clampLastSeen(parsed)
  return parsed as T
}

export interface VersionInfo {
  api_version: string
  backend_version: string
  web_version: string
  web_mode?: string
}

export async function getVersionInfo(): Promise<VersionInfo> {
  const res = await fetch(buildUrl('/api/version'), { credentials: 'same-origin' })
  if (!res.ok) {
    throw new Error(`获取版本失败: ${res.status}`)
  }
  return res.json()
}

export async function checkApiCompatibility(): Promise<void> {
  const res = await getVersionInfo()
  const REQUIRED = 'v1'
  if (res.api_version !== REQUIRED) {
    throw new Error(`后端 API 版本不兼容：需要 ${REQUIRED}，实际 ${res.api_version}`)
  }
}
