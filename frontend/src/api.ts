export class ApiError extends Error {
  status: number
  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

let csrf = ''
let onUnauthorized: (path: string) => void = () => {}

export function setCsrf(value: string) {
  csrf = value
}

export function clearCsrf() {
  csrf = ''
}

export function setUnauthorized(handler: (path: string) => void) {
  onUnauthorized = handler
}

export async function api<T>(path: string, method = 'GET', data?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json'
    if (csrf) headers['X-CSRF-Token'] = csrf
  }
  let response: Response
  try {
    response = await fetch('/api' + path, {
      method,
      credentials: 'same-origin',
      headers,
      body: data === undefined ? undefined : JSON.stringify(data),
      cache: 'no-store',
    })
  } catch {
    throw new ApiError('无法连接管理中心，请检查网络后重试。', 0)
  }
  let body: { error?: string } | null = null
  try {
    body = await response.json()
  } catch {
    throw new ApiError('管理中心未返回有效 JSON，请确认 API 服务已启动。', response.status)
  }
  if (!response.ok) {
    if (response.status === 401 && path !== '/login') onUnauthorized(path)
    const hints: Record<number, string> = {
      400: '请求无效或资源冲突，请检查字段、端口占用及关联配置。',
      401: path === '/login' ? '账号或密码不正确。' : '会话已失效，请重新登录。',
      403: '安全校验失败，请刷新页面并重新登录。',
      429: '请求过于频繁，请稍后重试。',
    }
    throw new ApiError(hints[response.status] || body?.error || `请求失败（${response.status}）`, response.status)
  }
  return body as T
}
