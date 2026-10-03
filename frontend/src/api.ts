// 统一 API 封装：/api/v1 前缀 + API Key 认证 + 401 自动跳登录

const API_PREFIX = '/api/v1';
const KEY_STORAGE = 'veilink_api_key';

export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export function getApiKey(): string | null {
  return localStorage.getItem(KEY_STORAGE);
}

export function setApiKey(key: string): void {
  localStorage.setItem(KEY_STORAGE, key);
}

export function clearApiKey(): void {
  localStorage.removeItem(KEY_STORAGE);
}

let onUnauthorized: () => void = () => {};

export function setUnauthorized(handler: () => void) {
  onUnauthorized = handler;
}

// 兼容旧签名：api(path, method, data)
export async function api<T>(path: string, method = 'GET', data?: unknown): Promise<T> {
  const key = getApiKey();
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (key) headers['Authorization'] = `Bearer ${key}`;
  if (method !== 'GET' && data !== undefined) headers['Content-Type'] = 'application/json';

  const res = await fetch(`${API_PREFIX}${path}`, {
    method,
    headers,
    body: data !== undefined ? JSON.stringify(data) : undefined,
  });

  if (res.status === 401) {
    clearApiKey();
    onUnauthorized();
    throw new ApiError('未授权，请重新输入 API Key', 401);
  }
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new ApiError(body.error || `请求失败 (${res.status})`, res.status);
  }
  if (res.status === 204) return null as T;
  const text = await res.text();
  if (!text) return null as T;
  return JSON.parse(text) as T;
}

// 启动时检查 API 契约版本
export async function checkApiCompatibility(): Promise<void> {
  const res = await fetch('/api/version').then(r => r.json());
  const REQUIRED = 'v1';
  if (res.api_version !== REQUIRED) {
    throw new Error(`后端 API 版本不兼容：需要 ${REQUIRED}，实际 ${res.api_version}`);
  }
}
