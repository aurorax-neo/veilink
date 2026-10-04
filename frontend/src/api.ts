// 统一 API 封装：服务地址配置 + /api/v1 前缀 + API Key 认证 + 401 自动跳登录

const API_PREFIX = '/api/v1';
const KEY_STORAGE = 'veilink_api_key';
const SERVER_STORAGE = 'veilink_server_url';
export class ApiError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

function safeStorage(): Storage | null {
  try {
    if (typeof window !== 'undefined' && window.localStorage) return window.localStorage;
    if (typeof localStorage !== 'undefined') return localStorage;
  } catch {}
  return null;
}

export function getApiKey(): string | null {
  return safeStorage()?.getItem(KEY_STORAGE) || null;
}

export function setApiKey(key: string): void {
  safeStorage()?.setItem(KEY_STORAGE, key);
}

export function clearApiKey(): void {
  safeStorage()?.removeItem(KEY_STORAGE);
}

export function getDefaultServerUrl(): string {
  try {
    if (typeof window !== 'undefined' && window.location?.origin) {
      return window.location.origin.replace(/\/+$/, '');
    }
  } catch {}
  return '';
}

export function getServerUrl(): string {
  const stored = safeStorage()?.getItem(SERVER_STORAGE);
  if (stored && stored.trim()) {
    return stored.trim().replace(/\/+$/, '');
  }
  return getDefaultServerUrl();
}

export function setServerUrl(url: string): void {
  const clean = (url || '').trim().replace(/\/+$/, '');
  if (!clean || clean === getDefaultServerUrl()) {
    safeStorage()?.removeItem(SERVER_STORAGE);
  } else {
    safeStorage()?.setItem(SERVER_STORAGE, clean);
  }
}

export function clearServerUrl(): void {
  safeStorage()?.removeItem(SERVER_STORAGE);
}

export function hasCustomServerUrl(): boolean {
  return !!safeStorage()?.getItem(SERVER_STORAGE);
}

export function buildUrl(path: string): string {
  const base = getServerUrl();
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return base ? `${base}${normalizedPath}` : normalizedPath;
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

  const res = await fetch(buildUrl(`${API_PREFIX}${path}`), {
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
    const hints: Record<number, string> = {
      400: '请求无效或资源冲突，请检查字段、端口占用及关联配置。',
      403: '没有执行该操作的权限。',
      404: '请求的资源不存在。',
      409: '请求无效或资源冲突。',
      429: '请求过于频繁，请稍后重试。',
    };
    if (res.status === 400 && (method === 'POST' || method === 'PUT') && /^\/nodes(?:\/[^/]+)?$/.test(path)) {
      throw new ApiError('节点保存失败：请核对字段、端口和配对模板。TLS 核对证书/私钥、CA 与连接地址；plain 必须有 VLESS Encryption；REALITY 核对密钥、Short ID 与域名；Hysteria2 核对 TLS 与密码且不能配 REALITY；XHTTP 支持 packet-up、stream-up、stream-one，核对规范路径、连接 HTTPS 与回源安全，HTTP 须 Encryption；流模式仅允许直连 HTTPS + TLS 回源的 HTTP/2 或 HTTP/3；Vision 仅支持 TCP + TLS/REALITY。', 400);
    }
    const body = await res.json().catch(() => ({}));
    throw new ApiError(hints[res.status] || body?.error || `请求失败 (${res.status})`, res.status);
  }
  if (res.status === 204) return null as T;
  const text = await res.text();
  if (!text) return null as T;
  return JSON.parse(text) as T;
}

export interface VersionInfo {
  api_version: string;
  backend_version: string;
  web_version: string;
  web_mode?: string;
}

export async function getVersionInfo(): Promise<VersionInfo> {
  const res = await fetch(buildUrl('/api/version'));
  if (!res.ok) {
    throw new Error(`获取版本失败: ${res.status}`);
  }
  return res.json();
}

// 启动时检查 API 契约版本
export async function checkApiCompatibility(): Promise<void> {
  const res = await getVersionInfo();
  const REQUIRED = 'v1';
  if (res.api_version !== REQUIRED) {
    throw new Error(`后端 API 版本不兼容：需要 ${REQUIRED}，实际 ${res.api_version}`);
  }
}
