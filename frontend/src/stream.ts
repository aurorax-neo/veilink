// frontend/src/stream.ts — SSE 订阅封装（替换所有 WebSocket 代码）
import { api, buildUrl } from './api';

type EventHandler = (data: any) => void;

export class VeilinkStream {
  private es: EventSource | null = null;
  private handlers = new Map<string, Set<EventHandler>>();
  private url: string;

  constructor() {
    this.url = '';
  }

  /** 连接。先换一次性 token，再建 EventSource */
  async connect(types?: string[]) {
    this.disconnect();

    // 1. 用 API Key 换一次性 token（解决 EventSource 不能带 Header）
    const { token } = await api<{ token: string }>('/stream/token', 'POST');

    // 2. 建连
    const params = new URLSearchParams({ token });
    if (types?.length) params.set('types', types.join(','));
    this.url = buildUrl(`/api/v1/stream?${params}`);
    this.es = new EventSource(this.url);

    this.es.addEventListener('hello', () => {
      console.debug('[stream] connected');
    });

    // 3. 分发事件到订阅者
    this.es.onmessage = (e) => this.dispatch('message', e.data);
    for (const type of ['log', 'node', 'tunnel', 'stats']) {
      this.es.addEventListener(type, (e: MessageEvent) => {
        try {
          this.dispatch(type, JSON.parse(e.data));
        } catch { /* 忽略坏数据 */ }
      });
    }

    this.es.onerror = () => {
      // 浏览器会自动重连，这里只打日志
      console.debug('[stream] reconnecting...');
    };
  }

  on(type: string, fn: EventHandler): () => void {
    if (!this.handlers.has(type)) this.handlers.set(type, new Set());
    this.handlers.get(type)!.add(fn);
    return () => this.handlers.get(type)?.delete(fn);
  }

  private dispatch(type: string, data: any) {
    this.handlers.get(type)?.forEach(fn => {
      try { fn(data); } catch (e) { console.error(e); }
    });
  }

  disconnect() {
    this.es?.close();
    this.es = null;
  }
}

// 单例
export const stream = new VeilinkStream();

// --- 用法示例（LogsView.vue） ---
// import { stream } from '@/stream';
// onMounted(async () => {
//   await stream.connect(['log']);
//   const off = stream.on('log', (entry) => appendLog(entry));
//   onUnmounted(() => { off(); });
// });
