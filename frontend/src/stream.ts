// frontend/src/stream.ts — SSE 订阅封装（替换所有 WebSocket 代码）
import { api, buildUrl } from './api';

type EventHandler = (data: any) => void;

export class VeilinkStream {
  private es: EventSource | null = null;
  private handlers = new Map<string, Set<EventHandler>>();
  private url: string;
  private types?: string[];
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private active = false;
  private generation = 0;

  constructor() {
    this.url = '';
  }

  /** 连接。先换一次性 token，再建 EventSource */
  async connect(types?: string[]) {
    this.clearReconnect();
    this.es?.close();
    this.es = null;
    this.types = types ? [...types] : undefined;
    this.active = true;
    const gen = ++this.generation;

    // 1. 用 API Key 换一次性 token（解决 EventSource 不能带 Header）
    const { token } = await api<{ token: string }>('/stream/token', 'POST');
    if (!this.active || gen !== this.generation) return;

    // 2. 建连
    const params = new URLSearchParams({ token });
    if (this.types?.length) params.set('types', this.types.join(','));
    this.url = buildUrl(`/api/v1/stream?${params}`);
    const es = new EventSource(this.url);
    this.es = es;

    es.addEventListener('hello', () => {
      console.debug('[stream] connected');
    });

    // 3. 分发事件到订阅者
    es.onmessage = (e) => this.dispatch('message', e.data);
    for (const type of ['log', 'node', 'tunnel', 'stats']) {
      es.addEventListener(type, (e: MessageEvent) => {
        try {
          this.dispatch(type, JSON.parse(e.data));
        } catch { /* 忽略坏数据 */ }
      });
    }

    es.onerror = () => {
      // 一次性 token 已在建连时被服务端消费，必须关闭旧连接并重新换票
      if (this.es === es) {
        es.close();
        this.es = null;
      }
      if (!this.active || gen !== this.generation || this.reconnectTimer !== null) return;
      console.debug('[stream] reconnecting with fresh token...');
      this.reconnectTimer = setTimeout(() => {
        this.reconnectTimer = null;
        if (!this.active || gen !== this.generation) return;
        void this.connect(this.types).catch(() => {});
      }, 1500);
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

  private clearReconnect() {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
  }

  disconnect() {
    this.active = false;
    this.generation++;
    this.clearReconnect();
    this.es?.close();
    this.es = null;
  }
}

// 单例
export const stream = new VeilinkStream();
