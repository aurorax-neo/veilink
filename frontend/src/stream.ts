// frontend/src/stream.ts — SSE 订阅与连接状态管理
import { api, buildUrl } from './api'

export type StreamState = 'disconnected' | 'connecting' | 'connected' | 'reconnecting'
type EventHandler = (data: unknown) => void
type StateHandler = (state: StreamState) => void

export class VeilinkStream {
  private es: EventSource | null = null
  private handlers = new Map<string, Set<EventHandler>>()
  private stateHandlers = new Set<StateHandler>()
  private state: StreamState = 'disconnected'
  private types?: string[]
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private active = false
  private generation = 0

  getState(): StreamState {
    return this.state
  }

  private setState(next: StreamState) {
    if (this.state === next) return
    this.state = next
    this.stateHandlers.forEach((fn) => {
      try { fn(next) } catch { /* ignore */ }
    })
  }

  onState(fn: StateHandler): () => void {
    this.stateHandlers.add(fn)
    fn(this.state)
    return () => { this.stateHandlers.delete(fn) }
  }

  async connect(types?: string[]) {
    this.clearReconnect()
    this.es?.close()
    this.es = null
    this.types = types ? [...types] : undefined
    this.active = true
    const gen = ++this.generation
    this.setState(this.state === 'reconnecting' ? 'reconnecting' : 'connecting')

    const { token } = await api<{ token: string }>('/stream/token', 'POST')
    if (!this.active || gen !== this.generation) return

    const params = new URLSearchParams({ token })
    if (this.types?.length) params.set('types', this.types.join(','))
    const url = buildUrl(`/api/v1/stream?${params}`)
    const es = new EventSource(url)
    this.es = es

    es.addEventListener('hello', () => {
      if (this.es === es && this.active) this.setState('connected')
    })

    es.onopen = () => {
      if (this.es === es && this.active) this.setState('connected')
    }

    es.onmessage = (e) => this.dispatch('message', e.data)
    for (const type of ['log', 'node', 'tunnel', 'stats']) {
      es.addEventListener(type, (e: MessageEvent) => {
        try {
          this.dispatch(type, JSON.parse(e.data))
        } catch { /* ignore malformed payload */ }
      })
    }

    es.onerror = () => {
      if (this.es === es) {
        es.close()
        this.es = null
      }
      if (!this.active || gen !== this.generation || this.reconnectTimer !== null) return
      this.setState('reconnecting')
      this.reconnectTimer = setTimeout(() => {
        this.reconnectTimer = null
        if (!this.active || gen !== this.generation) return
        void this.connect(this.types).catch(() => {
          if (this.active && gen === this.generation && this.reconnectTimer === null) {
            this.reconnectTimer = setTimeout(() => {
              this.reconnectTimer = null
              if (this.active && gen === this.generation) void this.connect(this.types).catch(() => {})
            }, 3000)
          }
        })
      }, 1500)
    }
  }

  on(type: string, fn: EventHandler): () => void {
    if (!this.handlers.has(type)) this.handlers.set(type, new Set())
    this.handlers.get(type)!.add(fn)
    return () => { this.handlers.get(type)?.delete(fn) }
  }

  private dispatch(type: string, data: unknown) {
    this.handlers.get(type)?.forEach((fn) => {
      try { fn(data) } catch (e) { console.error(e) }
    })
  }

  private clearReconnect() {
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
  }

  disconnect() {
    this.active = false
    this.generation++
    this.clearReconnect()
    this.es?.close()
    this.es = null
    this.setState('disconnected')
  }
}

export const stream = new VeilinkStream()
;(globalThis as Record<string, unknown>).__veilinkStream = stream
