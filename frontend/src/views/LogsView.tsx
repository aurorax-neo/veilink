import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ArrowUp, Pause, Play, RefreshCw, Search, Terminal } from 'lucide-react'
import { api } from '../api'
import { useConsole } from '../context/ConsoleContext'
import { byNameAndId, formatTime, logLevelTone, nodeName } from '../format'
import { askNodes, nodeBaseline, nodeChanged, registerPageRefresh, waitForReports } from '../pageRefresh'
import { stream } from '../stream'
import type { LogEntry } from '../types'
import { Alert, Badge, EmptyState } from '../components/ui/Badge'
import { Segmented, Select } from '../components/ui/Controls'

type LogSource = 'all' | 'master' | 'node'
type LogLevel = '' | 'INFO' | 'WARN' | 'ERROR'

export function LogsView() {
  const { nodes, reloadNode, dict } = useConsole()

  const [source, setSource] = useState<LogSource>(() => {
    try {
      const s = globalThis.sessionStorage?.getItem('veilink_logs_source') || globalThis.localStorage?.getItem('veilink_logs_source')
      if (s === 'all' || s === 'master' || s === 'node') return s
    } catch { /* ignore */ }
    return 'all'
  })
  const [nodeId, setNodeId] = useState('')
  const [level, setLevel] = useState<LogLevel>(() => {
    try {
      const l = globalThis.sessionStorage?.getItem('veilink_logs_level') ?? globalThis.localStorage?.getItem('veilink_logs_level')
      if (l === '' || l === 'INFO' || l === 'WARN' || l === 'ERROR') return l
    } catch { /* ignore */ }
    return ''
  })
  const [query, setQuery] = useState('')
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [showJumpLatest, setShowJumpLatest] = useState(false)
  const [freshKeys, setFreshKeys] = useState<Set<string>>(() => new Set())

  const listRef = useRef<HTMLDivElement>(null)
  const seenKeysRef = useRef<Set<string>>(new Set())
  const initializedRef = useRef(false)
  const scrolledAwayRef = useRef(false)
  const reqIdRef = useRef(0)
  const activeRef = useRef(true)
  const nodesRef = useRef(nodes)
  nodesRef.current = nodes

  const sortedNodes = useMemo(() => [...nodes].sort(byNameAndId), [nodes])

  const sourceLabel = useCallback(
    (entry: LogEntry) => {
      if (entry.source === 'master') return 'Master'
      if (!entry.node_id) return entry.source || '节点'
      const role = nodes.find((n) => n.id === entry.node_id)?.role
      return `${role === 'server' ? 'Server' : role === 'client' ? 'Client' : '节点'} · ${nodeName(nodes, entry.node_id)}`
    },
    [nodes],
  )

  const fetchLogs = useCallback(
    async (opts?: { silent?: boolean }) => {
      const ticket = ++reqIdRef.current
      setError('')
      if (!opts?.silent) setLoading(true)
      try {
        const params = new URLSearchParams()
        if (source !== 'all') params.set('source', source)
        if (source === 'node' && nodeId) params.set('node_id', nodeId)
        if (level) params.set('level', level)
        params.set('limit', '500')
        const res = await api<LogEntry[]>(`/logs?${params.toString()}`)
        if (ticket === reqIdRef.current && activeRef.current) {
          const next = res || []
          const entryKey = (e: LogEntry) => `${e.at}|${e.source}|${e.node_id || ''}|${e.level}|${e.message}`
          if (initializedRef.current && opts?.silent) {
            const newlyArrived = new Set<string>()
            for (const e of next) {
              const k = entryKey(e)
              if (!seenKeysRef.current.has(k)) newlyArrived.add(k)
            }
            setFreshKeys(newlyArrived)
          } else {
            setFreshKeys(new Set())
            initializedRef.current = true
          }
          seenKeysRef.current = new Set(next.map(entryKey))
          setLogs(next)
          // Spec 7.2: Only auto-follow when user hasn't scrolled away into history
          if (!scrolledAwayRef.current && listRef.current) {
            listRef.current.scrollTop = 0
          }
        }
      } catch (err) {
        if (ticket === reqIdRef.current && activeRef.current) {
          setError(err instanceof Error ? err.message : '加载日志失败')
        }
      } finally {
        if (ticket === reqIdRef.current && !opts?.silent) setLoading(false)
      }
    },
    [source, nodeId, level],
  )

  useEffect(() => {
    activeRef.current = true
    void fetchLogs()
    const offLog = stream.on('log', () => {
      if (activeRef.current) void fetchLogs({ silent: true })
    })
    const unregister = registerPageRefresh(async () => {
      await fetchLogs()
      if (!activeRef.current || source === 'master') return
      const targetNodes = (source === 'node' && nodeId ? nodesRef.current.filter((n) => n.id === nodeId) : nodesRef.current).filter(
        (n) => !n.revoked,
      )
      const baseline = new Map(targetNodes.map((n) => [n.id, nodeBaseline(n)]))
      const connected = await askNodes(targetNodes.map((n) => n.id))
      await waitForReports(
        async () => {
          if (!activeRef.current) return
          await Promise.all(connected.map((id) => reloadNode(id).catch(() => {})))
          if (activeRef.current) await fetchLogs({ silent: true })
        },
        () => activeRef.current && connected.some((id) => !nodeChanged(nodesRef.current.find((n) => n.id === id), baseline.get(id)!)),
      )
    })
    return () => {
      activeRef.current = false
      offLog()
      unregister()
    }
  }, [fetchLogs, source, nodeId, reloadNode])

  useEffect(() => {
    if (!autoRefresh) return
    const timer = window.setInterval(() => void fetchLogs({ silent: true }), 5000)
    return () => window.clearInterval(timer)
  }, [autoRefresh, fetchLogs])

  const changeSource = (next: LogSource) => {
    setSource(next)
    try {
      globalThis.sessionStorage?.setItem('veilink_logs_source', next)
      globalThis.localStorage?.setItem('veilink_logs_source', next)
    } catch { /* ignore */ }
  }

  const changeLevel = (next: LogLevel) => {
    setLevel(next)
    try {
      globalThis.sessionStorage?.setItem('veilink_logs_level', next)
      globalThis.localStorage?.setItem('veilink_logs_level', next)
    } catch { /* ignore */ }
  }

  // Spec 7.2: <= 1 line (~32px) stays pinned; scrolling away yields; > 3 lines (~96px) shows "跳至最新"
  const handleScroll = () => {
    const el = listRef.current
    if (!el) return
    if (el.scrollTop <= 32) {
      scrolledAwayRef.current = false
      setShowJumpLatest(false)
    } else {
      scrolledAwayRef.current = true
      if (el.scrollTop > 96) setShowJumpLatest(true)
    }
  }

  const jumpLatest = () => {
    scrolledAwayRef.current = false
    setShowJumpLatest(false)
    if (listRef.current) listRef.current.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const filteredLogs = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return logs
    return logs.filter((entry) => [entry.message, entry.level, entry.source, sourceLabel(entry)].join(' ').toLowerCase().includes(q))
  }, [logs, query, sourceLabel])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="toolbar">
        <Segmented<LogSource>
          ariaLabel="日志来源"
          value={source}
          onChange={changeSource}
          options={[
            { value: 'all', label: dict.logs.sourceAll },
            { value: 'master', label: dict.logs.sourceMaster },
            { value: 'node', label: dict.logs.sourceNode },
          ]}
        />

        {source === 'node' && (
          <div style={{ minWidth: 190 }}>
            <Select
              ariaLabel="选择节点"
              value={nodeId}
              onChange={setNodeId}
              options={[{ value: '', label: '全部节点' }, ...sortedNodes.map((n) => ({ value: n.id, label: n.name }))]}
            />
          </div>
        )}

        <Segmented<LogLevel>
          ariaLabel="日志级别"
          value={level}
          onChange={changeLevel}
          options={[
            { value: '', label: dict.common.all },
            { value: 'INFO', label: 'INFO' },
            { value: 'WARN', label: 'WARN' },
            { value: 'ERROR', label: 'ERROR' },
          ]}
        />

        <div className="toolbar-search">
          <Search size={15} className="toolbar-search-icon" />
          <input
            type="search"
            value={query}
            aria-label="搜索日志"
            placeholder={dict.logs.searchPlaceholder}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>

        <button
          type="button"
          className={`btn btn-sm ${autoRefresh ? 'btn-soft' : ''}`}
          onClick={() => setAutoRefresh((v) => !v)}
        >
          {autoRefresh ? <Pause size={14} /> : <Play size={14} />}
          <span>{autoRefresh ? dict.logs.stopAutoRefresh : dict.logs.autoRefresh}</span>
        </button>

        <button type="button" className="btn btn-sm" disabled={loading} onClick={() => void fetchLogs()}>
          <RefreshCw size={14} className={loading ? 'spin' : ''} />
          <span>{dict.common.refresh}</span>
        </button>
      </div>

      {error && <Alert tone="bad">{error}</Alert>}

      <section className="panel">
        <header className="panel-head">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Terminal size={15} style={{ color: 'var(--accent-strong)' }} />
            <h2>实时内存事件流</h2>
          </div>
          <span className="cell-sub tabular">
            {filteredLogs.length} / {logs.length}
          </span>
        </header>

        {loading && logs.length === 0 ? (
          <EmptyState title="加载中…" />
        ) : filteredLogs.length === 0 ? (
          <EmptyState icon={<Terminal size={20} />} title={dict.logs.emptyTitle} />
        ) : (
          <div ref={listRef} className="log-viewport" onScroll={handleScroll}>
            {filteredLogs.map((entry, idx) => {
              const sig = `${entry.at}|${entry.source}|${entry.node_id || ''}|${entry.level}|${entry.message}`
              const animateNew = freshKeys.has(sig) && idx < 6
              return (
                <div
                  key={`${entry.at}-${entry.source}-${idx}`}
                  className={`log-row ${animateNew ? 'stream-reveal' : ''}`}
                  style={animateNew ? ({ '--stagger-index': idx } as React.CSSProperties) : undefined}
                >
                  <time
                    className="cell-sub tabular ltr-force"
                    dateTime={entry.at ? new Date(entry.at * 1000).toISOString() : undefined}
                  >
                    {entry.at ? formatTime(entry.at * 1000) : '时间未知'}
                  </time>
                  <div style={{ display: 'flex', gap: 5, alignItems: 'center', flexWrap: 'wrap' }}>
                    <Badge text={entry.level || 'INFO'} tone={logLevelTone(entry.level)} />
                    {entry.source && <Badge text={sourceLabel(entry)} />}
                  </div>
                  <span className="log-msg">{entry.message}</span>
                </div>
              )
            })}

            {showJumpLatest && (
              <button type="button" className="btn btn-sm btn-primary jump-latest-fab" onClick={jumpLatest}>
                <ArrowUp size={14} />
                <span>{dict.common.jumpToLatest}</span>
              </button>
            )}
          </div>
        )}
      </section>
    </div>
  )
}
