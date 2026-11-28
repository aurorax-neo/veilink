import { useEffect, useMemo, useState } from 'react'
import { Check, Copy, FileClock, RotateCcw, Search } from 'lucide-react'
import { useConsole } from '../context/ConsoleContext'
import { actionLabel, actionTone, copyText, formatTime, relativeAge, serverNowMs, triggerHaptic } from '../format'
import type { Audit, PageId } from '../types'
import { Badge, EmptyState } from '../components/ui/Badge'
import { Segmented } from '../components/ui/Controls'

type AuditCategory = 'all' | 'node' | 'mapping'
const PAGE_STEP = 100

export function AuditView() {
  const { audit, nodes, mappings, loaded, loading, error, navigate, toast, dict } = useConsole()
  const [category, setCategory] = useState<AuditCategory>(() => {
    try {
      const saved = globalThis.sessionStorage?.getItem('veilink_audit_category') || globalThis.localStorage?.getItem('veilink_audit_category')
      if (saved === 'all' || saved === 'node' || saved === 'mapping') return saved
    } catch { /* ignore */ }
    return 'all'
  })
  const [query, setQuery] = useState('')
  const [visibleLimit, setVisibleLimit] = useState(PAGE_STEP)
  const [now, setNow] = useState(() => serverNowMs())
  const [copiedKey, setCopiedKey] = useState('')

  useEffect(() => {
    const timer = window.setInterval(() => setNow(serverNowMs()), 10000)
    return () => window.clearInterval(timer)
  }, [])

  const renderNow = Math.max(now, serverNowMs())

  const changeCategory = (next: AuditCategory) => {
    setCategory(next)
    setVisibleLimit(PAGE_STEP)
    try {
      globalThis.sessionStorage?.setItem('veilink_audit_category', next)
      globalThis.localStorage?.setItem('veilink_audit_category', next)
    } catch { /* ignore */ }
  }

  const counts = useMemo(() => {
    let node = 0
    let mapping = 0
    for (const item of audit) {
      if (item.action.startsWith('node.')) node += 1
      else if (item.action.startsWith('mapping.')) mapping += 1
    }
    return { all: audit.length, node, mapping }
  }, [audit])

  const resolveTarget = (item: Audit): { kind: string; name: string; page: PageId | null } => {
    if (item.action.startsWith('node.')) {
      const n = nodes.find((x) => x.id === item.object)
      if (n) {
        return {
          kind: n.role === 'server' ? '公网网关' : '内网节点',
          name: n.name,
          page: n.role === 'client' ? 'clients' : 'servers',
        }
      }
      return { kind: '节点', name: '', page: null }
    }
    if (item.action.startsWith('mapping.')) {
      const m = mappings.find((x) => x.id === item.object)
      if (m) return { kind: '端口映射', name: m.name, page: 'proxies' }
      return { kind: '端口映射', name: '', page: null }
    }
    return { kind: '控制平面', name: '', page: null }
  }

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return audit.filter((item) => {
      if (category === 'node' && !item.action.startsWith('node.')) return false
      if (category === 'mapping' && !item.action.startsWith('mapping.')) return false
      if (!q) return true
      const target = resolveTarget(item)
      return [item.action, actionLabel(item.action), item.object, target.name, target.kind].join(' ').toLowerCase().includes(q)
    })
  }, [audit, category, query, nodes, mappings])

  const visibleRows = rows.slice(0, visibleLimit)
  const remaining = Math.max(0, rows.length - visibleRows.length)

  const handleCopyId = async (id: string, key: string) => {
    try {
      await copyText(id)
      triggerHaptic(10)
      setCopiedKey(key)
      window.setTimeout(() => setCopiedKey((curr) => (curr === key ? '' : curr)), 2500)
    } catch {
      toast('复制失败。', true)
    }
  }

  if (!loaded && loading) return <div className="panel"><EmptyState title="正在加载审计轨迹…" /></div>
  if (!loaded) return <div className="panel"><EmptyState title="加载失败" description={error} /></div>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="toolbar">
        <Segmented<AuditCategory>
          ariaLabel="审计分类"
          value={category}
          onChange={changeCategory}
          options={[
            { value: 'all', label: `${dict.audit.catAll} (${counts.all})` },
            { value: 'node', label: `${dict.audit.catNode} (${counts.node})` },
            { value: 'mapping', label: `${dict.audit.catMapping} (${counts.mapping})` },
          ]}
        />
        <div className="toolbar-search">
          <Search size={15} className="toolbar-search-icon" />
          <input
            type="search"
            value={query}
            aria-label="搜索审计"
            placeholder={dict.audit.searchPlaceholder}
            onChange={(e) => {
              setQuery(e.target.value)
              setVisibleLimit(PAGE_STEP)
            }}
          />
        </div>
        {(query.trim() || category !== 'all') && (
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            onClick={() => {
              setQuery('')
              changeCategory('all')
            }}
          >
            <RotateCcw size={13} />
            <span>{dict.common.reset}</span>
          </button>
        )}
      </div>

      <section className="panel">
        <header className="panel-head">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <FileClock size={15} style={{ color: 'var(--accent-strong)' }} />
            <h2>管理写操作时间线</h2>
          </div>
          <span className="cell-sub tabular">
            {rows.length === audit.length ? `共 ${rows.length} 条` : `匹配 ${rows.length} / ${audit.length} 条`}
          </span>
        </header>

        {rows.length === 0 ? (
          <EmptyState icon={<FileClock size={20} />} title="暂无记录" />
        ) : (
          <>
            <ol className="audit-list">
              {visibleRows.map((item, idx) => {
                const target = resolveTarget(item)
                const copyKey = `${item.at}-${idx}`
                return (
                  <li key={`${item.at}-${item.action}-${item.object}-${idx}`} className="audit-item">
                    <div>
                      <time className="tabular ltr-force" style={{ fontSize: 12.5, display: 'block' }}>
                        {formatTime(item.at * 1000)}
                      </time>
                      <span className="cell-sub tabular">{relativeAge(item.at, renderNow)}</span>
                    </div>

                    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                      <Badge text={actionLabel(item.action)} tone={actionTone(item.action)} />
                      <Badge text={target.kind} />
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', minWidth: 0 }}>
                      {target.name && target.page && (
                        <button
                          type="button"
                          className="btn btn-sm btn-ghost"
                          style={{ minHeight: 30, padding: '0 8px', color: 'var(--accent-strong)' }}
                          onClick={() => navigate(target.page!)}
                        >
                          {target.name}
                        </button>
                      )}
                      {item.object && (
                        <>
                          <code className="cell-sub ltr-force" style={{ fontSize: 12, wordBreak: 'break-all' }}>
                            {item.object}
                          </code>
                          <button
                            type="button"
                            className={`btn btn-sm btn-ghost ${copiedKey === copyKey ? 'copy-bounce' : ''}`}
                            style={{ minHeight: 28, padding: '0 8px' }}
                            onClick={() => void handleCopyId(item.object, copyKey)}
                          >
                            {copiedKey === copyKey ? <Check size={12} style={{ color: 'var(--good)' }} /> : <Copy size={12} />}
                            <span>{copiedKey === copyKey ? dict.common.copied : dict.common.copy}</span>
                          </button>
                        </>
                      )}
                    </div>
                  </li>
                )
              })}
            </ol>

            {remaining > 0 && (
              <div style={{ padding: 14, display: 'flex', justifyContent: 'center', borderBlockStart: 'var(--hairline-width) solid var(--line-hairline)' }}>
                <button type="button" className="btn btn-sm" onClick={() => setVisibleLimit((v) => v + PAGE_STEP)}>
                  {dict.audit.loadMore}（剩余 {remaining} 条）
                </button>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  )
}
