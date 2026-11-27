import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ArrowLeftRight, ArrowRight, Edit3, MoreHorizontal, Plus, Power, Search, Trash2 } from 'lucide-react'
import { api } from '../api'
import { useConsole } from '../context/ConsoleContext'
import { byNameAndId, endpoint, formatBytes, formatTime, heartbeatOnline, nodeName, triggerHaptic, validateMapping, type Tone } from '../format'
import { askNodes, nodeBaseline, nodeChanged, registerPageRefresh, waitForReports } from '../pageRefresh'
import type { Mapping, TrafficRow } from '../types'
import { Alert, Badge, EmptyState, InlineAlert } from '../components/ui/Badge'
import { Dropdown, Segmented, Select, Switch } from '../components/ui/Controls'
import { ActionSheet, AlertDialog, Drawer } from '../components/ui/Overlays'

type FilterState = 'all' | 'on' | 'off'

const MAPPING_DRAFT_KEY = 'veilink_react_mapping_draft_v1'
const MAPPING_FILTER_KEY = 'veilink_proxies_filter'

interface MappingDraft {
  id: string
  name: string
  serverId: string
  clientId: string
  connectEndpointId: string
  bandwidthLimit: string
  pool: number
  muxType: '' | 'smux' | 'yamux' | 'h2mux'
  listenHost: string
  listenPort: string
  targetHost: string
  targetPort: string
  network: 'tcp' | 'udp'
  enabled: boolean
}

function mappingToDraft(m: Mapping): MappingDraft {
  const limit = m.bandwidth_limit?.match(/^([0-9]+(?:\.[0-9]+)?)(Kbps|Mbps|Gbps)$/)
  const mult = limit ? { Kbps: 0.001, Mbps: 1, Gbps: 1000 }[limit[2]] || 0 : 0
  const bandwidthLimit = limit ? String(Number((Number(limit[1]) * mult).toFixed(6))) : '0'
  const net = (m.network === 'udp' ? 'udp' : 'tcp') as 'tcp' | 'udp'
  const muxType = (net === 'tcp' && m.mux ? m.mux_type || 'smux' : '') as '' | 'smux' | 'yamux' | 'h2mux'
  return {
    id: m.id,
    name: m.name,
    serverId: m.server_id,
    clientId: m.client_id,
    connectEndpointId: m.connect_endpoint_id || '',
    bandwidthLimit,
    pool: m.pool || 1,
    muxType,
    listenHost: m.listen_host,
    listenPort: String(m.listen_port),
    targetHost: m.target_host,
    targetPort: String(m.target_port),
    network: net,
    enabled: m.enabled,
  }
}

export function ProxiesView() {
  const {
    nodes,
    mappings,
    mappingStatuses,
    traffic,
    trafficLoaded,
    loaded,
    loading,
    error,
    reload,
    refreshMappingStatuses,
    toast,
    showSnackbar,
    dict,
  } = useConsole()

  const [filter, setFilter] = useState<FilterState>(() => {
    try {
      const saved = globalThis.sessionStorage?.getItem(MAPPING_FILTER_KEY) || globalThis.localStorage?.getItem(MAPPING_FILTER_KEY)
      if (saved === 'all' || saved === 'on' || saved === 'off') return saved
    } catch { /* ignore */ }
    return 'all'
  })
  const [query, setQuery] = useState('')
  const [now, setNow] = useState(() => Date.now())

  const [drawerOpen, setDrawerOpen] = useState(false)
  const [hasSavedDraft, setHasSavedDraft] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Mapping | null>(null)
  const [mobileSheet, setMobileSheet] = useState<Mapping | null>(null)

  const servers = useMemo(() => nodes.filter((n) => n.role === 'server' && !n.revoked).sort(byNameAndId), [nodes])
  const clients = useMemo(() => nodes.filter((n) => n.role === 'client' && !n.revoked).sort(byNameAndId), [nodes])

  const [draft, setDraft] = useState<MappingDraft>({
    id: '',
    name: '',
    serverId: '',
    clientId: '',
    connectEndpointId: '',
    bandwidthLimit: '0',
    pool: 1,
    muxType: '',
    listenHost: '0.0.0.0',
    listenPort: '',
    targetHost: '127.0.0.1',
    targetPort: '',
    network: 'tcp',
    enabled: true,
  })

  const activeRef = useRef(true)
  const mappingsRef = useRef(mappings)
  const nodesRef = useRef(nodes)
  mappingsRef.current = mappings
  nodesRef.current = nodes

  useEffect(() => {
    activeRef.current = true
    const clock = window.setInterval(() => setNow(Date.now()), 2000)
    const unregister = registerPageRefresh(async () => {
      const ids = [...new Set(mappingsRef.current.flatMap((m) => [m.server_id, m.client_id]))].filter((id) => {
        const n = nodesRef.current.find((x) => x.id === id)
        return !!n && !n.revoked
      })
      const baseline = new Map(ids.map((id) => [id, nodeBaseline(nodesRef.current.find((x) => x.id === id)!)]))
      const connected = await askNodes(ids)
      await waitForReports(
        async () => {
          if (!activeRef.current) return
          await reload({ silent: true })
          await refreshMappingStatuses()
        },
        () => activeRef.current && connected.some((id) => !nodeChanged(nodesRef.current.find((x) => x.id === id), baseline.get(id)!)),
      )
    })
    return () => {
      activeRef.current = false
      window.clearInterval(clock)
      unregister()
    }
  }, [reload, refreshMappingStatuses])

  const changeFilter = (next: FilterState) => {
    setFilter(next)
    try {
      globalThis.sessionStorage?.setItem(MAPPING_FILTER_KEY, next)
      globalThis.localStorage?.setItem(MAPPING_FILTER_KEY, next)
    } catch { /* ignore */ }
  }

  // Spec 2.5: Auto-save unsaved mapping draft
  useEffect(() => {
    if (!drawerOpen || draft.id) return
    if (!draft.name && !draft.listenPort && !draft.targetPort) return
    try {
      globalThis.sessionStorage?.setItem(MAPPING_DRAFT_KEY, JSON.stringify(draft))
    } catch { /* ignore */ }
  }, [drawerOpen, draft])

  const connectionOptions = useCallback(
    (serverId: string) => {
      const srv = servers.find((n) => n.id === serverId)
      if (!srv) return []
      const list = srv.connect_endpoints?.length
        ? srv.connect_endpoints
        : srv.address && srv.port
          ? [{ id: 'primary', name: '首选地址', host: srv.address, port: srv.port, enabled: true }]
          : []
      return list.filter((ep) => ep.enabled)
    },
    [servers],
  )

  const activeConnections = useMemo(() => connectionOptions(draft.serverId), [connectionOptions, draft.serverId])
  const missingConnection = !!draft.connectEndpointId && !activeConnections.some((c) => c.id === draft.connectEndpointId)

  const openEditor = (mapping?: Mapping) => {
    if (mapping) {
      setDraft(mappingToDraft(mapping))
      setHasSavedDraft(false)
    } else {
      const firstServer = servers[0]?.id || ''
      const firstConn = connectionOptions(firstServer)[0]?.id || ''
      setDraft({
        id: '',
        name: '',
        serverId: firstServer,
        clientId: clients[0]?.id || '',
        connectEndpointId: firstConn,
        bandwidthLimit: '0',
        pool: 1,
        muxType: '',
        listenHost: '0.0.0.0',
        listenPort: '',
        targetHost: '127.0.0.1',
        targetPort: '',
        network: 'tcp',
        enabled: true,
      })
      try {
        setHasSavedDraft(!!globalThis.sessionStorage?.getItem(MAPPING_DRAFT_KEY))
      } catch {
        setHasSavedDraft(false)
      }
    }
    setDrawerOpen(true)
  }

  const restoreDraft = () => {
    try {
      const raw = globalThis.sessionStorage?.getItem(MAPPING_DRAFT_KEY)
      if (!raw) return
      const parsed = JSON.parse(raw)
      if (parsed && !parsed.id) setDraft((prev) => ({ ...prev, ...parsed }))
      setHasSavedDraft(false)
    } catch { /* ignore */ }
  }

  const discardDraft = () => {
    setHasSavedDraft(false)
    try { globalThis.sessionStorage?.removeItem(MAPPING_DRAFT_KEY) } catch { /* ignore */ }
  }

  const saveMapping = async (): Promise<boolean> => {
    const problem = validateMapping(draft, nodes, mappings, draft.id)
    if (problem) throw new Error(problem)
    const numLimit = Number(draft.bandwidthLimit)
    const formattedLimit =
      numLimit > 0
        ? numLimit === Number(numLimit.toFixed(3))
          ? `${numLimit}Mbps`
          : `${Number((numLimit * 1000).toFixed(3))}Kbps`
        : ''
    await api(draft.id ? `/mappings/${encodeURIComponent(draft.id)}` : '/mappings', draft.id ? 'PUT' : 'POST', {
      name: draft.name.trim(),
      server_id: draft.serverId,
      client_id: draft.clientId,
      pool: draft.pool,
      mux: draft.network === 'tcp' && draft.muxType !== '',
      mux_type: draft.network === 'tcp' ? draft.muxType : '',
      connect_endpoint_id: draft.connectEndpointId,
      bandwidth_limit: formattedLimit,
      listen_host: draft.listenHost.trim(),
      listen_port: Number(draft.listenPort),
      target_host: draft.targetHost.trim(),
      target_port: Number(draft.targetPort),
      network: draft.network,
      enabled: draft.enabled,
    })
    if (!draft.id) discardDraft()
    await reload()
    toast('端口映射已保存。')
    return true
  }

  // Spec 2.4: Reversible toggle executes directly + shows bottom Undo Snackbar!
  const toggleMapping = async (mapping: Mapping) => {
    const wasEnabled = mapping.enabled
    if (!wasEnabled) {
      const problem = validateMapping({ ...mappingToDraft(mapping), enabled: true }, nodes, mappings, mapping.id)
      if (problem) {
        toast(problem, true)
        return
      }
    }
    triggerHaptic(12)
    try {
      await api(`/mappings/${encodeURIComponent(mapping.id)}`, 'PUT', { ...mapping, enabled: !wasEnabled })
      await reload()
      showSnackbar(
        wasEnabled ? `已停用映射「${mapping.name}」` : `已启用映射「${mapping.name}」`,
        async () => {
          await api(`/mappings/${encodeURIComponent(mapping.id)}`, 'PUT', { ...mapping, enabled: wasEnabled })
          await reload()
          toast(`已撤销「${mapping.name}」的状态变更。`)
        },
        dict.common.undo,
      )
    } catch (err) {
      toast(err instanceof Error ? err.message : '切换失败', true)
    }
  }

  const commitDelete = async () => {
    if (!deleteTarget) return
    await api(`/mappings/${encodeURIComponent(deleteTarget.id)}`, 'DELETE')
    await reload()
    toast(`已永久删除映射「${deleteTarget.name}」。`)
  }

  const tunnelState = (mapping: Mapping): { text: string; tone: Tone } => {
    if (!mapping.enabled) return { text: '已停用', tone: 'neutral' }
    const srv = nodes.find((n) => n.id === mapping.server_id)
    const cli = nodes.find((n) => n.id === mapping.client_id)
    if (!srv || !cli || srv.revoked || cli.revoked) return { text: '节点不可用', tone: 'warn' }
    if (srv.disabled || cli.disabled) {
      return { text: srv.disabled && cli.disabled ? '两端已停用' : srv.disabled ? '服务端已停用' : '客户端已停用', tone: 'neutral' }
    }
    const currentNow = Math.max(now, Date.now())
    const sOn = heartbeatOnline(srv, currentNow)
    const cOn = heartbeatOnline(cli, currentNow)
    if (!sOn || !cOn) return { text: !sOn && !cOn ? '两端离线' : !sOn ? '服务端离线' : '客户端离线', tone: 'warn' }
    const st = mappingStatuses[mapping.id]
    const sDown = st?.server?.linked !== true
    const cDown = st?.client?.linked !== true
    if (!sDown && !cDown) return { text: '隧道已连通', tone: 'good' }
    if (sDown && cDown) return { text: '待建连', tone: 'warn' }
    return { text: sDown ? '服务端未连通' : '客户端未连通', tone: 'warn' }
  }

  const trafficMap = useMemo(() => new Map<string, TrafficRow>(traffic.map((r) => [r.mapping_id, r])), [traffic])
  const maxTrafficBytes = useMemo(
    () => Math.max(1, ...traffic.map((r) => (r.up_bytes || 0) + (r.down_bytes || 0))),
    [traffic],
  )

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    return mappings
      .filter((m) => {
        if (filter === 'on' && !m.enabled) return false
        if (filter === 'off' && m.enabled) return false
        if (!q) return true
        return [m.name, m.listen_host, m.target_host, nodeName(nodes, m.server_id), nodeName(nodes, m.client_id)]
          .join(' ')
          .toLowerCase()
          .includes(q)
      })
      .sort(byNameAndId)
  }, [mappings, filter, query, nodes])

  const poolOptions = useMemo(
    () => Array.from({ length: 32 }, (_, i) => ({ value: String(i + 1), label: `Pool ${i + 1} 条并发隧道` })),
    [],
  )

  if (!loaded && loading) {
    return <div className="panel"><EmptyState title="正在加载端口映射…" /></div>
  }
  if (!loaded) {
    return <div className="panel"><EmptyState title="加载失败" description={error} /></div>
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="toolbar">
        <Segmented<FilterState>
          ariaLabel="映射状态筛选"
          value={filter}
          onChange={changeFilter}
          options={[
            { value: 'all', label: `${dict.common.all} (${mappings.length})` },
            { value: 'on', label: dict.proxies.enabledOnly },
            { value: 'off', label: dict.proxies.disabledOnly },
          ]}
        />
        <div className="toolbar-search">
          <Search size={15} className="toolbar-search-icon" />
          <input
            type="search"
            value={query}
            aria-label="搜索映射"
            placeholder={dict.proxies.searchPlaceholder}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <button type="button" className="btn btn-primary" onClick={() => openEditor()}>
          <Plus size={16} />
          <span>{dict.proxies.newMapping}</span>
        </button>
      </div>

      <div className="panel">
        {rows.length === 0 ? (
          <EmptyState
            icon={<ArrowLeftRight size={20} />}
            title={dict.proxies.noMappings}
            action={
              <button type="button" className="btn btn-sm btn-primary" onClick={() => openEditor()}>
                <Plus size={14} />
                <span>{dict.proxies.newMapping}</span>
              </button>
            }
          />
        ) : (
          <>
            <div className="table-scroll desktop-table-wrap">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>路由名称</th>
                    <th>网关 → 客户端</th>
                    <th>转发路径</th>
                    <th>并发 / 复用</th>
                    <th>隧道状态</th>
                    <th>累计流量（上行 / 下行）</th>
                    <th style={{ textAlign: 'end' }}>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((m) => {
                    const st = tunnelState(m)
                    const tRow = trafficMap.get(m.id)
                    const totalB = (tRow?.up_bytes || 0) + (tRow?.down_bytes || 0)
                    const pct = tRow?.reported_at ? Math.max(4, Math.round((totalB / maxTrafficBytes) * 100)) : 0
                    const net = (m.network || 'tcp').toUpperCase()
                    return (
                      <tr key={m.id}>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <strong style={{ fontWeight: 'var(--fw-medium)' }}>{m.name}</strong>
                            <Badge text={net} tone={net === 'UDP' ? 'purple' : 'accent'} />
                          </div>
                          {m.bandwidth_limit && <div className="cell-sub tabular ltr-force">限速 {m.bandwidth_limit}</div>}
                        </td>

                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 13 }}>
                            <span>{nodeName(nodes, m.server_id)}</span>
                            <ArrowRight size={13} className="rtl-flip" style={{ color: 'var(--text-muted)' }} />
                            <span>{nodeName(nodes, m.client_id)}</span>
                          </div>
                          <div className="cell-sub">
                            {m.connect_endpoint_id
                              ? (() => {
                                  const ep = connectionOptions(m.server_id).find((c) => c.id === m.connect_endpoint_id)
                                  return ep ? `${ep.name} · ${endpoint(ep.host, ep.port)}` : '原入口不可用'
                                })()
                              : '自动按服务端入口顺序切换'}
                          </div>
                        </td>

                        <td>
                          <div className="mono tabular ltr-force" style={{ fontSize: 12.5 }}>
                            {endpoint(m.listen_host, m.listen_port)}
                          </div>
                          <div className="cell-sub mono tabular ltr-force">
                            → {endpoint(m.target_host, m.target_port)}
                          </div>
                        </td>

                        <td>
                          <div className="tabular" style={{ fontSize: 13 }}>Pool {m.pool || 1}</div>
                          <div className="cell-sub">
                            {m.network === 'udp' ? 'XUDP' : m.mux ? m.mux_type || 'smux' : 'mux 关闭'}
                          </div>
                        </td>

                        <td>
                          <Badge text={st.text} tone={st.tone} dot pulse={st.tone === 'good'} />
                        </td>

                        <td style={{ minWidth: 168 }}>
                          {!m.enabled ? (
                            <span className="cell-sub">—</span>
                          ) : !trafficLoaded ? (
                            <span className="cell-sub">读取中…</span>
                          ) : tRow?.reported_at ? (
                            <div style={{ display: 'grid', gap: 4 }}>
                              <div className="tabular ltr-force" style={{ fontSize: 12.5 }}>
                                ↑ {formatBytes(tRow.up_bytes)} / ↓ {formatBytes(tRow.down_bytes)}
                              </div>
                              <div className="kpi-bar" style={{ height: 3 }}>
                                <div className="kpi-bar-fill" style={{ width: `${pct}%` }} />
                              </div>
                              <div className="cell-sub tabular">{formatTime(tRow.reported_at)}</div>
                            </div>
                          ) : (
                            <span className="cell-sub">尚无流量上报</span>
                          )}
                        </td>

                        <td>
                          <div className="row-actions">
                            <button type="button" className="btn btn-sm btn-ghost" onClick={() => void toggleMapping(m)}>
                              <Power size={13} style={{ color: m.enabled ? 'var(--good)' : 'var(--text-muted)' }} />
                              <span>{m.enabled ? dict.common.disable : dict.common.enable}</span>
                            </button>
                            <button type="button" className="btn btn-sm btn-ghost" onClick={() => openEditor(m)}>
                              <Edit3 size={13} />
                              <span>{dict.common.edit}</span>
                            </button>
                            <Dropdown
                              menuLabel={`${m.name} 操作`}
                              trigger={(_open, toggle) => (
                                <button
                                  type="button"
                                  className="icon-btn icon-btn-compact"
                                  aria-label={`${m.name} 更多操作`}
                                  onClick={() => {
                                    if (window.innerWidth <= 768) setMobileSheet(m)
                                    else toggle()
                                  }}
                                >
                                  <MoreHorizontal size={16} />
                                </button>
                              )}
                              items={[
                                {
                                  id: 'edit',
                                  label: '编辑映射规则',
                                  icon: <Edit3 size={14} />,
                                  onSelect: () => openEditor(m),
                                },
                                {
                                  id: 'toggle',
                                  label: m.enabled ? '停用映射（可撤销）' : '启用映射',
                                  icon: <Power size={14} />,
                                  onSelect: () => void toggleMapping(m),
                                },
                                {
                                  id: 'del',
                                  label: '永久删除映射…',
                                  icon: <Trash2 size={14} />,
                                  danger: true,
                                  separatorBefore: true,
                                  onSelect: () => setDeleteTarget(m),
                                },
                              ]}
                            />
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {/* Mobile Touch Cards (<= 640px) */}
            <div className="mobile-cards" role="list" aria-label="端口映射卡片列表">
              {rows.map((m) => {
                const st = tunnelState(m)
                const tRow = trafficMap.get(m.id)
                const totalB = (tRow?.up_bytes || 0) + (tRow?.down_bytes || 0)
                const pct = tRow?.reported_at ? Math.max(4, Math.round((totalB / maxTrafficBytes) * 100)) : 0
                const net = (m.network || 'tcp').toUpperCase()
                return (
                  <article key={m.id} className="mobile-card" role="listitem">
                    <div className="mobile-card-head">
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        <strong style={{ fontSize: 15, fontWeight: 'var(--fw-medium)' }}>{m.name}</strong>
                        <Badge text={net} tone={net === 'UDP' ? 'purple' : 'accent'} />
                        <Badge text={`Pool ${m.pool || 1}`} />
                      </div>
                      <Badge text={st.text} tone={st.tone} dot pulse={st.tone === 'good'} />
                    </div>

                    <div className="mobile-card-meta">
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 13 }}>
                        <span>{nodeName(nodes, m.server_id)}</span>
                        <ArrowRight size={13} className="rtl-flip" style={{ color: 'var(--text-muted)' }} />
                        <span>{nodeName(nodes, m.client_id)}</span>
                      </div>
                      <div className="mono tabular ltr-force" style={{ fontSize: 12.5 }}>
                        {endpoint(m.listen_host, m.listen_port)} → {endpoint(m.target_host, m.target_port)}
                      </div>
                      {m.enabled && trafficLoaded && tRow?.reported_at && (
                        <div style={{ display: 'grid', gap: 4 }}>
                          <span className="cell-sub tabular ltr-force">
                            ↑ {formatBytes(tRow.up_bytes)} / ↓ {formatBytes(tRow.down_bytes)}
                          </span>
                          <div className="kpi-bar" style={{ height: 3 }}>
                            <div className="kpi-bar-fill" style={{ width: `${pct}%` }} />
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="mobile-card-actions">
                      <button type="button" className="btn btn-sm" onClick={() => void toggleMapping(m)}>
                        <Power size={14} style={{ color: m.enabled ? 'var(--good)' : 'var(--text-muted)' }} />
                        <span>{m.enabled ? dict.common.disable : dict.common.enable}</span>
                      </button>
                      <button type="button" className="btn btn-sm btn-soft" onClick={() => openEditor(m)}>
                        <Edit3 size={14} />
                        <span>{dict.common.edit}</span>
                      </button>
                      <button
                        type="button"
                        className="icon-btn"
                        aria-label={`${m.name} 更多操作`}
                        onClick={() => setMobileSheet(m)}
                      >
                        <MoreHorizontal size={18} />
                      </button>
                    </div>
                  </article>
                )
              })}
            </div>
          </>
        )}
      </div>

      {/* Mapping Editor Drawer / Mobile BottomSheet */}
      <Drawer
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
        title={draft.id ? `编辑映射 · ${draft.name}` : '新建端口映射'}
        saveLabel={draft.id ? '保存' : '创建'}
        disabled={!servers.length || !clients.length}
        onSubmit={saveMapping}
      >
        {hasSavedDraft && !draft.id && (
          <div className="draft-banner" role="status">
            <span>检测到上次未提交的映射草稿</span>
            <div style={{ display: 'flex', gap: 6 }}>
              <button type="button" className="btn btn-sm btn-primary" onClick={restoreDraft}>恢复草稿</button>
              <button type="button" className="btn btn-sm btn-ghost" onClick={discardDraft}>忽略</button>
            </div>
          </div>
        )}

        {(!servers.length || !clients.length) && (
          <Alert tone="warn">请先至少创建一个可用的公网网关（Server）与一个内网节点（Client）。</Alert>
        )}

        <div className="field">
          <label className="field-label" htmlFor="map-name">映射名称</label>
          <input id="map-name" type="text" maxLength={128} required value={draft.name} placeholder="例如：办公内网 SSH" onChange={(e) => setDraft((p) => ({ ...p, name: e.target.value }))} />
        </div>

        <div className="form-grid-2">
          <div className="field">
            <span className="field-label">公网网关（Server）</span>
            <Select
              ariaLabel="选择公网网关"
              value={draft.serverId}
              disabled={!servers.length}
              options={servers.map((n) => ({ value: n.id, label: n.name }))}
              onChange={(serverId) => {
                const nextConns = connectionOptions(serverId)
                setDraft((p) => ({ ...p, serverId, connectEndpointId: nextConns[0]?.id || '' }))
              }}
            />
          </div>
          <div className="field">
            <span className="field-label">内网节点（Client）</span>
            <Select
              ariaLabel="选择内网节点"
              value={draft.clientId}
              disabled={!clients.length}
              options={clients.map((n) => ({ value: n.id, label: n.name }))}
              onChange={(clientId) => setDraft((p) => ({ ...p, clientId }))}
            />
          </div>
        </div>

        <div className="field">
          <span className="field-label">连接入口</span>
          <Select
            ariaLabel="连接入口"
            value={draft.connectEndpointId}
            disabled={!activeConnections.length}
            options={[
              { value: '', label: '自动' },
              ...activeConnections.map((c) => ({ value: c.id, label: `${c.name} · ${endpoint(c.host, c.port)}` })),
            ]}
            onChange={(connectEndpointId) => setDraft((p) => ({ ...p, connectEndpointId }))}
          />
          {!activeConnections.length && <InlineAlert message="所选服务端没有启用的连接地址，请先编辑服务端。" />}
          {missingConnection && <InlineAlert message="原连接地址已停用或删除，请重新选择后保存。" />}
        </div>

        <div className="form-grid-2">
          <div className="field">
            <span className="field-label">网络协议</span>
            <Segmented<'tcp' | 'udp'>
              ariaLabel="网络协议"
              value={draft.network}
              onChange={(network) => setDraft((p) => ({ ...p, network, muxType: network === 'tcp' ? p.muxType : '' }))}
              options={[
                { value: 'tcp', label: 'TCP' },
                { value: 'udp', label: 'UDP (XUDP)' },
              ]}
            />
          </div>

          {/* Spec 3.2: >10 options (1-32) uses searchable Select with max-height 264px */}
          <div className="field">
            <span className="field-label">隧道连接池（Pool 1–32）</span>
            <Select
              ariaLabel="Pool 并发数"
              value={String(draft.pool)}
              searchable
              searchPlaceholder="输入并发连接数 1-32…"
              options={poolOptions}
              onChange={(val) => setDraft((p) => ({ ...p, pool: Number(val) }))}
            />
          </div>
        </div>

        <div className="field">
          <span className="field-label">TCP 多路复用（默认关闭）</span>
          <Segmented<'' | 'smux' | 'yamux' | 'h2mux'>
            ariaLabel="TCP mux"
            value={draft.muxType}
            disabled={draft.network !== 'tcp'}
            onChange={(muxType) => setDraft((p) => ({ ...p, muxType }))}
            options={[
              { value: '', label: '关闭' },
              { value: 'smux', label: 'smux' },
              { value: 'yamux', label: 'yamux' },
              { value: 'h2mux', label: 'h2mux' },
            ]}
          />
        </div>

        <div className="field">
          <label className="field-label" htmlFor="map-bw">带宽上限 (Mbps)</label>
          <input
            id="map-bw"
            className="tabular ltr-force"
            type="number"
            min={0}
            max={100000}
            step="0.000001"
            placeholder="0 不限速"
            value={draft.bandwidthLimit}
            onChange={(e) => setDraft((p) => ({ ...p, bandwidthLimit: e.target.value }))}
          />
        </div>

        <div className="form-grid-2">
          <div className="field">
            <label className="field-label" htmlFor="map-lhost">公网监听 IP</label>
            <input id="map-lhost" className="mono ltr-force" type="text" required value={draft.listenHost} onChange={(e) => setDraft((p) => ({ ...p, listenHost: e.target.value }))} />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="map-lport">公网监听端口</label>
            <input id="map-lport" className="mono tabular ltr-force" type="number" min={1} max={65535} required value={draft.listenPort} onChange={(e) => setDraft((p) => ({ ...p, listenPort: e.target.value }))} />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="map-thost">内网目标地址</label>
            <input id="map-thost" className="mono ltr-force" type="text" required value={draft.targetHost} onChange={(e) => setDraft((p) => ({ ...p, targetHost: e.target.value }))} />
          </div>
          <div className="field">
            <label className="field-label" htmlFor="map-tport">内网目标端口</label>
            <input id="map-tport" className="mono tabular ltr-force" type="number" min={1} max={65535} required value={draft.targetPort} onChange={(e) => setDraft((p) => ({ ...p, targetPort: e.target.value }))} />
          </div>
        </div>

        <Switch checked={draft.enabled} label="保存后立即启用此映射" onChange={(enabled) => setDraft((p) => ({ ...p, enabled }))} />
      </Drawer>

      <ActionSheet
        open={!!mobileSheet}
        title={mobileSheet ? `端口映射 · ${mobileSheet.name}` : undefined}
        onClose={() => setMobileSheet(null)}
        options={
          mobileSheet
            ? [
                { label: '编辑映射规则', icon: <Edit3 size={16} />, onSelect: () => openEditor(mobileSheet) },
                { label: mobileSheet.enabled ? '停用映射（可撤销）' : '启用映射', icon: <Power size={16} />, onSelect: () => void toggleMapping(mobileSheet) },
                { label: '永久删除映射', icon: <Trash2 size={16} />, danger: true, onSelect: () => setDeleteTarget(mobileSheet) },
              ]
            : []
        }
      />

      <AlertDialog
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        title={`删除映射「${deleteTarget?.name || ''}」`}
        lossSummary={
          deleteTarget
            ? `将移除 ${endpoint(deleteTarget.listen_host, deleteTarget.listen_port)} → ${endpoint(deleteTarget.target_host, deleteTarget.target_port)} 转发规则。`
            : ''
        }
        confirmLabel="确认删除"
        onConfirm={commitDelete}
      />
    </div>
  )
}
