import { useEffect, useMemo, useRef } from 'react'
import { Activity, AlertTriangle, ArrowLeftRight, ArrowRight, Laptop, Network, Server, ShieldCheck } from 'lucide-react'
import { useConsole } from '../context/ConsoleContext'
import { actionLabel, actionTone, attentionReasons, byNameAndId, formatBytes, heartbeatOnline, presence, relativeAge, revisionState, tunnelBadges } from '../format'
import { askNodes, nodeBaseline, nodeChanged, registerPageRefresh, waitForReports } from '../pageRefresh'
import { Badge, EmptyState } from '../components/ui/Badge'
import { TopologyCanvas } from '../components/TopologyCanvas'

export function DashboardView() {
  const { nodes, mappings, mappingStatuses, traffic, audit, loaded, loading, error, reload, navigate, setNotificationsOpen, dict } = useConsole()
  const activeRef = useRef(true)
  const nodesRef = useRef(nodes)
  nodesRef.current = nodes

  useEffect(() => {
    activeRef.current = true
    const unregister = registerPageRefresh(async () => {
      const eligible = nodesRef.current.filter((n) => !n.revoked)
      const baseline = new Map(eligible.map((n) => [n.id, nodeBaseline(n)]))
      const connected = await askNodes(eligible.map((n) => n.id))
      await waitForReports(
        () => reload({ silent: true }),
        () => activeRef.current && connected.some((id) => !nodeChanged(nodesRef.current.find((n) => n.id === id), baseline.get(id)!)),
      )
    })
    return () => {
      activeRef.current = false
      unregister()
    }
  }, [reload])

  const servers = useMemo(() => nodes.filter((n) => n.role === 'server').sort(byNameAndId), [nodes])
  const clients = useMemo(() => nodes.filter((n) => n.role === 'client').sort(byNameAndId), [nodes])
  const onlineServers = useMemo(() => servers.filter((n) => !n.disabled && heartbeatOnline(n)).length, [servers])
  const onlineClients = useMemo(() => clients.filter((n) => !n.disabled && heartbeatOnline(n)).length, [clients])
  const enabledMappings = useMemo(() => mappings.filter((m) => m.enabled).length, [mappings])
  const linkedMappings = useMemo(
    () => mappings.filter((m) => m.enabled && mappingStatuses[m.id]?.server?.linked && mappingStatuses[m.id]?.client?.linked).length,
    [mappings, mappingStatuses],
  )
  const attention = useMemo(() => nodes.filter((n) => attentionReasons(n).length > 0).sort(byNameAndId), [nodes])
  const totalTraffic = useMemo(() => {
    let up = 0
    let down = 0
    for (const row of traffic) {
      up += row.up_bytes || 0
      down += row.down_bytes || 0
    }
    return { up, down, total: up + down }
  }, [traffic])

  if (!loaded && loading) {
    return (
      <div className="panel">
        <EmptyState title="正在加载控制平面状态…" description="正在同步节点拓扑、端口映射与实时流量统计。" />
      </div>
    )
  }

  if (!loaded) {
    return (
      <div className="panel">
        <EmptyState title="加载失败" description={error} />
      </div>
    )
  }

  const serverRatio = servers.length ? Math.round((onlineServers / servers.length) * 100) : 0
  const clientRatio = clients.length ? Math.round((onlineClients / clients.length) * 100) : 0
  const mappingRatio = mappings.length ? Math.round((linkedMappings / mappings.length) * 100) : 0

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* 5-Card Telemetry KPI Strip */}
      <section className="kpi-grid" aria-label="关键指标概览">
        <button type="button" className="kpi-card" onClick={() => navigate('servers')}>
          <div className="kpi-top">
            <span>{dict.dashboard.onlineServers}</span>
            <Server size={15} />
          </div>
          <div className="kpi-value tabular">
            {onlineServers}
            <span style={{ fontSize: 15, color: 'var(--text-muted)', fontWeight: 'var(--fw-regular)' }}> / {servers.length}</span>
          </div>
          <div className="kpi-bar">
            <div className="kpi-bar-fill" style={{ width: `${serverRatio}%` }} />
          </div>
        </button>

        <button type="button" className="kpi-card" onClick={() => navigate('clients')}>
          <div className="kpi-top">
            <span>{dict.dashboard.onlineClients}</span>
            <Laptop size={15} />
          </div>
          <div className="kpi-value tabular">
            {onlineClients}
            <span style={{ fontSize: 15, color: 'var(--text-muted)', fontWeight: 'var(--fw-regular)' }}> / {clients.length}</span>
          </div>
          <div className="kpi-bar">
            <div className="kpi-bar-fill" style={{ width: `${clientRatio}%`, background: 'var(--good)' }} />
          </div>
        </button>

        <button type="button" className="kpi-card" onClick={() => navigate('proxies')}>
          <div className="kpi-top">
            <span>{dict.dashboard.activeMappings}</span>
            <ArrowLeftRight size={15} />
          </div>
          <div className="kpi-value tabular">
            {enabledMappings}
            <span style={{ fontSize: 15, color: 'var(--text-muted)', fontWeight: 'var(--fw-regular)' }}> / {mappings.length}</span>
          </div>
          <div className="kpi-sub tabular">已建立隧道链路 {linkedMappings} 条</div>
          <div className="kpi-bar">
            <div className="kpi-bar-fill" style={{ width: `${mappingRatio}%`, background: 'var(--purple)' }} />
          </div>
        </button>

        <button type="button" className="kpi-card" onClick={() => navigate('proxies')}>
          <div className="kpi-top">
            <span>{dict.dashboard.totalTraffic}</span>
            <Activity size={15} />
          </div>
          <div className="kpi-value tabular ltr-force" style={{ fontSize: 22 }}>
            {formatBytes(totalTraffic.total)}
          </div>
          <div className="kpi-sub tabular ltr-force">
            ↑ {formatBytes(totalTraffic.up)} · ↓ {formatBytes(totalTraffic.down)}
          </div>
        </button>

        <button
          type="button"
          className="kpi-card"
          onClick={() => {
            if (attention.length > 0) setNotificationsOpen(true)
            else navigate('servers')
          }}
        >
          <div className="kpi-top">
            <span>{dict.dashboard.attentionNodes}</span>
            {attention.length > 0 ? <AlertTriangle size={15} style={{ color: 'var(--warn)' }} /> : <ShieldCheck size={15} style={{ color: 'var(--good)' }} />}
          </div>
          <div className="kpi-value tabular" style={{ color: attention.length > 0 ? 'var(--warn)' : 'var(--good)' }}>
            {attention.length}
          </div>
          <div className="kpi-sub">{attention.length > 0 ? '点击展开通知中心排查' : dict.dashboard.noAttention}</div>
        </button>
      </section>

      {/* Interactive Live Reverse-Tunnel Topology */}
      <section className="panel">
        <header className="panel-head">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Network size={16} style={{ color: 'var(--accent-strong)' }} />
            <h2>{dict.dashboard.topologyTitle}</h2>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Badge text="已连通" tone="good" dot />
            <Badge text="待建连" tone="warn" dot />
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => navigate('proxies')}>
              <span>管理映射</span>
              <ArrowRight size={13} className="rtl-flip" />
            </button>
          </div>
        </header>
        {servers.length > 0 || clients.length > 0 ? (
          <TopologyCanvas nodes={nodes} mappings={mappings} statuses={mappingStatuses} onNavigate={navigate} />
        ) : (
          <EmptyState
            icon={<Network size={20} />}
            title="尚未构建网络拓扑"
            description={dict.dashboard.topologyEmpty}
            action={
              <button type="button" className="btn btn-sm btn-primary" onClick={() => navigate('servers')}>
                前往创建公网网关
              </button>
            }
          />
        )}
      </section>

      {/* 2-Column Fleet Bento */}
      <div className="bento-2">
        <section className="panel">
          <header className="panel-head">
            <h2>{dict.dashboard.gatewaysTitle}</h2>
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => navigate('servers')}>
              <span>{dict.dashboard.manageAll}</span>
              <ArrowRight size={13} className="rtl-flip" />
            </button>
          </header>
          {servers.length === 0 ? (
            <EmptyState icon={<Server size={18} />} title="暂无公网网关" />
          ) : (
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>网关</th>
                    <th>状态</th>
                    <th>隧道栈</th>
                    <th>配置</th>
                  </tr>
                </thead>
                <tbody>
                  {servers.slice(0, 6).map((node) => {
                    const st = presence(node)
                    const rev = revisionState(node)
                    return (
                      <tr key={node.id} style={{ cursor: 'pointer' }} onClick={() => navigate('servers')}>
                        <td>
                          <div style={{ fontWeight: 'var(--fw-medium)' }}>{node.name}</div>
                          <div className="cell-sub tabular ltr-force">
                            {mappings.filter((m) => m.server_id === node.id).length} 条映射
                          </div>
                        </td>
                        <td><Badge text={st.text} tone={st.tone} dot pulse={st.tone === 'good'} /></td>
                        <td>
                          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                            {tunnelBadges(node).slice(0, 3).map((b) => (
                              <Badge key={b.text} text={b.text} tone={b.tone} />
                            ))}
                          </div>
                        </td>
                        <td><Badge text={rev.text} tone={rev.tone} /></td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="panel">
          <header className="panel-head">
            <h2>{dict.dashboard.clientsTitle}</h2>
            <button type="button" className="btn btn-sm btn-ghost" onClick={() => navigate('clients')}>
              <span>{dict.dashboard.manageAll}</span>
              <ArrowRight size={13} className="rtl-flip" />
            </button>
          </header>
          {clients.length === 0 ? (
            <EmptyState icon={<Laptop size={18} />} title="暂无内网节点" />
          ) : (
            <div className="table-scroll">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>节点</th>
                    <th>状态</th>
                    <th>关联映射</th>
                    <th>配置</th>
                  </tr>
                </thead>
                <tbody>
                  {clients.slice(0, 6).map((node) => {
                    const st = presence(node)
                    const rev = revisionState(node)
                    return (
                      <tr key={node.id} style={{ cursor: 'pointer' }} onClick={() => navigate('clients')}>
                        <td>
                          <div style={{ fontWeight: 'var(--fw-medium)' }}>{node.name}</div>
                          <div className="cell-sub tabular ltr-force">{node.software_version || '等待上报'}</div>
                        </td>
                        <td><Badge text={st.text} tone={st.tone} dot pulse={st.tone === 'good'} /></td>
                        <td className="tabular">{mappings.filter((m) => m.client_id === node.id).length}</td>
                        <td><Badge text={rev.text} tone={rev.tone} /></td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>

      {/* Recent Audit Activity */}
      <section className="panel">
        <header className="panel-head">
          <h2>{dict.dashboard.recentAuditTitle}</h2>
          <button type="button" className="btn btn-sm btn-ghost" onClick={() => navigate('audit')}>
            <span>完整审计轨迹</span>
            <ArrowRight size={13} className="rtl-flip" />
          </button>
        </header>
        {audit.length === 0 ? (
          <EmptyState title="暂无审计记录" description="节点与映射的创建、修改与令牌操作会自动记录。" />
        ) : (
          <ul className="audit-list">
            {audit.slice(0, 5).map((item, idx) => (
              <li key={`${item.at}-${item.action}-${idx}`} className="audit-item">
                <span className="cell-sub tabular">{relativeAge(item.at)}</span>
                <Badge text={actionLabel(item.action)} tone={actionTone(item.action)} />
                <code className="cell-sub ltr-force" style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {item.object || '—'}
                </code>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
