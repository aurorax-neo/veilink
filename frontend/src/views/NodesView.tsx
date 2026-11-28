import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Check,
  Copy,
  Download,
  Edit3,
  FileCode2,
  Laptop,
  MoreHorizontal,
  Plus,
  Power,
  QrCode,
  RefreshCw,
  Search,
  Server,
  ShieldOff,
  Trash2,
  X,
} from 'lucide-react'
import { api } from '../api'
import { useConsole } from '../context/ConsoleContext'
import {
  attentionReasons,
  byNameAndId,
  copyText,
  endpoint,
  heartbeatOnline,
  isOfflineNode,
  needsAttention,
  nodeSeenSummary,
  presence,
  revisionState,
  seenText,
  serverNowMs,
  triggerHaptic,
  tunnelBadges,
  tunnelSummaryText,
} from '../format'
import { registerPageRefresh } from '../pageRefresh'
import { stream } from '../stream'
import type { Node } from '../types'
import { NodeEditorDrawer } from '../components/NodeEditorDrawer'
import { NodeOnboardingModal } from '../components/NodeOnboardingModal'
import { Alert, Badge, EmptyState, Tooltip } from '../components/ui/Badge'
import { Dropdown, Segmented, SplitPane } from '../components/ui/Controls'
import { ActionSheet, AlertDialog, Drawer, Modal, Popconfirm } from '../components/ui/Overlays'

type NodeFilter = 'all' | 'online' | 'offline' | 'attention' | 'disabled'

export function NodesView({ role }: { role: 'server' | 'client' }) {
  const { nodes, mappings, loaded, loading, error, reload, reloadNode, toast, showSnackbar, dict } = useConsole()
  const isServer = role === 'server'
  const roleLabel = isServer ? '公网网关' : '内网节点'

  const [filter, setFilter] = useState<NodeFilter>('all')
  const [query, setQuery] = useState('')
  const [selectedId, setSelectedId] = useState('')
  const [now, setNow] = useState(() => serverNowMs())

  const [editorOpen, setEditorOpen] = useState(false)
  const [editingNode, setEditingNode] = useState<Node | null>(null)
  const [onboardingNode, setOnboardingNode] = useState<Node | null>(null)
  const [configNode, setConfigNode] = useState<Node | null>(null)
  const [mobileSheetNode, setMobileSheetNode] = useState<Node | null>(null)
  const [isMobileViewport, setIsMobileViewport] = useState(() =>
    typeof window !== 'undefined' ? window.innerWidth <= 768 : false,
  )

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return
    const mq = window.matchMedia('(max-width: 768px)')
    const sync = () => setIsMobileViewport(mq.matches)
    sync()
    mq.addEventListener?.('change', sync)
    return () => mq.removeEventListener?.('change', sync)
  }, [])
  const [dangerAction, setDangerAction] = useState<{ node: Node; kind: 'delete' | 'revoke' } | null>(null)

  const [refreshingIds, setRefreshingIds] = useState<Set<string>>(() => new Set())
  const [feedbackMap, setFeedbackMap] = useState<Record<string, { text: string; bad: boolean }>>({})
  const [copiedId, setCopiedId] = useState('')

  const activeRef = useRef(true)
  const nodesRef = useRef(nodes)
  nodesRef.current = nodes

  useEffect(() => {
    setSelectedId('')
    setFilter('all')
    setQuery('')
  }, [role])

  useEffect(() => {
    activeRef.current = true
    const timer = window.setInterval(() => setNow(serverNowMs()), 2000)
    const off = stream.on('node', (data) => {
      const nid = (data as { node_id?: string } | null)?.node_id
      if (nid) {
        setFeedbackMap((prev) => {
          if (!prev[nid]) return prev
          const copy = { ...prev }
          delete copy[nid]
          return copy
        })
        void reloadNode(nid).catch(() => {})
      }
    })
    return () => {
      activeRef.current = false
      window.clearInterval(timer)
      off()
    }
  }, [reloadNode])

  const refreshSingleNode = useCallback(
    async (node: Node) => {
      if (node.revoked || isOfflineNode(node)) return
      setRefreshingIds((prev) => new Set(prev).add(node.id))
      try {
        const res = await api<{ connected: boolean; reported?: boolean }>(`/nodes/${encodeURIComponent(node.id)}/refresh`, 'POST', {})
        if (!activeRef.current) return
        await reloadNode(node.id).catch(() => {})
        if (!res?.connected) {
          setFeedbackMap((prev) => ({ ...prev, [node.id]: { text: '推送通道未连接，重连后自动同步', bad: false } }))
        } else if (res.reported) {
          setFeedbackMap((prev) => {
            const next = { ...prev }
            delete next[node.id]
            return next
          })
          toast(`节点「${node.name}」状态已更新。`)
        } else {
          setFeedbackMap((prev) => ({ ...prev, [node.id]: { text: '已请求上报，等待节点反馈…', bad: false } }))
        }
      } catch (err) {
        if (activeRef.current) {
          setFeedbackMap((prev) => ({
            ...prev,
            [node.id]: { text: err instanceof Error ? err.message : '请求刷新失败', bad: true },
          }))
        }
      } finally {
        if (activeRef.current) {
          setRefreshingIds((prev) => {
            const next = new Set(prev)
            next.delete(node.id)
            return next
          })
        }
      }
    },
    [reloadNode, toast],
  )

  useEffect(() => {
    const unregister = registerPageRefresh(async () => {
      const targets = nodesRef.current.filter((n) => n.role === role && !n.revoked && !isOfflineNode(n))
      await Promise.all(targets.map((n) => refreshSingleNode(n)))
    })
    return unregister
  }, [role, refreshSingleNode])

  const roleNodes = useMemo(() => nodes.filter((n) => n.role === role), [nodes, role])

  const defaultName = useMemo(() => {
    const used = new Set(roleNodes.map((n) => n.name.trim()))
    let num = 1
    while (used.has(String(num))) num++
    return String(num)
  }, [roleNodes])

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase()
    const currentNow = Math.max(now, serverNowMs())
    return roleNodes
      .filter((n) => {
        if (filter === 'online' && (n.disabled || isOfflineNode(n) || !heartbeatOnline(n, currentNow))) return false
        if (filter === 'offline' && !isOfflineNode(n)) return false
        if (filter === 'attention' && !needsAttention(n, currentNow)) return false
        if (filter === 'disabled' && !n.disabled && !n.revoked) return false
        if (!q) return true
        return [n.name, n.id, n.address, n.error, isOfflineNode(n) ? 'offline 脱机' : 'online 在线', tunnelSummaryText(n)].join(' ').toLowerCase().includes(q)
      })
      .sort((a, b) => Number(needsAttention(b, currentNow)) - Number(needsAttention(a, currentNow)) || byNameAndId(a, b))
  }, [roleNodes, filter, query, now])

  const selectedNode = useMemo(() => roleNodes.find((n) => n.id === selectedId) || null, [roleNodes, selectedId])

  const nodeMappings = useCallback(
    (id: string) => mappings.filter((m) => (isServer ? m.server_id === id : m.client_id === id)),
    [mappings, isServer],
  )

  const effectiveSources = useCallback(
    (node: Node) => {
      if (node.revoked) return []
      const ids = new Set(mappings.filter((m) => m.client_id === node.id).map((m) => m.server_id))
      return nodes.filter((n) => n.role === 'server' && !n.revoked && ids.has(n.id)).sort(byNameAndId)
    },
    [mappings, nodes],
  )

  // Spec 2.4: Reversible enable/disable executes directly + shows bottom Undo Snackbar!
  const toggleDisabled = async (node: Node) => {
    if (node.revoked) return
    const nextDisabled = !node.disabled
    triggerHaptic(12)
    try {
      const res = await api<{ connected: boolean }>(`/nodes/${encodeURIComponent(node.id)}/disabled`, 'POST', {
        disabled: nextDisabled,
      })
      await reload()
      const msg = isOfflineNode(node)
        ? nextDisabled
          ? `已标记停用「${node.name}」（需重导出脱机配置）`
          : `已标记启用「${node.name}」（需重导出脱机配置）`
        : !res?.connected
          ? nextDisabled
            ? `已标记停用「${node.name}」（重连后停止）`
            : `已标记启用「${node.name}」（重连后恢复）`
          : nextDisabled
            ? `已停用${roleLabel}「${node.name}」`
            : `已启用${roleLabel}「${node.name}」`
      showSnackbar(
        msg,
        async () => {
          await api(`/nodes/${encodeURIComponent(node.id)}/disabled`, 'POST', { disabled: !nextDisabled })
          await reload()
          toast(`已撤销对「${node.name}」的状态变更。`)
        },
        dict.common.undo,
      )
    } catch (err) {
      toast(err instanceof Error ? err.message : '操作失败', true)
    }
  }

  const handleCopy = async (text: string, id: string) => {
    try {
      await copyText(text)
      triggerHaptic(10)
      setCopiedId(id)
      window.setTimeout(() => setCopiedId((curr) => (curr === id ? '' : curr)), 2500)
    } catch {
      toast('复制失败，请手动复制。', true)
    }
  }

  const commitDanger = async () => {
    if (!dangerAction) return
    const { node, kind } = dangerAction
    const path = `/nodes/${encodeURIComponent(node.id)}`
    if (kind === 'revoke') {
      await api(`${path}/revoke`, 'POST', {})
      toast(`已吊销「${node.name}」的凭据。`)
    } else {
      await api(path, 'DELETE')
      if (selectedId === node.id) setSelectedId('')
      toast(`已永久删除「${node.name}」。`)
    }
    await reload()
  }

  const closeEditor = useCallback(() => setEditorOpen(false), [])
  const handleEditorSaved = useCallback(
    async (saved: Node) => {
      await reload()
      if (isOfflineNode(saved)) {
        toast('脱机节点已保存，请导出最新脱机配置部署到节点。')
        if (!editingNode) setOnboardingNode(saved)
      } else {
        toast('节点已保存，等待节点上报确认同步状态。')
        if (!editingNode && !saved.embedded) setOnboardingNode(saved)
      }
    },
    [editingNode, reload, toast],
  )
  const closeOnboarding = useCallback(() => setOnboardingNode(null), [])
  const handleOnboardingExported = useCallback(
    (nid: string) => {
      void reloadNode(nid).catch(() => {})
    },
    [reloadNode],
  )

  if (!loaded && loading) {
    return (
      <div className="panel">
        <EmptyState title="正在加载节点列表…" />
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

  const renderNow = Math.max(now, serverNowMs())

  const tablePane = (
    <div>
      {rows.length === 0 ? (
        <EmptyState
          icon={isServer ? <Server size={20} /> : <Laptop size={20} />}
          title={dict.nodes.noNodes}
          action={
            <button
              type="button"
              className="btn btn-sm btn-primary"
              onClick={() => {
                setEditingNode(null)
                setEditorOpen(true)
              }}
            >
              <Plus size={14} />
              <span>{isServer ? dict.nodes.newServer : dict.nodes.newClient}</span>
            </button>
          }
        />
      ) : (
        <>
          <div className="table-scroll desktop-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>{roleLabel}</th>
                  <th>在线状态</th>
                  {isServer && <th>隧道协议栈</th>}
                  <th>映射</th>
                  <th>配置同步</th>
                  <th style={{ textAlign: 'end' }}>操作</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((node) => {
                  const offline = isOfflineNode(node)
                  const st = presence(node, renderNow)
                  const rev = revisionState(node)
                  const mCount = nodeMappings(node.id).length
                  const fb = feedbackMap[node.id]
                  const isSelected = selectedId === node.id
                  const isBusyRefresh = refreshingIds.has(node.id)
                  return (
                    <tr key={node.id} className={isSelected ? 'is-selected' : ''}>
                      <td>
                        <button
                          type="button"
                          className="node-cell-trigger"
                          aria-expanded={isSelected}
                          onClick={() => setSelectedId((curr) => (curr === node.id ? '' : node.id))}
                        >
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                            <span className="node-name">{node.name}</span>
                            {node.embedded && <Badge text="内置" tone="accent" />}
                            {offline && <Badge text="脱机模式" tone="info" />}
                          </span>
                          <span className="cell-sub mono ltr-force tabular">
                            {offline ? '独立运行' : node.software_version || '未上报版本'} · {node.id.slice(0, 12)}
                          </span>
                        </button>
                      </td>

                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <Badge text={st.text} tone={st.tone} dot pulse={st.tone === 'good'} />
                          {!offline && (
                            <Popconfirm
                              title={`主动向「${node.name}」发送状态上报指令？`}
                              confirmLabel="立即刷新"
                              onConfirm={() => refreshSingleNode(node)}
                            >
                              {(toggle) => (
                                <Tooltip content="请求节点立即上报心跳与修订">
                                  <button
                                    type="button"
                                    className="icon-btn icon-btn-compact"
                                    disabled={node.revoked || isBusyRefresh}
                                    aria-label={`刷新节点 ${node.name}`}
                                    onClick={toggle}
                                  >
                                    <RefreshCw size={14} className={isBusyRefresh ? 'spin' : ''} />
                                  </button>
                                </Tooltip>
                              )}
                            </Popconfirm>
                          )}
                        </div>
                        <div className="cell-sub tabular" style={{ color: fb?.bad ? 'var(--bad)' : undefined }}>
                          {fb?.text || nodeSeenSummary(node, renderNow, true)}
                        </div>
                      </td>

                      {isServer && (
                        <td>
                          <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                            {tunnelBadges(node).map((b) => (
                              <Badge key={b.text} text={b.text} tone={b.tone} />
                            ))}
                          </div>
                          <div className="cell-sub mono ltr-force tabular" style={{ marginBlockStart: 3 }}>
                            {node.address ? endpoint(node.address, node.port) : '未配置入口'}
                          </div>
                        </td>
                      )}

                      <td className="tabular">{mCount}</td>

                      <td>
                        <Tooltip
                          content={
                            offline
                              ? `目标修订 r${node.desired_revision} · 已导出 r${node.exported_revision || 0}（脱机免心跳）`
                              : node.error || `目标修订 r${node.desired_revision} · 已应用 r${node.applied_revision}`
                          }
                        >
                          <Badge text={rev.text} tone={rev.tone} />
                        </Tooltip>
                      </td>

                      <td>
                        <div className="row-actions">
                          {!node.embedded && (
                            <button
                              type="button"
                              className="btn btn-sm btn-soft"
                              disabled={node.revoked}
                              onClick={() => setOnboardingNode(node)}
                            >
                              {offline ? <Download size={13} /> : <QrCode size={13} />}
                              <span>{offline ? '脱机配置' : dict.nodes.onboarding}</span>
                            </button>
                          )}
                          <button
                            type="button"
                            className="btn btn-sm btn-ghost"
                            disabled={node.revoked}
                            onClick={() => {
                              setEditingNode(node)
                              setEditorOpen(true)
                            }}
                          >
                            <Edit3 size={13} />
                            <span>{dict.common.edit}</span>
                          </button>

                          <Dropdown
                            menuLabel={`${node.name} 更多操作`}
                            trigger={(_open, toggle) => (
                              <button
                                type="button"
                                className="icon-btn icon-btn-compact"
                                aria-label={`${node.name} 更多操作`}
                                onClick={() => {
                                  if (window.innerWidth <= 768) setMobileSheetNode(node)
                                  else toggle()
                                }}
                              >
                                <MoreHorizontal size={16} />
                              </button>
                            )}
                            items={[
                              {
                                id: 'inspect',
                                label: isSelected ? '收起详情面板' : '查看节点详情',
                                icon: <Server size={14} />,
                                onSelect: () => setSelectedId((curr) => (curr === node.id ? '' : node.id)),
                              },
                              ...(role === 'client'
                                ? [
                                    {
                                      id: 'config',
                                      label: '查看派生隧道配置',
                                      icon: <FileCode2 size={14} />,
                                      disabled: node.revoked || node.disabled || !effectiveSources(node).length,
                                      onSelect: () => setConfigNode(node),
                                    },
                                  ]
                                : []),
                              {
                                id: 'toggle',
                                label: node.disabled ? '立即启用节点' : '停用节点（可撤销）',
                                icon: <Power size={14} />,
                                disabled: node.revoked,
                                onSelect: () => void toggleDisabled(node),
                              },
                              ...(!node.embedded
                                ? [
                                    ...(!offline
                                      ? [
                                          {
                                            id: 'revoke',
                                            label: '吊销节点凭据…',
                                            icon: <ShieldOff size={14} />,
                                            danger: true,
                                            disabled: node.revoked,
                                            separatorBefore: true,
                                            onSelect: () => setDangerAction({ node, kind: 'revoke' }),
                                          },
                                        ]
                                      : []),
                                    {
                                      id: 'delete',
                                      label: '永久删除节点…',
                                      icon: <Trash2 size={14} />,
                                      danger: true,
                                      separatorBefore: offline,
                                      onSelect: () => setDangerAction({ node, kind: 'delete' }),
                                    },
                                  ]
                                : []),
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

          {/* Dedicated Touch-Friendly Mobile Cards (<= 640px) */}
          <div className="mobile-cards" role="list" aria-label={`${roleLabel}卡片列表`}>
            {rows.map((node) => {
              const offline = isOfflineNode(node)
              const st = presence(node, renderNow)
              const rev = revisionState(node)
              const mCount = nodeMappings(node.id).length
              const isSelected = selectedId === node.id
              return (
                <article key={node.id} className={`mobile-card ${isSelected ? 'is-selected' : ''}`} role="listitem">
                  <div className="mobile-card-head">
                    <button
                      type="button"
                      className="node-cell-trigger"
                      onClick={() => setSelectedId((curr) => (curr === node.id ? '' : node.id))}
                    >
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                        <span className="node-name" style={{ fontSize: 15 }}>{node.name}</span>
                        {node.embedded && <Badge text="内置" tone="accent" />}
                        {offline && <Badge text="脱机模式" tone="info" />}
                      </span>
                      <span className="cell-sub mono ltr-force tabular">
                        {offline ? nodeSeenSummary(node, renderNow, true) : `${node.software_version || '未上报'} · ${seenText(node.last_seen, renderNow, true)}`}
                      </span>
                    </button>
                    <Badge text={st.text} tone={st.tone} dot pulse={st.tone === 'good'} />
                  </div>

                  <div className="mobile-card-meta">
                    {isServer && (
                      <>
                        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                          {tunnelBadges(node).map((b) => (
                            <Badge key={b.text} text={b.text} tone={b.tone} />
                          ))}
                        </div>
                        {node.address && (
                          <code className="cell-sub ltr-force tabular">{endpoint(node.address, node.port)}</code>
                        )}
                      </>
                    )}
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                      <span className="cell-sub tabular">关联映射 {mCount} 条</span>
                      <Badge text={rev.text} tone={rev.tone} />
                    </div>
                  </div>

                  <div className="mobile-card-actions">
                    {!node.embedded && (
                      <button
                        type="button"
                        className="btn btn-sm btn-soft"
                        disabled={node.revoked}
                        onClick={() => setOnboardingNode(node)}
                      >
                        {offline ? <Download size={14} /> : <QrCode size={14} />}
                        <span>{offline ? '脱机配置' : dict.nodes.onboarding}</span>
                      </button>
                    )}
                    <button
                      type="button"
                      className="btn btn-sm"
                      disabled={node.revoked}
                      onClick={() => {
                        setEditingNode(node)
                        setEditorOpen(true)
                      }}
                    >
                      <Edit3 size={14} />
                      <span>{dict.common.edit}</span>
                    </button>
                    <button
                      type="button"
                      className="icon-btn"
                      aria-label={`${node.name} 更多操作`}
                      onClick={() => setMobileSheetNode(node)}
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
  )

  const inspectorPane = selectedNode ? (
    <div style={{ padding: 18, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <h2 style={{ fontSize: 17 }}>{selectedNode.name}</h2>
            <Badge text={presence(selectedNode, renderNow).text} tone={presence(selectedNode, renderNow).tone} dot />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBlockStart: 4 }}>
            <code className="cell-sub ltr-force">{selectedNode.id}</code>
            <button
              type="button"
              className={`btn btn-sm btn-ghost ${copiedId === selectedNode.id ? 'copy-bounce' : ''}`}
              style={{ minWidth: 34, minHeight: 34, padding: '0 8px' }}
              aria-label="复制节点 ID"
              onClick={() => void handleCopy(selectedNode.id, selectedNode.id)}
            >
              {copiedId === selectedNode.id ? <Check size={12} style={{ color: 'var(--good)' }} /> : <Copy size={12} />}
            </button>
          </div>
        </div>
        <button type="button" className="icon-btn icon-btn-compact" aria-label="关闭详情" onClick={() => setSelectedId('')}>
          <X size={16} />
        </button>
      </div>

      {selectedNode.error && !isOfflineNode(selectedNode) && <Alert tone="bad">{selectedNode.error}</Alert>}
      {attentionReasons(selectedNode, renderNow).length > 0 && (!selectedNode.error || isOfflineNode(selectedNode)) && (
        <Alert tone="warn">待排查项：{attentionReasons(selectedNode, renderNow).join(' · ')}</Alert>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 10 }}>
        <div className="inspector-card" style={{ padding: 12 }}>
          <div className="cell-sub">{isOfflineNode(selectedNode) ? '运行模式' : '软件版本（节点上报）'}</div>
          <div className="mono tabular ltr-force" style={{ marginBlockStart: 4, fontWeight: 'var(--fw-medium)' }}>
            {isOfflineNode(selectedNode) ? '脱机独立运行' : selectedNode.software_version || '未上报'}
          </div>
          <div className="cell-sub mono ltr-force">
            {isOfflineNode(selectedNode) ? '免控制面连接 · 免心跳' : selectedNode.software_commit ? selectedNode.software_commit.slice(0, 10) : '—'}
          </div>
        </div>
        <div className="inspector-card" style={{ padding: 12 }}>
          <div className="cell-sub">{isOfflineNode(selectedNode) ? '脱机配置导出' : '配置修订同步'}</div>
          <div className="tabular" style={{ marginBlockStart: 4, fontWeight: 'var(--fw-medium)' }}>
            {isOfflineNode(selectedNode)
              ? `已导出 r${selectedNode.exported_revision || 0} / r${selectedNode.desired_revision}`
              : `r${selectedNode.applied_revision} / r${selectedNode.desired_revision}`}
          </div>
          <div className="cell-sub tabular">
            {isOfflineNode(selectedNode) ? '导出文件或命令独立启动' : seenText(selectedNode.last_seen, renderNow, false)}
          </div>
        </div>
      </div>

      {isServer ? (
        <div className="inspector-card" style={{ padding: 14, display: 'grid', gap: 10 }}>
          <span className="form-section-title">隧道与连接入口</span>
          <div style={{ fontSize: 13 }}>{tunnelSummaryText(selectedNode)}</div>
          <div className="cell-sub mono ltr-force">
            本地绑定：{endpoint(selectedNode.tunnel?.listen_host || '127.0.0.1', selectedNode.tunnel?.listen_port || 0)}
          </div>
          {(selectedNode.connect_endpoints || []).map((ep) => (
            <div key={ep.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 12.5 }}>
              <span>{ep.name}</span>
              <code className="ltr-force tabular">{endpoint(ep.host, ep.port)}</code>
            </div>
          ))}
        </div>
      ) : (
        <div className="inspector-card" style={{ padding: 14, display: 'grid', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span className="form-section-title">派生网关来源</span>
            <button
              type="button"
              className="btn btn-sm btn-soft"
              disabled={selectedNode.revoked || selectedNode.disabled || !effectiveSources(selectedNode).length}
              onClick={() => setConfigNode(selectedNode)}
            >
              <FileCode2 size={13} />
              <span>查看完整 JSON</span>
            </button>
          </div>
          {effectiveSources(selectedNode).length === 0 ? (
            <span className="cell-sub">当前未通过端口映射关联可用公网网关。</span>
          ) : (
            effectiveSources(selectedNode).map((srv) => (
              <div key={srv.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 13 }}>
                <span>{srv.name}</span>
                <code className="cell-sub ltr-force">{endpoint(srv.address, srv.port)}</code>
              </div>
            ))
          )}
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button
          type="button"
          className="btn btn-sm btn-primary"
          disabled={selectedNode.revoked}
          onClick={() => {
            setEditingNode(selectedNode)
            setEditorOpen(true)
          }}
        >
          <Edit3 size={14} />
          <span>编辑配置</span>
        </button>
        {!selectedNode.embedded && (
          <button
            type="button"
            className="btn btn-sm btn-soft"
            disabled={selectedNode.revoked}
            onClick={() => setOnboardingNode(selectedNode)}
          >
            {isOfflineNode(selectedNode) ? <Download size={14} /> : <QrCode size={14} />}
            <span>{isOfflineNode(selectedNode) ? '导出脱机配置' : '快捷接入'}</span>
          </button>
        )}
        <button
          type="button"
          className="btn btn-sm"
          disabled={selectedNode.revoked}
          onClick={() => void toggleDisabled(selectedNode)}
        >
          <Power size={14} />
          <span>{selectedNode.disabled ? '启用' : '停用'}</span>
        </button>
        {!selectedNode.embedded && !isOfflineNode(selectedNode) && (
          <button
            type="button"
            className="btn btn-sm btn-danger-ghost"
            disabled={selectedNode.revoked}
            onClick={() => setDangerAction({ node: selectedNode, kind: 'revoke' })}
          >
            <ShieldOff size={14} />
            <span>吊销凭据</span>
          </button>
        )}
      </div>
    </div>
  ) : null

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div className="toolbar">
        <Segmented<NodeFilter>
          ariaLabel="节点状态筛选"
          value={filter}
          onChange={setFilter}
          options={[
            { value: 'all', label: `${dict.common.all} (${roleNodes.length})` },
            { value: 'online', label: dict.common.online },
            { value: 'offline', label: '脱机独立' },
            { value: 'attention', label: dict.common.attention },
            { value: 'disabled', label: dict.common.disabled },
          ]}
        />

        <div className="toolbar-search">
          <Search size={15} className="toolbar-search-icon" />
          <input
            type="search"
            value={query}
            aria-label={`搜索${roleLabel}`}
            placeholder={dict.nodes.searchPlaceholder}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>

        <button
          type="button"
          className="btn btn-primary"
          onClick={() => {
            setEditingNode(null)
            setEditorOpen(true)
          }}
        >
          <Plus size={16} />
          <span>{isServer ? dict.nodes.newServer : dict.nodes.newClient}</span>
        </button>
      </div>

      {/* Spec 7.5 Resizable SplitPane on desktop/tablet; Spec 2.3 BottomSheet Drawer on mobile (<= 768px) */}
      <SplitPane
        start={tablePane}
        end={inspectorPane}
        showEnd={!!selectedNode && !isMobileViewport}
        defaultRatio={64}
        restoreEndLabel="展开节点详情"
      />

      <Drawer
        open={!!selectedNode && isMobileViewport}
        onClose={() => setSelectedId('')}
        title={selectedNode?.name || ''}
        hideSave
      >
        {inspectorPane}
      </Drawer>

      <NodeEditorDrawer
        open={editorOpen}
        role={role}
        node={editingNode}
        defaultName={defaultName}
        onClose={closeEditor}
        onSaved={handleEditorSaved}
      />

      <NodeOnboardingModal
        node={onboardingNode}
        onClose={closeOnboarding}
        onExported={handleOnboardingExported}
      />

      {/* Mobile ActionSheet (Spec 2.6) */}
      <ActionSheet
        open={!!mobileSheetNode}
        title={mobileSheetNode ? `${roleLabel} · ${mobileSheetNode.name}` : undefined}
        onClose={() => setMobileSheetNode(null)}
        options={
          mobileSheetNode
            ? [
                {
                  label: '查看详情与遥测',
                  icon: <Server size={16} />,
                  onSelect: () => setSelectedId(mobileSheetNode.id),
                },
                {
                  label: '编辑配置',
                  icon: <Edit3 size={16} />,
                  disabled: mobileSheetNode.revoked,
                  onSelect: () => {
                    setEditingNode(mobileSheetNode)
                    setEditorOpen(true)
                  },
                },
                ...(!mobileSheetNode.embedded
                  ? [
                      {
                        label: isOfflineNode(mobileSheetNode) ? '导出脱机配置' : '快捷接入命令',
                        icon: isOfflineNode(mobileSheetNode) ? <Download size={16} /> : <QrCode size={16} />,
                        disabled: mobileSheetNode.revoked,
                        onSelect: () => setOnboardingNode(mobileSheetNode),
                      },
                    ]
                  : []),
                {
                  label: mobileSheetNode.disabled ? '启用节点' : '停用节点（可撤销）',
                  icon: <Power size={16} />,
                  disabled: mobileSheetNode.revoked,
                  onSelect: () => void toggleDisabled(mobileSheetNode),
                },
                ...(!mobileSheetNode.embedded
                  ? [
                      ...(!isOfflineNode(mobileSheetNode)
                        ? [
                            {
                              label: '吊销节点凭据',
                              icon: <ShieldOff size={16} />,
                              danger: true,
                              disabled: mobileSheetNode.revoked,
                              onSelect: () => setDangerAction({ node: mobileSheetNode, kind: 'revoke' }),
                            },
                          ]
                        : []),
                      {
                        label: '永久删除节点',
                        icon: <Trash2 size={16} />,
                        danger: true,
                        onSelect: () => setDangerAction({ node: mobileSheetNode, kind: 'delete' }),
                      },
                    ]
                  : []),
              ]
            : []
        }
      />

      {/* Irreversible AlertDialog (Spec 2.4 — blocks backdrop & Esc, quantifies loss) */}
      <AlertDialog
        open={!!dangerAction}
        onClose={() => setDangerAction(null)}
        title={dangerAction?.kind === 'revoke' ? `吊销「${dangerAction.node.name}」凭据` : `永久删除「${dangerAction?.node.name || ''}」`}
        lossSummary={
          dangerAction?.kind === 'revoke'
            ? `吊销后「${dangerAction.node.name}」将失去控制面认证权限。`
            : `将删除「${dangerAction?.node.name || ''}」及关联的 ${dangerAction ? nodeMappings(dangerAction.node.id).length : 0} 条映射。`
        }
        confirmLabel={
          dangerAction?.kind === 'revoke'
            ? '确认吊销'
            : `确认删除`
        }
        onConfirm={commitDanger}
      />

      {/* Client Effective Derived Config Modal (lg: 720px) */}
      <Modal
        open={!!configNode}
        onClose={() => setConfigNode(null)}
        size="lg"
        title={`派生配置 · ${configNode?.name || ''}`}
        hideSave
      >
        {configNode &&
          effectiveSources(configNode).map((source) => {
            const jsonText = source.client_tunnel ? JSON.stringify(source.client_tunnel, null, 2) : '服务端尚无下发模板'
            return (
              <div key={source.id} className="field">
                <div className="field-label">
                  <span>来源网关：{source.name} · <code className="ltr-force">{endpoint(source.address, source.port)}</code></span>
                  <button
                    type="button"
                    className={`btn btn-sm btn-ghost ${copiedId === `cfg-${source.id}` ? 'copy-bounce' : ''}`}
                    onClick={() => void handleCopy(jsonText, `cfg-${source.id}`)}
                  >
                    {copiedId === `cfg-${source.id}` ? <Check size={13} style={{ color: 'var(--good)' }} /> : <Copy size={13} />}
                    <span>{copiedId === `cfg-${source.id}` ? '已复制' : '复制 JSON'}</span>
                  </button>
                </div>
                <textarea
                  className="mono ltr-force"
                  rows={9}
                  readOnly
                  spellCheck={false}
                  value={jsonText}
                  onClick={(e) => e.currentTarget.select()}
                />
              </div>
            )
          })}
      </Modal>
    </div>
  )
}
