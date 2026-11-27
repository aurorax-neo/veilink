import { useEffect, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import {
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  Bell,
  CheckCheck,
  Laptop,
  RefreshCw,
  RotateCcw,
  Server,
  ShieldCheck,
  WifiOff,
  X,
} from 'lucide-react'
import { useConsole } from '../context/ConsoleContext'
import { attentionReasons, byNameAndId, seenText } from '../format'
import type { PageId } from '../types'
import { Badge, Tooltip } from './ui/Badge'

interface NoticeEntry {
  key: string
  severity: 'bad' | 'warn' | 'info'
  category: 'server' | 'client' | 'system'
  title: string
  subtitle: string
  reasons: string[]
  targetPage: PageId
  actionLabel: string
}

export function NotificationCenter() {
  const {
    nodes,
    versionWarning,
    trafficError,
    statusError,
    streamState,
    navigate,
    triggerPageRefresh,
    loading,
    refreshing,
    dict,
    notificationsOpen,
    setNotificationsOpen,
  } = useConsole()

  const triggerRef = useRef<HTMLButtonElement>(null)
  const popRef = useRef<HTMLDivElement>(null)
  const [pos, setPos] = useState<{ top: number; left: number; width: number } | null>(null)
  const [dismissedKeys, setDismissedKeys] = useState<string[]>([])
  const [showDismissed, setShowDismissed] = useState(false)

  const allNotices = useMemo<NoticeEntry[]>(() => {
    const list: NoticeEntry[] = []

    const attentionNodes = nodes
      .filter((n) => attentionReasons(n).length > 0)
      .sort((a, b) => {
        const aErr = a.error ? 0 : 1
        const bErr = b.error ? 0 : 1
        return aErr - bErr || byNameAndId(a, b)
      })

    for (const node of attentionNodes) {
      const reasons = attentionReasons(node)
      const isBad = Boolean(node.error)
      const subtitle = node.error
        ? node.error
        : `${node.role === 'server' ? '公网网关' : '内网节点'} · ${seenText(node.last_seen, Date.now(), true)}`
      list.push({
        key: `node:${node.id}:${reasons.join('|')}:${node.error || ''}`,
        severity: isBad ? 'bad' : 'warn',
        category: node.role === 'server' ? 'server' : 'client',
        title: node.name,
        subtitle,
        reasons,
        targetPage: node.role === 'server' ? 'servers' : 'clients',
        actionLabel: '排查',
      })
    }

    if (trafficError) {
      list.push({
        key: `traffic:${trafficError}`,
        severity: 'bad',
        category: 'system',
        title: '流量统计读取异常',
        subtitle: trafficError,
        reasons: ['遥测异常'],
        targetPage: 'proxies',
        actionLabel: '查看映射',
      })
    }

    if (statusError) {
      list.push({
        key: `status:${statusError}`,
        severity: 'warn',
        category: 'system',
        title: '隧道状态同步提示',
        subtitle: statusError,
        reasons: ['状态降级'],
        targetPage: 'proxies',
        actionLabel: '查看映射',
      })
    }

    if (versionWarning) {
      list.push({
        key: `version:${versionWarning}`,
        severity: 'warn',
        category: 'system',
        title: '版本兼容性提示',
        subtitle: versionWarning,
        reasons: ['版本告警'],
        targetPage: 'settings',
        actionLabel: '查看设置',
      })
    }

    if (streamState === 'reconnecting') {
      list.push({
        key: 'sse:reconnecting',
        severity: 'info',
        category: 'system',
        title: '事件流重连中',
        subtitle: '',
        reasons: [],
        targetPage: 'logs',
        actionLabel: '日志',
      })
    }

    return list
  }, [nodes, statusError, streamState, trafficError, versionWarning])

  const dismissedSet = useMemo(() => new Set(dismissedKeys), [dismissedKeys])
  const activeNotices = useMemo(() => allNotices.filter((item) => !dismissedSet.has(item.key)), [allNotices, dismissedSet])
  const visibleNotices = showDismissed ? allNotices : activeNotices
  const hiddenCount = allNotices.length - activeNotices.length
  const hasError = activeNotices.some((item) => item.severity === 'bad')
  const badgeCount = activeNotices.length

  useEffect(() => {
    if (!notificationsOpen) {
      setPos(null)
      return
    }
    const updatePos = () => {
      const vw = window.innerWidth
      if (vw <= 640) {
        setPos({ top: 62, left: 12, width: Math.max(260, vw - 24) })
        return
      }
      const rect = triggerRef.current?.getBoundingClientRect()
      const width = Math.min(392, vw - 24)
      if (!rect) {
        setPos({ top: 62, left: Math.max(12, vw - width - 12), width })
        return
      }
      const isRtl = document.documentElement.dir === 'rtl'
      const rawLeft = isRtl ? rect.left : rect.right - width
      const left = Math.min(vw - width - 12, Math.max(12, rawLeft))
      setPos({ top: Math.round(rect.bottom + 8), left: Math.round(left), width })
    }

    updatePos()
    const onDocDown = (e: MouseEvent) => {
      const target = e.target as Node
      if (triggerRef.current?.contains(target) || popRef.current?.contains(target)) return
      setNotificationsOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setNotificationsOpen(false)
    }
    document.addEventListener('mousedown', onDocDown)
    window.addEventListener('keydown', onKey)
    window.addEventListener('resize', updatePos)
    window.addEventListener('scroll', updatePos, true)
    return () => {
      document.removeEventListener('mousedown', onDocDown)
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('resize', updatePos)
      window.removeEventListener('scroll', updatePos, true)
    }
  }, [notificationsOpen, setNotificationsOpen])

  const dismissOne = (key: string) => {
    setDismissedKeys((curr) => (curr.includes(key) ? curr : [...curr, key]))
  }

  const dismissAll = () => {
    setDismissedKeys(allNotices.map((item) => item.key))
    setShowDismissed(false)
  }

  const restoreAll = () => {
    setDismissedKeys([])
    setShowDismissed(false)
  }

  const renderIcon = (item: NoticeEntry) => {
    if (item.category === 'server') return <Server size={15} />
    if (item.category === 'client') return <Laptop size={15} />
    if (item.key === 'sse:reconnecting') return <WifiOff size={15} />
    if (item.severity === 'bad') return <AlertCircle size={15} />
    return <AlertTriangle size={15} />
  }

  return (
    <>
      <Tooltip content={badgeCount > 0 ? `${dict.common.notifications}（${badgeCount}）` : dict.common.notifications}>
        <button
          ref={triggerRef}
          type="button"
          className={`icon-btn notif-trigger ${notificationsOpen ? 'is-open' : ''}`}
          aria-label={badgeCount > 0 ? `${dict.common.notifications}，${badgeCount} 项待处理` : dict.common.notifications}
          aria-haspopup="dialog"
          aria-expanded={notificationsOpen}
          onClick={() => setNotificationsOpen(!notificationsOpen)}
        >
          <Bell size={16} />
          {badgeCount > 0 && (
            <span className={`notif-badge tabular ${hasError ? 'is-bad' : 'is-warn'}`}>
              {badgeCount > 99 ? '99+' : badgeCount}
            </span>
          )}
        </button>
      </Tooltip>

      {notificationsOpen &&
        pos &&
        createPortal(
          <div
            ref={popRef}
            className="notif-popover"
            role="dialog"
            aria-label={dict.common.notifications}
            style={{
              top: pos.top,
              left: pos.left,
              width: pos.width,
            }}
          >
            <header className="notif-head">
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}>
                <h2 style={{ fontSize: 14, fontWeight: 'var(--fw-semibold)' }}>{dict.common.notifications}</h2>
                {badgeCount > 0 ? (
                  <Badge text={`${badgeCount} 项待处理`} tone={hasError ? 'bad' : 'warn'} />
                ) : (
                  <Badge text="全部正常" tone="good" />
                )}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <Tooltip content={dict.common.refresh}>
                  <button
                    type="button"
                    className="icon-btn icon-btn-compact"
                    aria-label={dict.common.refresh}
                    disabled={loading || refreshing}
                    onClick={() => void triggerPageRefresh()}
                  >
                    <RefreshCw size={14} className={loading || refreshing ? 'spin' : ''} />
                  </button>
                </Tooltip>
                {badgeCount > 0 && (
                  <Tooltip content="当前会话全部已读">
                    <button
                      type="button"
                      className="icon-btn icon-btn-compact"
                      aria-label="全部标为已读"
                      onClick={dismissAll}
                    >
                      <CheckCheck size={15} />
                    </button>
                  </Tooltip>
                )}
                <button
                  type="button"
                  className="icon-btn icon-btn-compact"
                  aria-label={dict.common.close}
                  onClick={() => setNotificationsOpen(false)}
                >
                  <X size={15} />
                </button>
              </div>
            </header>

            <div className="notif-list">
              {visibleNotices.length === 0 ? (
                <div className="notif-empty">
                  <span className="notif-empty-icon" aria-hidden="true">
                    <ShieldCheck size={20} />
                  </span>
                  <strong>{dict.dashboard.noAttention}</strong>
                  {hiddenCount > 0 && <span>已忽略 {hiddenCount} 条</span>}
                </div>
              ) : (
                visibleNotices.map((item) => {
                  const isDismissed = dismissedSet.has(item.key)
                  return (
                    <div key={item.key} className={`notif-item is-${item.severity} ${isDismissed ? 'is-muted' : ''}`}>
                      <span className={`notif-item-icon is-${item.severity}`} aria-hidden="true">
                        {renderIcon(item)}
                      </span>
                      <div className="notif-item-body">
                        <div className="notif-item-top">
                          <strong className="notif-item-title">{item.title}</strong>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                            <button
                              type="button"
                              className="notif-action-link"
                              onClick={() => {
                                navigate(item.targetPage)
                                setNotificationsOpen(false)
                              }}
                            >
                              <span>{item.actionLabel}</span>
                              <ArrowRight size={12} className="rtl-flip" />
                            </button>
                            {!isDismissed && (
                              <button
                                type="button"
                                className="notif-dismiss-btn"
                                aria-label={`忽略 ${item.title}`}
                                onClick={() => dismissOne(item.key)}
                              >
                                <X size={13} />
                              </button>
                            )}
                          </div>
                        </div>
                        <p className="notif-item-sub">{item.subtitle}</p>
                        {item.reasons.length > 0 && (
                          <div className="notif-item-tags">
                            {item.reasons.map((r) => (
                              <Badge
                                key={r}
                                text={r}
                                tone={item.severity === 'bad' ? 'bad' : item.severity === 'warn' ? 'warn' : 'accent'}
                              />
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )
                })
              )}
            </div>

            {hiddenCount > 0 && (
              <footer className="notif-foot">
                <button
                  type="button"
                  className="btn btn-sm btn-ghost"
                  onClick={() => setShowDismissed((v) => !v)}
                >
                  <span>{showDismissed ? '仅看未读' : `查看已忽略（${hiddenCount}）`}</span>
                </button>
                <button type="button" className="btn btn-sm btn-ghost" onClick={restoreAll}>
                  <RotateCcw size={13} />
                  <span>恢复提醒</span>
                </button>
              </footer>
            )}
          </div>,
          document.body,
        )}
    </>
  )
}
