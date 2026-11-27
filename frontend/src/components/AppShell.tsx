import { useEffect, useMemo, useState, type ReactNode } from 'react'
import {
  Activity,
  ArrowLeftRight,
  Compass,
  FileClock,
  Globe,
  HardDrive,
  Laptop,
  LayoutDashboard,
  LogOut,
  Menu,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  RefreshCw,
  Search,
  Server,
  Settings,
  Sun,
  Terminal,
  X,
} from 'lucide-react'
import { useConsole } from '../context/ConsoleContext'
import { LOCALES } from '../i18n'
import type { PageId } from '../types'
import { NotificationCenter } from './NotificationCenter'
import { Badge, Tooltip } from './ui/Badge'
import { CommandPalette, type CommandEntry } from './ui/CommandPalette'
import { Dropdown } from './ui/Controls'
import { Tour, type TourStep } from './ui/Tour'

const NAV_GROUPS: Array<{
  key: 'overview' | 'network' | 'observability' | 'system'
  items: PageId[]
}> = [
  { key: 'overview', items: ['dashboard'] },
  { key: 'network', items: ['servers', 'clients', 'proxies'] },
  { key: 'observability', items: ['logs', 'audit'] },
  { key: 'system', items: ['settings'] },
]

function navIcon(id: PageId) {
  switch (id) {
    case 'dashboard':
      return <LayoutDashboard size={17} />
    case 'servers':
      return <Server size={17} />
    case 'clients':
      return <Laptop size={17} />
    case 'proxies':
      return <ArrowLeftRight size={17} />
    case 'logs':
      return <Terminal size={17} />
    case 'audit':
      return <FileClock size={17} />
    case 'settings':
      return <Settings size={17} />
  }
}

export function AppShell({ children }: { children: ReactNode }) {
  const {
    page,
    navigate,
    requestLogout,
    currentUser,
    nodes,
    mappings,
    loading,
    refreshing,
    triggerPageRefresh,
    software,
    versionError,
    reloadVersion,
    streamState,
    theme,
    toggleTheme,
    locale,
    setLocale,
    dict,
    tourOpen,
    setTourOpen,
  } = useConsole()

  const [isMobileViewport, setIsMobileViewport] = useState(() =>
    typeof window !== 'undefined' ? window.innerWidth <= 768 : false,
  )
  const [collapsed, setCollapsed] = useState(() =>
    typeof window !== 'undefined' ? window.innerWidth >= 769 && window.innerWidth <= 1180 : false,
  )
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const [cmdkOpen, setCmdkOpen] = useState(false)

  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return
    const mqMobile = window.matchMedia('(max-width: 768px)')
    const mqTablet = window.matchMedia('(min-width: 769px) and (max-width: 1180px)')
    const sync = () => {
      setIsMobileViewport(mqMobile.matches)
      if (!mqMobile.matches) {
        setMobileMenuOpen(false)
        setCollapsed(mqTablet.matches)
      }
    }
    sync()
    mqMobile.addEventListener?.('change', sync)
    mqTablet.addEventListener?.('change', sync)
    return () => {
      mqMobile.removeEventListener?.('change', sync)
      mqTablet.removeEventListener?.('change', sync)
    }
  }, [])

  const railCollapsed = !isMobileViewport && collapsed

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setCmdkOpen((v) => !v)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const serverCount = useMemo(() => nodes.filter((n) => n.role === 'server').length, [nodes])
  const clientCount = useMemo(() => nodes.filter((n) => n.role === 'client').length, [nodes])

  const badgeCount = (id: PageId): { count?: number; warn?: boolean } => {
    if (id === 'servers') return { count: serverCount }
    if (id === 'clients') return { count: clientCount }
    if (id === 'proxies') return { count: mappings.length }
    return {}
  }

  const sseLabel =
    streamState === 'connected'
      ? dict.common.sseConnected
      : streamState === 'reconnecting' || streamState === 'connecting'
        ? dict.common.sseReconnecting
        : dict.common.sseDisconnected
  const sseTone = streamState === 'connected' ? 'good' : streamState === 'reconnecting' || streamState === 'connecting' ? 'warn' : 'neutral'

  const commands = useMemo<CommandEntry[]>(() => {
    const navCmds: CommandEntry[] = (['dashboard', 'servers', 'clients', 'proxies', 'logs', 'audit', 'settings'] as PageId[]).map(
      (id) => ({
        id: `nav-${id}`,
        group: '页面导航',
        label: dict.pages[id].title,
        hint: dict.pages[id].subtitle,
        icon: navIcon(id),
        onSelect: () => navigate(id),
      }),
    )
    const nodeCmds: CommandEntry[] = nodes.slice(0, 12).map((n) => ({
      id: `node-${n.id}`,
      group: n.role === 'server' ? '公网网关' : '内网节点',
      label: n.name,
      hint: n.address ? `${n.address}:${n.port}` : n.id.slice(0, 12),
      icon: n.role === 'server' ? <Server size={15} /> : <Laptop size={15} />,
      onSelect: () => navigate(n.role === 'server' ? 'servers' : 'clients'),
    }))
    const actionCmds: CommandEntry[] = [
      {
        id: 'act-theme',
        group: '快捷操作',
        label: theme === 'dark' ? dict.common.themeLight : dict.common.themeDark,
        icon: theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />,
        onSelect: toggleTheme,
      },
      {
        id: 'act-refresh',
        group: '快捷操作',
        label: dict.common.refresh,
        icon: <RefreshCw size={15} />,
        onSelect: () => void triggerPageRefresh(),
      },
      {
        id: 'act-tour',
        group: '快捷操作',
        label: dict.common.tour,
        icon: <Compass size={15} />,
        onSelect: () => setTourOpen(true),
      },
    ]
    return [...navCmds, ...nodeCmds, ...actionCmds]
  }, [dict, navigate, nodes, setTourOpen, theme, toggleTheme, triggerPageRefresh])

  const tourSteps: TourStep[] = [
    {
      selector: '[data-tour="sidebar"]',
      title: '分层导航工作台',
      description: '按「概览 / 网络拓扑 / 可观测性 / 系统」分区组织，并支持折叠为图标栏释放更大视野。',
    },
    {
      selector: '[data-tour="cmdk"]',
      title: '全局快速跳转（⌘K / Ctrl+K）',
      description: '随时呼出命令面板，跨页面检索任意网关、客户端、端口映射或快速切换主题与刷新。',
    },
    {
      selector: '[data-tour="sse-pill"]',
      title: 'SSE 实时遥测连接',
      description: '控制平面通过 Server-Sent Events 毫秒级接收节点心跳、隧道状态与实时运行日志。',
    },
    {
      selector: '[data-tour="page-refresh"]',
      title: '主动唤醒节点上报',
      description: '点击刷新不仅重新拉取状态，还会通过控制通道主动唤醒在线节点立即回传最新修订与应用结果。',
    },
  ]

  const activeLocale = LOCALES.find((l) => l.code === locale)

  return (
    <>
      <div className={`app-shell ${railCollapsed ? 'sidebar-collapsed' : ''}`}>
        {mobileMenuOpen && (
          <div
            className="overlay-backdrop"
            style={{ zIndex: 1440 }}
            onClick={() => setMobileMenuOpen(false)}
          />
        )}

        <aside className={`app-sidebar ${mobileMenuOpen ? 'mobile-open' : ''}`} data-tour="sidebar" aria-label="主导航侧栏">
          <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
            <div className="brand-bar">
              <a
                className="brand-link"
                href="#/dashboard"
                onClick={(e) => {
                  e.preventDefault()
                  navigate('dashboard')
                  setMobileMenuOpen(false)
                }}
              >
                <span className="brand-logo" aria-hidden="true">
                  <svg viewBox="0 0 32 32" width={18} height={18} fill="currentColor">
                    <path d="M7.5 8.5h4.4L16 20.2 20.1 8.5H24.5L17.4 24.5h-2.8L7.5 8.5z" />
                  </svg>
                </span>
                {!railCollapsed && <span>{dict.appName}</span>}
              </a>

              <button
                type="button"
                className="icon-btn icon-btn-compact"
                aria-label={isMobileViewport ? dict.common.close : railCollapsed ? '展开侧边栏' : '折叠侧边栏'}
                onClick={() => {
                  if (isMobileViewport) setMobileMenuOpen(false)
                  else setCollapsed((v) => !v)
                }}
              >
                {isMobileViewport ? <X size={16} /> : railCollapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
              </button>
            </div>

            <nav className="nav-scroll" aria-label="控制台导航">
              {NAV_GROUPS.map((group) => (
                <div key={group.key} className="nav-group">
                  {!railCollapsed && <div className="nav-group-label">{dict.navGroups[group.key]}</div>}
                  {group.items.map((id) => {
                    const meta = badgeCount(id)
                    return (
                      <button
                        key={id}
                        type="button"
                        className="nav-item"
                        aria-current={page === id ? 'page' : undefined}
                        title={railCollapsed ? dict.pages[id].title : undefined}
                        onClick={() => {
                          navigate(id)
                          setMobileMenuOpen(false)
                        }}
                      >
                        <span className="nav-item-icon inline-icon" aria-hidden="true">
                          {navIcon(id)}
                        </span>
                        {!railCollapsed && (
                          <>
                            <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                              {dict.pages[id].title}
                            </span>
                            {meta.count !== undefined && (
                              <span className={`nav-item-count tabular ${meta.warn ? 'has-warn' : ''}`}>
                                {meta.count}
                              </span>
                            )}
                          </>
                        )}
                      </button>
                    )
                  })}
                </div>
              ))}
            </nav>
          </div>

          <div className="sidebar-foot">
            {!railCollapsed && currentUser?.email && (
              <button
                type="button"
                className="nav-item"
                style={{ minHeight: 38, marginBlockEnd: 2 }}
                title={currentUser.email}
                onClick={() => {
                  navigate('settings')
                  setMobileMenuOpen(false)
                }}
              >
                <span className="sidebar-avatar" aria-hidden="true">
                  {currentUser.email.slice(0, 1).toUpperCase()}
                </span>
                <span className="ltr-force" style={{ fontSize: 12.5, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {currentUser.email}
                </span>
              </button>
            )}
            {!railCollapsed && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '4px 10px', fontSize: 12, color: 'var(--text-muted)' }}>
                <span className="inline-icon" style={{ gap: 6 }}>
                  <HardDrive size={13} />
                  <span className="tabular ltr-force">{software?.backend_version || 'veilink'}</span>
                </span>
                <span className="tabular ltr-force">{software?.api_version || 'v1'}</span>
              </div>
            )}
            <button
              type="button"
              className="nav-item"
              title={railCollapsed ? dict.common.signOut : undefined}
              onClick={() => {
                setMobileMenuOpen(false)
                requestLogout()
              }}
            >
              <span className="inline-icon" aria-hidden="true"><LogOut size={16} /></span>
              {!railCollapsed && <span>{dict.common.signOut}</span>}
            </button>
          </div>
        </aside>

        <div className="app-workspace">
          <header className="app-topbar">
            <div className="topbar-start">
              <button
                type="button"
                className="icon-btn mobile-menu-btn"
                aria-label="打开导航菜单"
                onClick={() => setMobileMenuOpen(true)}
              >
                <Menu size={18} />
              </button>
              <nav className="breadcrumb" aria-label="面包屑">
                <span>{dict.controlPlane}</span>
                <span aria-hidden="true">/</span>
                <strong>{dict.pages[page].title}</strong>
              </nav>
            </div>

            <div className="topbar-end">
              <button
                type="button"
                className="cmdk-trigger"
                data-tour="cmdk"
                aria-label={dict.common.commandPalette}
                onClick={() => setCmdkOpen(true)}
              >
                <Search size={14} />
                <span className="topbar-desktop-only">{dict.common.commandPalette}</span>
                <span className="cmdk-kbd ltr-force topbar-desktop-only">⌘K</span>
              </button>

              <span data-tour="sse-pill" className="topbar-desktop-only">
                <Tooltip content="Server-Sent Events 实时事件推送通道状态">
                  <Badge text={sseLabel} tone={sseTone} dot pulse={streamState === 'connected'} />
                </Tooltip>
              </span>

              <span className="topbar-desktop-only">
                <Dropdown
                  menuLabel="版本信息"
                  trigger={(_open, toggle) => (
                    <button type="button" className="btn btn-sm btn-ghost tabular" onClick={toggle}>
                      <Activity size={14} />
                      <span className="ltr-force">{software?.backend_version || (versionError ? '—' : '…')}</span>
                    </button>
                  )}
                  items={[
                    {
                      id: 'ver-backend',
                      label: `后端版本: ${software?.backend_version || '未知'}`,
                      disabled: true,
                      onSelect: () => {},
                    },
                    {
                      id: 'ver-api',
                      label: `API 契约: ${software?.api_version || 'v1'}`,
                      disabled: true,
                      onSelect: () => {},
                    },
                    {
                      id: 'ver-web',
                      label: `前端栈: React 19 (${software?.web_version && software.web_version !== 'prebundled' ? software.web_version : software?.backend_version || 'embedded'})`,
                      disabled: true,
                      onSelect: () => {},
                    },
                    {
                      id: 'ver-retry',
                      label: '重新获取版本',
                      separatorBefore: true,
                      onSelect: () => void reloadVersion(),
                    },
                  ]}
                />
              </span>

              <NotificationCenter />

              <Dropdown
                menuLabel="切换语言"
                trigger={(_open, toggle) => (
                  <button type="button" className="icon-btn" aria-label="切换语言" title={activeLocale?.native} onClick={toggle}>
                    <Globe size={16} />
                  </button>
                )}
                items={LOCALES.map((item) => ({
                  id: item.code,
                  label: `${item.native}${item.dir === 'rtl' ? ' · RTL' : ''}`,
                  onSelect: () => setLocale(item.code),
                }))}
              />

              <span className="topbar-desktop-only">
                <Tooltip content={dict.common.tour}>
                  <button type="button" className="icon-btn" aria-label={dict.common.tour} onClick={() => setTourOpen(true)}>
                    <Compass size={16} />
                  </button>
                </Tooltip>
              </span>

              <Tooltip content={theme === 'dark' ? dict.common.themeLight : dict.common.themeDark}>
                <button
                  type="button"
                  className="icon-btn"
                  aria-label={theme === 'dark' ? dict.common.themeLight : dict.common.themeDark}
                  onClick={toggleTheme}
                >
                  {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
                </button>
              </Tooltip>
            </div>
          </header>

          <main id="main" className="app-stage" tabIndex={-1}>
            <div className="stage-inner">
              <div className="page-header">
                <h1>{dict.pages[page].title}</h1>
                <div className="page-header-actions">
                  <button
                    type="button"
                    className="btn btn-sm"
                    data-tour="page-refresh"
                    disabled={loading || refreshing}
                    onClick={() => void triggerPageRefresh()}
                  >
                    <RefreshCw size={14} className={loading || refreshing ? 'spin' : ''} />
                    <span>{loading || refreshing ? dict.common.refreshing : dict.common.refresh}</span>
                  </button>
                </div>
              </div>

              {children}
            </div>
          </main>
        </div>
      </div>

      {/* Mobile Thumb-Reachable Bottom Dock (<= 640px, Spec 2.6 + safe-area) */}
      <nav className="mobile-bottom-nav" aria-label="移动端快捷导航">
        {(['dashboard', 'servers', 'clients', 'proxies'] as PageId[]).map((id) => (
          <button
            key={id}
            type="button"
            className="mobile-dock-btn"
            aria-current={page === id ? 'page' : undefined}
            onClick={() => {
              navigate(id)
              setMobileMenuOpen(false)
            }}
          >
            {navIcon(id)}
            <span>{dict.pages[id].title}</span>
          </button>
        ))}
        <button
          type="button"
          className="mobile-dock-btn"
          aria-expanded={mobileMenuOpen}
          onClick={() => setMobileMenuOpen((v) => !v)}
        >
          <Menu size={17} />
          <span>{dict.common.more}</span>
        </button>
      </nav>

      <CommandPalette open={cmdkOpen} onClose={() => setCmdkOpen(false)} commands={commands} />
      <Tour open={tourOpen} steps={tourSteps} onClose={() => setTourOpen(false)} />
    </>
  )
}
