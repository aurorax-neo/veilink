import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { api, ApiError, checkApiCompatibility, clearSessionToken, getVersionInfo, setSessionToken, setUnauthorized, type VersionInfo } from '../api'
import { applyLocaleToDocument, getDict, readStoredLocale, type Dict } from '../i18n'
import { runPageRefresh } from '../pageRefresh'
import { stream, type StreamState } from '../stream'
import { pageFromHash, type Audit, type AuthStatusResponse, type AuthUser, type LocaleCode, type Mapping, type MappingStatus, type Node, type PageId, type ThemeMode, type TrafficRow } from '../types'
import { Modal } from '../components/ui/Overlays'
import { ToastRegion, type SnackbarItem, type ToastItem } from '../components/ui/ToastRegion'

export interface ConsoleState {
  phase: 'boot' | 'setup' | 'login' | 'app'
  page: PageId
  navigate: (next: PageId) => void

  currentUser: AuthUser | null
  secretFileHint: string
  authError: string
  authBusy: boolean
  completeSetup: (installSecret: string, email: string, password: string) => Promise<void>
  submitLogin: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  requestLogout: () => void
  refreshAccount: () => Promise<void>

  nodes: Node[]
  mappings: Mapping[]
  mappingStatuses: Record<string, MappingStatus>
  statusError: string
  audit: Audit[]
  traffic: TrafficRow[]
  trafficLoaded: boolean
  trafficError: string

  loading: boolean
  refreshing: boolean
  loaded: boolean
  error: string

  software: VersionInfo | null
  versionError: boolean
  versionWarning: string
  reloadVersion: () => Promise<void>

  streamState: StreamState

  theme: ThemeMode
  toggleTheme: () => void
  locale: LocaleCode
  setLocale: (next: LocaleCode) => void
  dict: Dict

  tourOpen: boolean
  setTourOpen: (open: boolean) => void
  notificationsOpen: boolean
  setNotificationsOpen: (open: boolean) => void

  reload: (options?: { silent?: boolean }) => Promise<void>
  reloadNode: (id: string) => Promise<void>
  refreshMappingStatuses: () => Promise<void>
  triggerPageRefresh: () => Promise<void>

  toast: (text: string, bad?: boolean) => void
  showSnackbar: (text: string, onUndo: () => void | Promise<void>, undoLabel?: string) => void
}

const ConsoleCtx = createContext<ConsoleState | null>(null)

export function useConsole(): ConsoleState {
  const ctx = useContext(ConsoleCtx)
  if (!ctx) throw new Error('useConsole must be used inside ConsoleProvider')
  return ctx
}

export function ConsoleProvider({ children }: { children: ReactNode }) {
  const [phase, setPhase] = useState<'boot' | 'setup' | 'login' | 'app'>('boot')
  const [page, setPage] = useState<PageId>(() => pageFromHash())
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null)
  const [secretFileHint, setSecretFileHint] = useState('/data/.install_secret')
  const [authError, setAuthError] = useState('')
  const [authBusy, setAuthBusy] = useState(false)

  const [nodes, setNodes] = useState<Node[]>([])
  const [mappings, setMappings] = useState<Mapping[]>([])
  const [mappingStatuses, setMappingStatuses] = useState<Record<string, MappingStatus>>({})
  const [statusError, setStatusError] = useState('')
  const [audit, setAudit] = useState<Audit[]>([])
  const [traffic, setTraffic] = useState<TrafficRow[]>([])
  const [trafficLoaded, setTrafficLoaded] = useState(false)
  const [trafficError, setTrafficError] = useState('')

  const [loading, setLoading] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [error, setError] = useState('')

  const [software, setSoftware] = useState<VersionInfo | null>(null)
  const [versionError, setVersionError] = useState(false)
  const [versionWarning, setVersionWarning] = useState('')

  const [streamState, setStreamState] = useState<StreamState>('disconnected')
  const [tourOpen, setTourOpen] = useState(false)
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [logoutConfirmOpen, setLogoutConfirmOpen] = useState(false)

  const [theme, setTheme] = useState<ThemeMode>(() => {
    try {
      const saved = globalThis.localStorage?.getItem('veilink_theme')
      if (saved === 'light' || saved === 'dark') return saved
    } catch { /* ignore */ }
    return 'dark'
  })

  const [locale, setLocaleState] = useState<LocaleCode>(() => readStoredLocale())
  const dict = useMemo(() => getDict(locale), [locale])

  const [toasts, setToasts] = useState<ToastItem[]>([])
  const [snackbar, setSnackbar] = useState<SnackbarItem | null>(null)

  const genRef = useRef(0)
  const statusGenRef = useRef(0)
  const toastIdRef = useRef(0)
  const snackbarTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const loadingRef = useRef(false)
  const refreshingRef = useRef(false)
  const liveBusyRef = useRef(false)
  const phaseRef = useRef(phase)
  phaseRef.current = phase
  loadingRef.current = loading
  refreshingRef.current = refreshing

  const dismissToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((item) => item.id !== id))
  }, [])

  const toast = useCallback((text: string, bad = false) => {
    if (!text) return
    const id = ++toastIdRef.current
    setToasts((prev) => [...prev.slice(-2), { id, text, bad }])
    window.setTimeout(() => {
      setToasts((prev) => prev.filter((item) => item.id !== id))
    }, bad ? 5500 : 2200)
  }, [])

  const dismissSnackbar = useCallback(() => {
    if (snackbarTimerRef.current) clearTimeout(snackbarTimerRef.current)
    snackbarTimerRef.current = undefined
    setSnackbar(null)
  }, [])

  const showSnackbar = useCallback((text: string, onUndo: () => void | Promise<void>, undoLabel?: string) => {
    if (snackbarTimerRef.current) clearTimeout(snackbarTimerRef.current)
    const id = ++toastIdRef.current
    setSnackbar({ id, text, onUndo, undoLabel })
    snackbarTimerRef.current = window.setTimeout(() => {
      setSnackbar((curr) => (curr?.id === id ? null : curr))
    }, 6500)
  }, [])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try { globalThis.localStorage?.setItem('veilink_theme', theme) } catch { /* ignore */ }
  }, [theme])

  useEffect(() => {
    applyLocaleToDocument(locale)
  }, [locale])

  const toggleTheme = useCallback(() => {
    setTheme((t) => (t === 'dark' ? 'light' : 'dark'))
  }, [])

  const setLocale = useCallback((next: LocaleCode) => {
    setLocaleState(next)
  }, [])

  const reloadVersion = useCallback(async () => {
    setVersionError(false)
    try {
      const info = await getVersionInfo()
      setSoftware(info)
    } catch {
      setVersionError(true)
    }
  }, [])

  const refreshAccount = useCallback(async () => {
    try {
      const me = await api<AuthUser>('/auth/me')
      setCurrentUser(me)
    } catch { /* ignore */ }
  }, [])

  const refreshMappingStatuses = useCallback(async () => {
    const ticket = ++statusGenRef.current
    setStatusError('')
    try {
      const res = await api<Record<string, MappingStatus>>('/mappings/status')
      if (ticket !== statusGenRef.current || phaseRef.current !== 'app') return
      if (!res || typeof res !== 'object' || Array.isArray(res)) throw new Error('状态格式无效')
      setMappingStatuses(res)
    } catch {
      if (ticket === statusGenRef.current && phaseRef.current === 'app') {
        setMappingStatuses({})
        setStatusError('映射隧道状态读取失败，可点击刷新重试。')
      }
    }
  }, [])

  const loadTraffic = useCallback(async (ticket: number) => {
    try {
      const rows = await api<TrafficRow[] | null>('/traffic')
      if (ticket !== genRef.current) return
      if (rows !== null && !Array.isArray(rows)) throw new Error('流量数据格式不正确')
      setTraffic(rows || [])
      setTrafficLoaded(true)
      setTrafficError('')
    } catch (reason) {
      if (ticket !== genRef.current) return
      setTrafficError(reason instanceof Error ? reason.message : '流量读取失败')
    }
  }, [])

  const reloadNode = useCallback(async (id: string) => {
    const ticket = genRef.current
    const list = await api<Node[] | null>('/nodes')
    if (ticket !== genRef.current || phaseRef.current !== 'app') return
    if (!Array.isArray(list)) throw new ApiError('节点数据格式不正确。', 200)
    const updated = list.find((n) => n.id === id)
    if (!updated) throw new ApiError('节点已不存在，请刷新列表。', 404)
    setNodes((prev) => prev.map((n) => (n.id === id ? updated : n)))
  }, [])

  const reload = useCallback(
    async (options?: { silent?: boolean }) => {
      if (options?.silent && loadingRef.current) return
      const ticket = ++genRef.current
      if (!options?.silent) setLoading(true)
      try {
        const fetchedNodes = await api<Node[] | null>('/nodes')
        if (ticket !== genRef.current) return
        if (fetchedNodes !== null && !Array.isArray(fetchedNodes)) throw new ApiError('API 数据格式不正确。', 200)
        if (options?.silent) {
          setNodes(fetchedNodes || [])
          await Promise.all([loadTraffic(ticket), refreshMappingStatuses()])
          return
        }
        const [fetchedMappings, fetchedAudit] = await Promise.all([
          api<Mapping[] | null>('/mappings'),
          api<Audit[] | null>('/audit'),
        ])
        if (ticket !== genRef.current) return
        if (![fetchedMappings, fetchedAudit].every((x) => x === null || Array.isArray(x))) {
          throw new ApiError('API 数据格式不正确。', 200)
        }
        setNodes(fetchedNodes || [])
        setMappings(fetchedMappings || [])
        setAudit(fetchedAudit || [])
        await Promise.all([loadTraffic(ticket), refreshMappingStatuses()])
        if (ticket !== genRef.current) return
        setLoaded(true)
        setError('')
      } catch (reason) {
        if (ticket !== genRef.current || options?.silent) return
        const msg = reason instanceof Error ? reason.message : '请求失败'
        setError(msg)
        toast(msg, true)
        throw reason
      } finally {
        if (ticket === genRef.current && !options?.silent) setLoading(false)
      }
    },
    [loadTraffic, refreshMappingStatuses, toast],
  )

  const resetAll = useCallback(() => {
    genRef.current += 1
    statusGenRef.current += 1
    setCurrentUser(null)
    setNodes([])
    setMappings([])
    setMappingStatuses({})
    setAudit([])
    setTraffic([])
    setTrafficLoaded(false)
    setTrafficError('')
    setStatusError('')
    setLoaded(false)
    setLoading(false)
    setRefreshing(false)
    setError('')
    dismissSnackbar()
  }, [dismissSnackbar])

  const navigate = useCallback((next: PageId) => {
    setPage(next)
    const hash = `#/${next}`
    pageFromHash(hash)
    if (location.hash !== hash) location.hash = hash
    const stage = document.getElementById('main')
    if (stage) stage.scrollTop = 0
  }, [])

  const enterApp = useCallback(
    async (user?: AuthUser | null) => {
      if (user) setCurrentUser(user)
      setPhase('app')
      setAuthError('')
      void reloadVersion()
      if (!user) void refreshAccount()
      if (typeof EventSource !== 'undefined') {
        void stream.connect(['node', 'tunnel', 'stats', 'log']).catch(() => {})
      }
      try {
        await reload()
      } catch { /* error shown in view */ }
    },
    [reload, reloadVersion, refreshAccount],
  )

  const completeSetup = useCallback(
    async (installSecret: string, email: string, password: string) => {
      setAuthBusy(true)
      setAuthError('')
      try {
        const res = await api<{ ok: boolean; token: string; user: AuthUser }>('/auth/setup', 'POST', {
          install_secret: installSecret.trim(),
          email: email.trim(),
          password,
        })
        if (res.token) setSessionToken(res.token)
        await enterApp(res.user)
        toast('管理员账户已初始化，公开注册已永久锁定。')
      } catch (reason) {
        setAuthError(reason instanceof Error ? reason.message : '初始化失败')
      } finally {
        setAuthBusy(false)
      }
    },
    [enterApp, toast],
  )

  const submitLogin = useCallback(
    async (email: string, password: string) => {
      setAuthBusy(true)
      setAuthError('')
      try {
        const res = await api<{ ok: boolean; token: string; user: AuthUser }>('/auth/login', 'POST', {
          email: email.trim(),
          password,
        })
        if (res.token) setSessionToken(res.token)
        await enterApp(res.user)
      } catch (reason) {
        if (reason instanceof ApiError && reason.status === 409) {
          setPhase('setup')
          setAuthError('')
        } else {
          setAuthError(reason instanceof Error ? reason.message : '登录失败')
        }
      } finally {
        setAuthBusy(false)
      }
    },
    [enterApp],
  )

  const logout = useCallback(async () => {
    setLogoutConfirmOpen(false)
    try {
      await api('/auth/logout', 'POST', {})
    } catch { /* ignore network errors during logout */ }
    stream.disconnect()
    clearSessionToken()
    resetAll()
    setPhase('login')
    document.title = 'Veilink · 控制平面'
  }, [resetAll])

  const requestLogout = useCallback(() => {
    setLogoutConfirmOpen(true)
  }, [])

  const triggerPageRefresh = useCallback(async () => {
    if (loadingRef.current || refreshingRef.current) return
    setRefreshing(true)
    try {
      await reload()
      await runPageRefresh()
    } catch { /* desk shows error */ } finally {
      setRefreshing(false)
    }
  }, [reload])

  useEffect(() => {
    if (phase === 'app') {
      document.title = `Veilink · ${dict.pages[page].title}`
    } else if (phase === 'setup') {
      document.title = `Veilink · ${dict.setup.title}`
    } else {
      document.title = `Veilink · ${dict.controlPlane}`
    }
  }, [phase, page, dict])

  useEffect(() => {
    setUnauthorized(() => {
      stream.disconnect()
      clearSessionToken()
      resetAll()
      setPhase('login')
      setAuthError('登录会话已过期，请重新输入管理员邮箱与密码。')
    })

    const onHash = () => {
      setPage(pageFromHash())
      const stage = document.getElementById('main')
      if (stage) stage.scrollTop = 0
    }
    const refreshLive = async () => {
      if (phaseRef.current !== 'app' || document.visibilityState === 'hidden' || loadingRef.current || refreshingRef.current || liveBusyRef.current) return
      liveBusyRef.current = true
      try {
        await reload({ silent: true })
      } catch { /* ignore */ } finally {
        liveBusyRef.current = false
      }
    }
    const onVisible = () => {
      if (document.visibilityState === 'visible') void refreshLive()
    }

    window.addEventListener('hashchange', onHash)
    document.addEventListener('visibilitychange', onVisible)
    const timer = window.setInterval(() => { void refreshLive() }, 5000)
    const offState = stream.onState(setStreamState)
    const offNode = stream.on('node', () => { void refreshLive() })
    const offTunnel = stream.on('tunnel', () => { void refreshLive() })

    void (async () => {
      try {
        await checkApiCompatibility()
        setVersionWarning('')
      } catch (reason) {
        setVersionWarning(reason instanceof Error ? reason.message : '版本检查失败')
      }
      try {
        const st = await api<AuthStatusResponse>('/auth/status')
        if (st.secret_file_hint) setSecretFileHint(st.secret_file_hint)
        if (!st.installed) {
          clearSessionToken()
          setPhase('setup')
          return
        }
        if (st.authenticated && st.user) {
          await enterApp(st.user)
          return
        }
        setPhase('login')
      } catch {
        setPhase('login')
      }
    })()

    return () => {
      window.removeEventListener('hashchange', onHash)
      document.removeEventListener('visibilitychange', onVisible)
      window.clearInterval(timer)
      offState()
      offNode()
      offTunnel()
      stream.disconnect()
    }
  }, [enterApp, reload, resetAll])

  const value: ConsoleState = {
    phase,
    page,
    navigate,
    currentUser,
    secretFileHint,
    authError,
    authBusy,
    completeSetup,
    submitLogin,
    logout,
    requestLogout,
    refreshAccount,
    nodes,
    mappings,
    mappingStatuses,
    statusError,
    audit,
    traffic,
    trafficLoaded,
    trafficError,
    loading,
    refreshing,
    loaded,
    error,
    software,
    versionError,
    versionWarning,
    reloadVersion,
    streamState,
    theme,
    toggleTheme,
    locale,
    setLocale,
    dict,
    tourOpen,
    setTourOpen,
    notificationsOpen,
    setNotificationsOpen,
    reload,
    reloadNode,
    refreshMappingStatuses,
    triggerPageRefresh,
    toast,
    showSnackbar,
  }

  return (
    <ConsoleCtx.Provider value={value}>
      {children}
      <Modal
        open={logoutConfirmOpen && phase === 'app'}
        onClose={() => setLogoutConfirmOpen(false)}
        size="sm"
        title={dict.common.signOutConfirm}
        cancelLabel={dict.common.cancel}
        saveLabel={dict.common.signOut}
        danger
        onSubmit={async () => {
          await logout()
          return true
        }}
      >
        <p style={{ margin: 0, fontSize: 13.5, color: 'var(--text-secondary)' }}>
          {currentUser?.email || ''}
        </p>
      </Modal>
      <ToastRegion
        toasts={toasts}
        snackbar={snackbar}
        onDismissToast={dismissToast}
        onDismissSnackbar={dismissSnackbar}
      />
    </ConsoleCtx.Provider>
  )
}
