import type { LocaleCode, PageId } from './types'

export interface LocaleMeta {
  code: LocaleCode
  label: string
  native: string
  dir: 'ltr' | 'rtl'
}

export const LOCALES: readonly LocaleMeta[] = [
  { code: 'zh-CN', label: 'Chinese', native: '简体中文', dir: 'ltr' },
  { code: 'en', label: 'English', native: 'English', dir: 'ltr' },
  { code: 'de', label: 'German', native: 'Deutsch', dir: 'ltr' },
  { code: 'id', label: 'Indonesian', native: 'Bahasa Indonesia', dir: 'ltr' },
  { code: 'th', label: 'Thai', native: 'ภาษาไทย', dir: 'ltr' },
  { code: 'vi', label: 'Vietnamese', native: 'Tiếng Việt', dir: 'ltr' },
  { code: 'ar', label: 'Arabic (RTL)', native: 'العربية', dir: 'rtl' },
] as const

export interface Dict {
  appName: string
  controlPlane: string
  navGroups: { overview: string; network: string; observability: string; system: string }
  pages: Record<PageId, { title: string; subtitle: string }>
  common: {
    refresh: string
    refreshing: string
    save: string
    saving: string
    cancel: string
    close: string
    delete: string
    edit: string
    enable: string
    disable: string
    copy: string
    copied: string
    search: string
    reset: string
    all: string
    online: string
    attention: string
    disabled: string
    revoked: string
    undo: string
    keepCurrent: string
    signOut: string
    signOutConfirm: string
    commandPalette: string
    tour: string
    sseConnected: string
    sseReconnecting: string
    sseDisconnected: string
    jumpToLatest: string
    version: string
    themeLight: string
    themeDark: string
    skipToMain: string
    more: string
    notifications: string
  }
  login: {
    badge: string
    headline: string
    description: string
    emailLabel: string
    emailPlaceholder: string
    passwordLabel: string
    passwordPlaceholder: string
    submit: string
    submitting: string
    lockedNotice: string
    forgotTitle: string
    forgotDesc: string
    feature1Title: string
    feature1Desc: string
    feature2Title: string
    feature2Desc: string
    feature3Title: string
    feature3Desc: string
  }
  setup: {
    badge: string
    title: string
    subtitle: string
    step1: string
    step2: string
    step3: string
    guardTitle: string
    guardDesc: string
    secretLabel: string
    secretPlaceholder: string
    emailLabel: string
    passwordLabel: string
    confirmPasswordLabel: string
    singleAdminNote: string
    submit: string
    submitting: string
  }
  dashboard: {
    onlineServers: string
    onlineClients: string
    activeMappings: string
    totalTraffic: string
    attentionNodes: string
    topologyTitle: string
    topologyEmpty: string
    gatewaysTitle: string
    clientsTitle: string
    recentAuditTitle: string
    manageAll: string
    attentionBanner: string
    noAttention: string
  }
  nodes: {
    newServer: string
    newClient: string
    searchPlaceholder: string
    onboarding: string
    inspect: string
    viewConfig: string
    revoke: string
    noNodes: string
    noNodesHint: string
    selectHint: string
  }
  proxies: {
    newMapping: string
    searchPlaceholder: string
    noMappings: string
    noMappingsHint: string
    enabledOnly: string
    disabledOnly: string
  }
  logs: {
    sourceAll: string
    sourceMaster: string
    sourceNode: string
    autoRefresh: string
    stopAutoRefresh: string
    searchPlaceholder: string
    emptyTitle: string
  }
  audit: {
    catAll: string
    catNode: string
    catMapping: string
    searchPlaceholder: string
    loadMore: string
  }
  settings: {
    runtimeTitle: string
    serviceTitle: string
    accountTitle: string
    saveConfig: string
    appearanceTitle: string
    restartTour: string
  }
}

const zhCN: Dict = {
  appName: 'Veilink',
  controlPlane: '控制平面',
  navGroups: { overview: '概览', network: '网络拓扑', observability: '可观测性', system: '系统' },
  pages: {
    dashboard: { title: '总览仪表盘', subtitle: '实时隧道拓扑、节点健康度与全局吞吐视图' },
    servers: { title: '公网网关', subtitle: '承载反向隧道加密入口、证书与公网监听的 Server 节点' },
    clients: { title: '内网节点', subtitle: '主动连出至网关并将加密流量转发至内网服务的 Client 节点' },
    proxies: { title: '端口映射', subtitle: '公网监听端口到内网目标服务的 TCP / UDP 隧道路由表' },
    logs: { title: '实时日志流', subtitle: 'Master 控制面与已接入节点的实时内存运行事件流' },
    audit: { title: '审计轨迹', subtitle: '节点配置、接入令牌、凭据变更与映射写操作记录' },
    settings: { title: '系统与账户', subtitle: '管理员账户安全、控制面监听配置、运行状态与多平台界面偏好' },
  },
  common: {
    refresh: '刷新',
    refreshing: '同步中…',
    save: '保存更改',
    saving: '正在保存…',
    cancel: '取消',
    close: '关闭',
    delete: '删除',
    edit: '编辑',
    enable: '启用',
    disable: '停用',
    copy: '复制',
    copied: '已复制',
    search: '搜索',
    reset: '重置筛选',
    all: '全部',
    online: '在线',
    attention: '需关注',
    disabled: '已停用',
    revoked: '已吊销',
    undo: '撤销',
    keepCurrent: '保留当前状态',
    signOut: '注销登录',
    signOutConfirm: '确认注销登录？',
    commandPalette: '快速跳转',
    tour: '功能导览',
    sseConnected: 'SSE 实时连接',
    sseReconnecting: 'SSE 重连中',
    sseDisconnected: 'SSE 未连接',
    jumpToLatest: '跳至最新',
    version: '版本',
    themeLight: '切换浅色外观',
    themeDark: '切换深色外观',
    skipToMain: '跳转到主内容',
    more: '更多',
    notifications: '通知中心',
  },
  login: {
    badge: 'Zero-Trust Reverse Tunnel Control Plane',
    headline: '高性能加密反向隧道控制台',
    description: '统一编排公网网关与内网节点，原生支持 VLESS、REALITY、Vision、后量子 ML-KEM-768、XHTTP（H1/H2/H3）与 Hysteria2。',
    emailLabel: '邮箱',
    emailPlaceholder: 'admin@example.com',
    passwordLabel: '密码',
    passwordPlaceholder: '',
    submit: '登录',
    submitting: '登录中…',
    lockedNotice: '仅限唯一已注册管理员登录 · 公开注册已永久锁定',
    forgotTitle: '忘记管理员密码？',
    forgotDesc: '请在部署 Master 的服务器终端执行重置命令，系统将立即注销旧会话并输出新密码：',
    feature1Title: '多协议抗审查隧道栈',
    feature1Desc: 'REALITY + ML-DSA-65、VLESS Encryption 0-RTT、XHTTP H2/H3 与 Hysteria2 统一编排下发。',
    feature2Title: '服务端集中派生，零手动漂移',
    feature2Desc: '仅维护网关侧配置，客户端证书信任、密钥对与接入快照由控制平面自动派生同步。',
    feature3Title: '实时 SSE 遥测与脱机韧性',
    feature3Desc: '毫秒级节点心跳与隧道状态回传，同时支持脱机容器 / 单二进制 / state.json 独立冷启动。',
  },
  setup: {
    badge: 'First-Time Installation · Install Lock Active',
    title: '初始化管理员',
    subtitle: '',
    step1: '安装令牌',
    step2: '管理员账户',
    step3: '完成',
    guardTitle: '安装令牌',
    guardDesc: '',
    secretLabel: '安装令牌',
    secretPlaceholder: 'VLK-XXXX-XXXX-XXXX-XXXX',
    emailLabel: '邮箱',
    passwordLabel: '密码',
    confirmPasswordLabel: '确认密码',
    singleAdminNote: '',
    submit: '完成注册',
    submitting: '提交中…',
  },
  dashboard: {
    onlineServers: '在线公网网关',
    onlineClients: '在线内网节点',
    activeMappings: '活跃端口映射',
    totalTraffic: '本进程累计流量',
    attentionNodes: '需关注节点',
    topologyTitle: '实时反向隧道拓扑',
    topologyEmpty: '创建服务端、客户端与端口映射后，此处自动绘制实时加密链路拓扑。',
    gatewaysTitle: '公网网关状态',
    clientsTitle: '内网节点状态',
    recentAuditTitle: '最近变更审计',
    manageAll: '查看全部',
    attentionBanner: '存在需要关注的节点（心跳超时、配置待同步或应用异常），点击对应节点可立即排查。',
    noAttention: '所有节点状态正常',
  },
  nodes: {
    newServer: '新建公网网关',
    newClient: '新建内网节点',
    searchPlaceholder: '搜索名称、ID、连接地址或错误…',
    onboarding: '快捷接入',
    inspect: '详情',
    viewConfig: '下发配置',
    revoke: '吊销凭据',
    noNodes: '暂无匹配节点',
    noNodesHint: '新建节点或清除当前筛选条件。',
    selectHint: '选择左侧任意节点以查看实时遥测、连接地址、下发配置与诊断信息。',
  },
  proxies: {
    newMapping: '新建端口映射',
    searchPlaceholder: '搜索映射名称、网关、客户端或地址…',
    noMappings: '暂无端口映射',
    noMappingsHint: '创建一条公网到内网的 TCP / UDP 映射规则开始转发流量。',
    enabledOnly: '已启用',
    disabledOnly: '已停用',
  },
  logs: {
    sourceAll: '全部来源',
    sourceMaster: '控制中心',
    sourceNode: '节点日志',
    autoRefresh: '5s 轮询',
    stopAutoRefresh: '停止轮询',
    searchPlaceholder: '过滤日志消息、节点名称或级别…',
    emptyTitle: '暂无近期日志',
  },
  audit: {
    catAll: '全部事件',
    catNode: '节点变更',
    catMapping: '映射变更',
    searchPlaceholder: '搜索操作类型、目标名称或对象 ID…',
    loadMore: '加载更多记录',
  },
  settings: {
    runtimeTitle: '运行态概览',
    serviceTitle: 'Master 服务监听配置',
    accountTitle: '唯一管理员账户与会话安全',
    saveConfig: '保存监听配置',
    appearanceTitle: '界面语言、外观与引导',
    restartTour: '重新开始功能导览',
  },
}

const en: Dict = {
  appName: 'Veilink',
  controlPlane: 'Control Plane',
  navGroups: { overview: 'Overview', network: 'Mesh Network', observability: 'Observability', system: 'System' },
  pages: {
    dashboard: { title: 'Dashboard', subtitle: 'Live tunnel topology, node health telemetry, and throughput overview' },
    servers: { title: 'Public Gateways', subtitle: 'Edge server nodes hosting encrypted reverse-tunnel listeners' },
    clients: { title: 'Intranet Nodes', subtitle: 'Private client agents dialing outbound to forward local targets' },
    proxies: { title: 'Port Mappings', subtitle: 'TCP & UDP ingress-to-target tunnel routing table' },
    logs: { title: 'Live Logs', subtitle: 'Real-time in-memory stream from control plane and connected nodes' },
    audit: { title: 'Audit Trail', subtitle: 'Immutable record of administrative write operations' },
    settings: { title: 'Settings & Account', subtitle: 'Administrator security, listener configuration, runtime status, and preferences' },
  },
  common: {
    refresh: 'Refresh',
    refreshing: 'Syncing…',
    save: 'Save Changes',
    saving: 'Saving…',
    cancel: 'Cancel',
    close: 'Close',
    delete: 'Delete',
    edit: 'Edit',
    enable: 'Enable',
    disable: 'Disable',
    copy: 'Copy',
    copied: 'Copied',
    search: 'Search',
    reset: 'Reset Filters',
    all: 'All',
    online: 'Online',
    attention: 'Attention',
    disabled: 'Disabled',
    revoked: 'Revoked',
    undo: 'Undo',
    keepCurrent: 'Keep Current',
    signOut: 'Sign Out',
    signOutConfirm: 'Sign out of current session?',
    commandPalette: 'Jump to…',
    tour: 'Quick Tour',
    sseConnected: 'SSE Live',
    sseReconnecting: 'Reconnecting',
    sseDisconnected: 'Offline',
    jumpToLatest: 'Jump to Latest',
    version: 'Build',
    themeLight: 'Switch to Light Mode',
    themeDark: 'Switch to Dark Mode',
    skipToMain: 'Skip to main content',
    more: 'More',
    notifications: 'Notifications',
  },
  login: {
    badge: 'Zero-Trust Reverse Tunnel Control Plane',
    headline: 'Encrypted Reverse Tunnel Cockpit',
    description: 'Orchestrate edge gateways and intranet agents over VLESS, REALITY, Vision, ML-KEM-768, XHTTP (H1/H2/H3), and Hysteria2.',
    emailLabel: 'Email',
    emailPlaceholder: 'admin@example.com',
    passwordLabel: 'Password',
    passwordPlaceholder: '',
    submit: 'Sign In',
    submitting: 'Signing in…',
    lockedNotice: 'Single administrator account only · Public registration is permanently locked',
    forgotTitle: 'Forgot administrator password?',
    forgotDesc: 'Run the recovery CLI command on your Master host to reset the password and invalidate active sessions:',
    feature1Title: 'Multi-Protocol Censorship-Resistant Stack',
    feature1Desc: 'REALITY + ML-DSA-65, VLESS Encryption 0-RTT, XHTTP H2/H3, and Hysteria2 managed in one place.',
    feature2Title: 'Derived Client Configs, Zero Drift',
    feature2Desc: 'Configure gateways once; client trust anchors, keypairs, and snapshots derive automatically.',
    feature3Title: 'Real-Time SSE & Offline Bootstrap',
    feature3Desc: 'Sub-second status updates with offline Docker, standalone binary, and state.json exports.',
  },
  setup: {
    badge: 'First-Time Installation · Install Lock Active',
    title: 'Initialize Admin',
    subtitle: '',
    step1: 'Install Secret',
    step2: 'Admin Account',
    step3: 'Done',
    guardTitle: 'Install Secret',
    guardDesc: '',
    secretLabel: 'Install Secret',
    secretPlaceholder: 'VLK-XXXX-XXXX-XXXX-XXXX',
    emailLabel: 'Email',
    passwordLabel: 'Password',
    confirmPasswordLabel: 'Confirm Password',
    singleAdminNote: '',
    submit: 'Complete Setup',
    submitting: 'Submitting…',
  },
  dashboard: {
    onlineServers: 'Online Gateways',
    onlineClients: 'Online Agents',
    activeMappings: 'Active Mappings',
    totalTraffic: 'Session Traffic',
    attentionNodes: 'Needs Attention',
    topologyTitle: 'Live Reverse-Tunnel Topology',
    topologyEmpty: 'Create a gateway, an intranet client, and a mapping to visualize live tunnel paths.',
    gatewaysTitle: 'Gateway Fleet',
    clientsTitle: 'Intranet Agents',
    recentAuditTitle: 'Recent Activity',
    manageAll: 'Manage',
    attentionBanner: 'Some nodes need attention (stale heartbeat, pending revision, or apply error).',
    noAttention: 'All systems nominal',
  },
  nodes: {
    newServer: 'New Gateway',
    newClient: 'New Intranet Node',
    searchPlaceholder: 'Filter by name, ID, endpoint, or error…',
    onboarding: 'Onboard',
    inspect: 'Inspect',
    viewConfig: 'Derived Config',
    revoke: 'Revoke Credentials',
    noNodes: 'No matching nodes',
    noNodesHint: 'Create a node or adjust your search filter.',
    selectHint: 'Select any node to inspect telemetry, connect endpoints, derived config, and diagnostics.',
  },
  proxies: {
    newMapping: 'New Mapping',
    searchPlaceholder: 'Filter by mapping name, node, or host…',
    noMappings: 'No port mappings',
    noMappingsHint: 'Create a TCP or UDP mapping rule to expose an intranet service.',
    enabledOnly: 'Enabled',
    disabledOnly: 'Disabled',
  },
  logs: {
    sourceAll: 'All Sources',
    sourceMaster: 'Master',
    sourceNode: 'Nodes',
    autoRefresh: '5s Poll',
    stopAutoRefresh: 'Stop Poll',
    searchPlaceholder: 'Filter log messages, nodes, or levels…',
    emptyTitle: 'No recent logs',
  },
  audit: {
    catAll: 'All Events',
    catNode: 'Nodes',
    catMapping: 'Mappings',
    searchPlaceholder: 'Filter by action, object name, or ID…',
    loadMore: 'Load More Entries',
  },
  settings: {
    runtimeTitle: 'Runtime Status',
    serviceTitle: 'Master Listener Configuration',
    accountTitle: 'Administrator Account & Sessions',
    saveConfig: 'Save Configuration',
    appearanceTitle: 'Language, Appearance & Guided Tour',
    restartTour: 'Replay Interactive Tour',
  },
}

const de: Dict = {
  ...en,
  controlPlane: 'Steuerungsebene',
  navGroups: { overview: 'Übersicht', network: 'Tunnel-Netzwerk', observability: 'Beobachtbarkeit', system: 'Systemverwaltung' },
  pages: {
    dashboard: { title: 'Übersichts-Dashboard', subtitle: 'Echtzeit-Topologie, Knotenstatus und Datenverkehr' },
    servers: { title: 'Öffentliche Gateways', subtitle: 'Server-Knoten für verschlüsselte Reverse-Tunnel-Eingänge' },
    clients: { title: 'Intranet-Knoten', subtitle: 'Interne Agenten zur Weiterleitung lokaler Dienste' },
    proxies: { title: 'Portweiterleitungen', subtitle: 'TCP- und UDP-Tunnel-Routing-Konfiguration' },
    logs: { title: 'Echtzeit-Protokolle', subtitle: 'Laufende System- und Knotenprotokolle im Arbeitsspeicher' },
    audit: { title: 'Prüfprotokoll', subtitle: 'Nachvollziehbare Änderungs- und Sicherheitsereignisse' },
    settings: { title: 'System & Konto', subtitle: 'Administratorkonto, Listener-Konfiguration und Systemeinstellungen' },
  },
  common: {
    ...en.common,
    refresh: 'Aktualisieren',
    refreshing: 'Wird synchronisiert…',
    save: 'Änderungen speichern',
    saving: 'Wird gespeichert…',
    cancel: 'Abbrechen',
    close: 'Schließen',
    delete: 'Endgültig löschen',
    edit: 'Bearbeiten',
    enable: 'Aktivieren',
    disable: 'Deaktivieren',
    copy: 'Kopieren',
    copied: 'Kopiert',
    reset: 'Filter zurücksetzen',
    undo: 'Rückgängig',
    keepCurrent: 'Beibehalten',
    signOut: 'Abmelden',
    signOutConfirm: 'Aktuelle Sitzung abmelden?',
    commandPalette: 'Schnellsuche…',
    jumpToLatest: 'Zum Neuesten springen',
    more: 'Mehr',
    notifications: 'Benachrichtigungen',
  },
  nodes: {
    ...en.nodes,
    newServer: 'Neues Gateway erstellen',
    newClient: 'Neuen Intranet-Knoten anlegen',
    onboarding: 'Schnelleinbindung',
    revoke: 'Zugangsdaten widerrufen',
  },
  proxies: {
    ...en.proxies,
    newMapping: 'Neue Portweiterleitung',
  },
}

const id: Dict = {
  ...en,
  controlPlane: 'Panel Kendali',
  navGroups: { overview: 'Ringkasan', network: 'Jaringan Terowongan', observability: 'Pemantauan', system: 'Pengaturan Sistem' },
  pages: {
    dashboard: { title: 'Dasbor Ringkasan', subtitle: 'Topologi terowongan waktu nyata dan kesehatan simpul' },
    servers: { title: 'Gerbang Publik', subtitle: 'Simpul server penerima koneksi terowongan terenkripsi' },
    clients: { title: 'Simpul Intranet', subtitle: 'Agen jaringan lokal untuk penerusan layanan internal' },
    proxies: { title: 'Pemetaan Port', subtitle: 'Aturan perutean TCP & UDP dari gerbang ke target internal' },
    logs: { title: 'Catatan Aktivitas', subtitle: 'Aliran log memori langsung dari pusat kendali dan simpul' },
    audit: { title: 'Jejak Audit', subtitle: 'Riwayat perubahan konfigurasi dan kredensial keamanan' },
    settings: { title: 'Pengaturan & Akun', subtitle: 'Keamanan akun administrator, konfigurasi pendengar, dan preferensi' },
  },
  common: {
    ...en.common,
    refresh: 'Segarkan',
    refreshing: 'Menyinkronkan…',
    save: 'Simpan Perubahan',
    saving: 'Menyimpan…',
    cancel: 'Batalkan',
    delete: 'Hapus Permanen',
    edit: 'Ubah',
    enable: 'Aktifkan',
    disable: 'Nonaktifkan',
    undo: 'Urungkan',
    signOut: 'Keluar Sesi',
    signOutConfirm: 'Keluar dari sesi saat ini?',
    jumpToLatest: 'Lompat ke Terbaru',
    more: 'Lainnya',
    notifications: 'Pusat Notifikasi',
  },
}

const th: Dict = {
  ...en,
  controlPlane: 'ศูนย์ควบคุมระบบ',
  navGroups: { overview: 'ภาพรวม', network: 'โครงข่ายอุโมงค์', observability: 'การเฝ้าระวัง', system: 'ตั้งค่าระบบ' },
  pages: {
    dashboard: { title: 'แดชบอร์ดภาพรวม', subtitle: 'แผนผังการเชื่อมต่อแบบเรียลไทม์และสถานะสุขภาพโหนด' },
    servers: { title: 'เกตเวย์สาธารณะ', subtitle: 'โหนดเซิร์ฟเวอร์ที่รองรับอุโมงค์เข้ารหัสฝั่งขาเข้า' },
    clients: { title: 'โหนดเครือข่ายภายใน', subtitle: 'โหนดไคลเอนต์ที่เชื่อมต่อออกเพื่อส่งต่อบริการภายใน' },
    proxies: { title: 'การจับคู่พอร์ต', subtitle: 'เส้นทางการส่งต่อ TCP และ UDP ผ่านอุโมงค์เข้ารหัส' },
    logs: { title: 'บันทึกการทำงานสด', subtitle: 'สตรีมบันทึกเหตุการณ์แบบเรียลไทม์จากศูนย์ควบคุมและโหนด' },
    audit: { title: 'ประวัติการตรวจสอบ', subtitle: 'บันทึกการแก้ไขการตั้งค่าและการจัดการสิทธิ์ทั้งหมด' },
    settings: { title: 'ตั้งค่าและบัญชี', subtitle: 'ความปลอดภัยบัญชีผู้ดูแล สถานะการทำงาน และการตั้งค่าพอร์ต' },
  },
  common: {
    ...en.common,
    refresh: 'รีเฟรชข้อมูล',
    refreshing: 'กำลังซิงค์…',
    save: 'บันทึกการเปลี่ยนแปลง',
    cancel: 'ยกเลิก',
    delete: 'ลบถาวร',
    edit: 'แก้ไข',
    enable: 'เปิดใช้งาน',
    disable: 'ปิดใช้งาน',
    undo: 'เลิกทำ',
    signOut: 'ออกจากระบบ',
    signOutConfirm: 'ยืนยันการออกจากระบบ?',
    jumpToLatest: 'ไปยังรายการล่าสุด',
    more: 'เพิ่มเติม',
    notifications: 'ศูนย์การแจ้งเตือน',
  },
}

const vi: Dict = {
  ...en,
  controlPlane: 'Trung tâm Điều khiển',
  navGroups: { overview: 'Tổng quan', network: 'Mạng Đường hầm', observability: 'Giám sát', system: 'Hệ thống' },
  pages: {
    dashboard: { title: 'Bảng điều khiển', subtitle: 'Sơ đồ đường hầm thời gian thực và trạng thái các nút mạng' },
    servers: { title: 'Cổng Công cộng', subtitle: 'Các nút máy chủ tiếp nhận kết nối đường hầm mã hóa' },
    clients: { title: 'Nút Mạng nội bộ', subtitle: 'Tác nhân kết nối ra ngoài để chuyển tiếp dịch vụ nội bộ' },
    proxies: { title: 'Ánh xạ Cổng', subtitle: 'Bảng định tuyến TCP và UDP từ cổng công cộng vào đích nội bộ' },
    logs: { title: 'Nhật ký Trực tiếp', subtitle: 'Luồng sự kiện thời gian thực từ trung tâm và các nút' },
    audit: { title: 'Nhật ký Kiểm toán', subtitle: 'Lịch sử các thao tác thay đổi cấu hình và khóa xác thực' },
    settings: { title: 'Cài đặt & Tài khoản', subtitle: 'Bảo mật tài khoản quản trị, trạng thái hệ thống và cổng lắng nghe' },
  },
  common: {
    ...en.common,
    refresh: 'Làm mới',
    refreshing: 'Đang đồng bộ…',
    save: 'Lưu thay đổi',
    cancel: 'Hủy bỏ',
    delete: 'Xóa vĩnh viễn',
    edit: 'Chỉnh sửa',
    enable: 'Bật',
    disable: 'Tắt',
    undo: 'Hoàn tác',
    signOut: 'Đăng xuất',
    signOutConfirm: 'Xác nhận đăng xuất?',
    jumpToLatest: 'Đi tới mới nhất',
    more: 'Thêm',
    notifications: 'Trung tâm thông báo',
  },
}

const ar: Dict = {
  ...en,
  controlPlane: 'لوحة التحكم',
  navGroups: { overview: 'نظرة عامة', network: 'شبكة الأنفاق', observability: 'المراقبة والسجلات', system: 'النظام' },
  pages: {
    dashboard: { title: 'لوحة القيادة', subtitle: 'مخطط الأنفاق المباشر وحالة العقد وحركة البيانات' },
    servers: { title: 'البوابات العامة', subtitle: 'عقد الخادم المستضيفة لمداخل الأنفاق المشفرة' },
    clients: { title: 'العقد الداخلية', subtitle: 'عقد العملاء المتصلة لإعادة توجيه الخدمات المحلية' },
    proxies: { title: 'توجيه المنافذ', subtitle: 'جدول توجيه حركة TCP و UDP عبر الأنفاق الآمنة' },
    logs: { title: 'السجلات المباشرة', subtitle: 'تدفق الأحداث المباشر من مركز التحكم والعقد المتصلة' },
    audit: { title: 'سجل التدقيق', subtitle: 'سجل عمليات التعديل وإدارة المفاتيح والشهادات' },
    settings: { title: 'الإعدادات والحساب', subtitle: 'أمان حساب المسؤول وإعدادات الاستماع وحالة التشغيل' },
  },
  common: {
    ...en.common,
    refresh: 'تحديث',
    refreshing: 'جارٍ المزامنة…',
    save: 'حفظ التغييرات',
    saving: 'جارٍ الحفظ…',
    cancel: 'إلغاء',
    close: 'إغلاق',
    delete: 'حذف نهائي',
    edit: 'تعديل',
    enable: 'تفعيل',
    disable: 'تعطيل',
    copy: 'نسخ',
    copied: 'تم النسخ',
    search: 'بحث',
    reset: 'إعادة تعيين',
    all: 'الكل',
    online: 'متصل',
    attention: 'يحتاج انتباه',
    disabled: 'معطل',
    revoked: 'ملغى',
    undo: 'تراجع',
    keepCurrent: 'الإبقاء على الحالي',
    signOut: 'تسجيل الخروج',
    signOutConfirm: 'تأكيد تسجيل الخروج؟',
    commandPalette: 'انتقال سريع…',
    tour: 'جولة تعريفية',
    sseConnected: 'اتصال مباشر',
    sseReconnecting: 'إعادة الاتصال',
    sseDisconnected: 'غير متصل',
    jumpToLatest: 'الانتقال للأحدث',
    version: 'الإصدار',
    themeLight: 'الوضع الفاتح',
    themeDark: 'الوضع الداكن',
    skipToMain: 'انتقل إلى المحتوى الرئيسي',
    more: 'المزيد',
    notifications: 'مركز الإشعارات',
  },
  login: {
    ...en.login,
    headline: 'وحدة تحكم الأنفاق العكسية المشفرة',
    description: 'إدارة موحدة للبوابات العامة والعقد الداخلية عبر VLESS و REALITY و Vision و XHTTP و Hysteria2.',
    emailLabel: 'البريد الإلكتروني',
    passwordLabel: 'كلمة المرور',
    submit: 'تسجيل الدخول',
    submitting: 'جارٍ الدخول…',
    lockedNotice: 'حساب مسؤول وحيد فقط · التسجيل العام مغلق بشكل دائم',
  },
  setup: {
    ...en.setup,
    title: 'تهيئة حساب المسؤول الوحيد',
    subtitle: 'أدخل رمز التثبيت لمرة واحدة من الخادم لحماية التثبيت من الزوار ثم أنشئ البريد الإلكتروني وكلمة المرور.',
    guardTitle: 'حماية منع تسجيل الزوار مفعّلة',
    secretLabel: 'رمز التثبيت الآمن (Install Secret)',
    emailLabel: 'البريد الإلكتروني للمسؤول',
    passwordLabel: 'كلمة المرور (8 أحرف على الأقل)',
    confirmPasswordLabel: 'تأكيد كلمة المرور',
    submit: 'إكمال التهيئة وقفل التسجيل',
    submitting: 'جارٍ التهيئة…',
  },
  dashboard: {
    ...en.dashboard,
    onlineServers: 'البوابات المتصلة',
    onlineClients: 'العقد الداخلية المتصلة',
    activeMappings: 'التوجيهات النشطة',
    totalTraffic: 'إجمالي البيانات',
    attentionNodes: 'عقد تحتاج مراجعة',
    topologyTitle: 'مخطط الأنفاق المباشر',
    gatewaysTitle: 'حالة البوابات العامة',
    clientsTitle: 'حالة العقد الداخلية',
    recentAuditTitle: 'أحدث التغييرات',
    manageAll: 'إدارة الكل',
  },
  nodes: {
    ...en.nodes,
    newServer: 'إضافة بوابة جديدة',
    newClient: 'إضافة عقدة داخلية',
    onboarding: 'الربط السريع',
    viewConfig: 'عرض الإعدادات',
    revoke: 'إلغاء الاعتماد',
  },
  proxies: {
    ...en.proxies,
    newMapping: 'توجيه منفذ جديد',
  },
  settings: {
    ...en.settings,
    runtimeTitle: 'حالة التشغيل',
    serviceTitle: 'إعدادات المستمع الرئيسي',
    accountTitle: 'حساب المسؤول الوحيد والجلسات',
    saveConfig: 'حفظ الإعدادات',
    appearanceTitle: 'اللغة والمظهر والجولة التعريفية',
    restartTour: 'إعادة تشغيل الجولة',
  },
}

const DICTS: Record<LocaleCode, Dict> = {
  'zh-CN': zhCN,
  en,
  de,
  id,
  th,
  vi,
  ar,
}

export function getDict(code: LocaleCode): Dict {
  return DICTS[code] || zhCN
}

export function getLocaleDir(code: LocaleCode): 'ltr' | 'rtl' {
  return code === 'ar' ? 'rtl' : 'ltr'
}

export function readStoredLocale(): LocaleCode {
  try {
    const saved = globalThis.localStorage?.getItem('veilink_locale') as LocaleCode | null
    if (saved && saved in DICTS) return saved
  } catch { /* ignore */ }
  return 'zh-CN'
}

export function applyLocaleToDocument(code: LocaleCode): void {
  try {
    if (typeof document !== 'undefined') {
      document.documentElement.lang = code
      document.documentElement.dir = getLocaleDir(code)
    }
    globalThis.localStorage?.setItem('veilink_locale', code)
  } catch { /* ignore */ }
}
