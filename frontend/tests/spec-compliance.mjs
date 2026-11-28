import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'

const read = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8')

function loadTs(rel) {
  const js = ts.transpileModule(read(rel), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText
  const m = { exports: {} }
  vm.runInContext(js, vm.createContext({ exports: m.exports, module: m, TextEncoder }))
  return m.exports
}

test('Design tokens satisfy Spec 6.1 surface luminance hierarchy & Spec 6.3 dark font weight reduction', () => {
  const tokens = read('../src/styles/tokens.css')
  assert.match(tokens, /--surface-0:\s*#0b0b0a/i)
  assert.match(tokens, /--surface-1:\s*#151515/i)
  assert.match(tokens, /--surface-2:\s*#1a1a19/i)
  assert.match(tokens, /--surface-3:\s*#20201e/i)
  assert.match(tokens, /--surface-0:\s*#f5f5f3/i)
  assert.match(tokens, /--surface-2:\s*#fcfcfb/i)
  assert.match(tokens, /--fw-regular:\s*360/)
  assert.match(tokens, /--fw-regular:\s*400/)
})

test('Global CSS satisfies Spec 2.3/2.6/3.2/4.1/5.4/6.4-6.9/7.4 layout, motion, and single scroll contracts', () => {
  const css = read('../src/styles/app.css')
  // Modal exact widths 400 / 520 / 720px
  assert.match(css, /\.modal-sm\s*\{\s*max-width:\s*400px/)
  assert.match(css, /\.modal-md\s*\{\s*max-width:\s*520px/)
  assert.match(css, /\.modal-lg\s*\{\s*max-width:\s*720px/)
  // Mobile BottomSheet 30% / 60% / 80% dvh
  assert.match(css, /\.snap-30\s*\{\s*height:\s*30dvh/)
  assert.match(css, /\.snap-60\s*\{\s*height:\s*60dvh/)
  assert.match(css, /\.snap-80\s*\{\s*height:\s*80dvh/)
  // Select max-height 264px
  assert.match(css, /\.select-list\s*\{[^}]*max-height:\s*264px/)
  // Hit target >= 40px
  assert.match(css, /\.icon-btn\s*\{[^}]*min-width:\s*40px[^}]*min-height:\s*40px/)
  // Safe line-height, tabular-nums, inline-icon -0.125em, text-wrap pretty, Grid 0fr -> 1fr
  assert.match(css, /line-height:\s*1\.5/)
  assert.match(css, /font-variant-numeric:\s*tabular-nums/)
  assert.match(css, /vertical-align:\s*-0\.125em/)
  assert.match(css, /text-wrap:\s*pretty/)
  assert.match(css, /grid-template-rows:\s*0fr/)
  assert.match(css, /grid-template-rows:\s*1fr/)
  assert.match(css, /blur\(6px\)/)
  // Single vertical scroll stage in app-shell
  assert.match(css, /\.app-shell\s*\{[^}]*height:\s*100dvh[^}]*overflow:\s*hidden/)
  assert.match(css, /\.app-stage\s*\{[^}]*overflow-y:\s*auto[^}]*scrollbar-gutter:\s*stable/)
})

test('Format helpers satisfy Spec 7.1 IME 500ms guard & Spec 7.6 filename truncation with extension', () => {
  const format = loadTs('../src/format.ts')
  assert.equal(format.truncateFileName('2025年度财务报告-最终版-完整审核稿.pdf', 14), '2025年度财务报告-最终版...pdf')
  assert.equal(format.truncateFileName('short.pem', 16), 'short.pem')

  assert.equal(format.isImeComposingEnter({ key: 'Enter', isComposing: true }, 0, 1000), true)
  assert.equal(format.isImeComposingEnter({ key: 'Enter', isComposing: false }, 800, 1100), true)
  assert.equal(format.isImeComposingEnter({ key: 'Enter', isComposing: false }, 500, 1100), false)
})

test('i18n supports Spec 5.6 verification locales including DE, ID, TH, VI, and Arabic RTL', () => {
  const i18n = loadTs('../src/i18n.ts')
  const codes = i18n.LOCALES.map((l) => l.code)
  for (const required of ['zh-CN', 'en', 'de', 'id', 'th', 'vi', 'ar']) {
    assert.ok(codes.includes(required), `Missing locale ${required}`)
    const dict = i18n.getDict(required)
    assert.ok(dict.pages.dashboard.title.length > 0)
  }
  assert.equal(i18n.getLocaleDir('ar'), 'rtl')
  assert.equal(i18n.getLocaleDir('zh-CN'), 'ltr')
})

test('Overlays enforce AlertDialog Esc blocking and SplitPane drag shield + Esc/50-50/80% rules', () => {
  const overlays = read('../src/components/ui/Overlays.tsx')
  const controls = read('../src/components/ui/Controls.tsx')
  assert.match(overlays, /role="alertdialog"/)
  assert.match(overlays, /if \(e\.key === 'Escape'\)[\s\S]*e\.preventDefault\(\)/)
  assert.match(controls, /split-drag-shield/)
  assert.match(controls, /rawPct > 80/)
  assert.match(controls, /setRatio\(50\)/)
})

test('Email/password validation, Setup Wizard anti-visitor flow, and multi-resolution responsive CSS', () => {
  const format = loadTs('../src/format.ts')
  assert.equal(format.validateEmailAddress('admin@veilink.io'), null)
  assert.equal(format.validateEmailAddress('Ops.User+prod@sub.example.org'), null)
  assert.notEqual(format.validateEmailAddress('admin'), null)
  assert.notEqual(format.validateEmailAddress('admin@localhost'), null)
  assert.notEqual(format.validateEmailAddress('a..b@example.com'), null)
  assert.notEqual(format.validateEmailAddress('has space@example.com'), null)

  assert.equal(format.evaluatePasswordStrength('short').valid, false)
  assert.equal(format.evaluatePasswordStrength('StrongPass!2026').valid, true)
  assert.equal(format.evaluatePasswordStrength('StrongPass!2026').score, 4)

  const html = read('../index.html')
  assert.match(html, /viewport-fit=cover/)
  assert.doesNotMatch(html, /<script(?![^>]*src=)/i, 'strict CSP prohibits inline scripts')

  const css = read('../src/styles/app.css')
  assert.match(css, /input\[type='email'\]/)
  assert.match(css, /@media\s*\(min-width:\s*1800px\)/)
  assert.match(css, /\.mobile-cards\s*\{/)
  assert.match(css, /\.mobile-bottom-nav\s*\{/)
  assert.match(css, /safe-area-inset-bottom/)
  assert.match(css, /font-size:\s*16px/)
  assert.match(css, /prefers-reduced-motion/)

  const setupView = read('../src/views/SetupView.tsx')
  assert.match(setupView, /install_secret|installSecret/)
  assert.match(setupView, /validateEmailAddress/)
  assert.match(setupView, /evaluatePasswordStrength/)

  // Alerts are consolidated into the topbar NotificationCenter so Dashboard has zero layout shift
  const dashboardView = read('../src/views/DashboardView.tsx')
  const appShell = read('../src/components/AppShell.tsx')
  const notifCenter = read('../src/components/NotificationCenter.tsx')
  const loginView = read('../src/views/LoginView.tsx')
  const onboardingModal = read('../src/components/NodeOnboardingModal.tsx')
  const topologyCanvas = read('../src/components/TopologyCanvas.tsx')
  assert.doesNotMatch(dashboardView, /<Alert\b/, 'Dashboard should not render inline top warning banners that shift KPI content')
  assert.match(appShell, /<NotificationCenter\s*\/>/)
  assert.doesNotMatch(appShell, /page-subtitle/, 'Page headers must stay concise without verbose subtitles')
  assert.match(notifCenter, /notif-popover/)

  // Minimal Login & Setup ("登录就是登录") and compact 1:1 TopologyCanvas
  assert.doesNotMatch(loginView, /login-showcase|单管理员锁|Collapsible|PBKDF2/)
  assert.doesNotMatch(setupView, /login-showcase|setup-stepper|PBKDF2/)
  assert.doesNotMatch(onboardingModal, /<Collapsible|result\?\.warning/)
  assert.match(topologyCanvas, /ResizeObserver/)
  assert.match(topologyCanvas, /const nodeH = 38/)

  // Sign-out secondary confirmation across AppShell and SettingsView
  const settingsView = read('../src/views/SettingsView.tsx')
  const consoleCtx = read('../src/context/ConsoleContext.tsx')
  assert.match(appShell, /requestLogout/)
  assert.doesNotMatch(appShell, /onClick=\{\(\) => void logout\(\)\}/)
  assert.match(settingsView, /requestLogout/)
  assert.match(consoleCtx, /logoutConfirmOpen/)
})

test('copyText falls back to synchronous mobile-compatible textarea selection when Clipboard API is blocked or missing', async () => {
  const code = ts.transpileModule(read('../src/format.ts'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText

  let selectedRange = null
  let execCopiedValue = null
  let removed = false
  const fakeTa = {
    value: '',
    style: { cssText: '' },
    tabIndex: 0,
    setAttribute() {},
    focus() {},
    select() {},
    setSelectionRange(start, end) {
      selectedRange = [start, end]
    },
    remove() {
      removed = true
    },
  }
  const fakeDoc = {
    activeElement: { closest: () => null, focus() {} },
    body: { appendChild() {} },
    createElement: () => fakeTa,
    execCommand: (cmd) => {
      if (cmd === 'copy') {
        execCopiedValue = fakeTa.value
        return true
      }
      return false
    },
  }

  // Case 1: iOS WKWebView / Brave where navigator.clipboard.writeText rejects with NotAllowedError
  const m1 = { exports: {} }
  vm.runInContext(
    code,
    vm.createContext({
      exports: m1.exports,
      module: m1,
      TextEncoder,
      document: fakeDoc,
      navigator: {
        clipboard: {
          writeText: async () => {
            throw new Error('NotAllowedError: Clipboard write blocked in WKWebView')
          },
        },
      },
    }),
  )
  await m1.exports.copyText('veilink-mobile-cmd-123')
  assert.equal(execCopiedValue, 'veilink-mobile-cmd-123')
  assert.deepEqual(selectedRange, [0, 'veilink-mobile-cmd-123'.length])
  assert.equal(removed, true)

  // Case 2: Non-HTTPS HTTP origin where navigator.clipboard is undefined
  execCopiedValue = null
  const m2 = { exports: {} }
  vm.runInContext(
    code,
    vm.createContext({
      exports: m2.exports,
      module: m2,
      TextEncoder,
      document: fakeDoc,
      navigator: {},
    }),
  )
  await m2.exports.copyText('http-fallback-ok')
  assert.equal(execCopiedValue, 'http-fallback-ok')
})

test('Transport badges avoid neutral surface collision and offline nodes suppress heartbeat checks', () => {
  const format = loadTs('../src/format.ts')
  const tokens = read('../src/styles/tokens.css')
  const css = read('../src/styles/app.css')
  const onboarding = read('../src/components/NodeOnboardingModal.tsx')
  const editor = read('../src/components/NodeEditorDrawer.tsx')

  assert.match(tokens, /--info-soft:/)
  assert.match(tokens, /--badge-neutral-bg:/)
  assert.match(tokens, /--segmented-track:/)
  assert.match(css, /\.badge-info\s*\{/)
  assert.match(onboarding, /\/offline/)
  assert.match(editor, /脱机独立/)

  const chips = format.tunnelBadges({
    id: 'srv-reality',
    name: 'Edge',
    role: 'server',
    address: '1.2.3.4',
    port: 443,
    revoked: false,
    desired_revision: 1,
    applied_revision: 1,
    last_seen: Math.floor(Date.now() / 1000),
    error: '',
    tunnel: {
      protocol: 'vless',
      flow: 'xtls-rprx-vision',
      decryption: 'mlkem768x25519plus.native.600s.demo',
      reality: { dest: 'www.microsoft.com:443', public_key: 'pk', short_id: '0102' },
    },
  })
  const tcpBadge = chips.find((b) => b.text === 'TCP')
  assert.ok(tcpBadge)
  assert.equal(tcpBadge.tone, 'info', 'TCP transport badge must use distinct info tone instead of neutral background shade')

  const offlinePending = {
    id: 'cli-off',
    name: 'Airgap-Client',
    role: 'client',
    mode: 'offline',
    address: '',
    port: 0,
    revoked: false,
    desired_revision: 3,
    applied_revision: 0,
    exported_revision: 0,
    last_seen: 0,
    error: 'stale-online-error',
  }
  assert.equal(format.isOfflineNode(offlinePending), true)
  assert.equal(format.heartbeatOnline(offlinePending), false)
  assert.deepEqual(JSON.parse(JSON.stringify(format.presence(offlinePending))), { text: '脱机独立', tone: 'info' })
  assert.deepEqual(JSON.parse(JSON.stringify(format.revisionState(offlinePending))), { text: '待导出', tone: 'warn' })
  assert.deepEqual(JSON.parse(JSON.stringify(format.attentionReasons(offlinePending))), ['配置待导出'])

  const offlineExported = { ...offlinePending, exported_revision: 3 }
  assert.equal(format.nodeOperational(offlineExported), true)
  assert.deepEqual(JSON.parse(JSON.stringify(format.revisionState(offlineExported))), { text: '已导出', tone: 'good' })
  assert.deepEqual(JSON.parse(JSON.stringify(format.attentionReasons(offlineExported))), [])
})

test('Modals and Drawers stay flicker-free under 2s clock ticks and SSE node updates', () => {
  const onboarding = read('../src/components/NodeOnboardingModal.tsx')
  const editor = read('../src/components/NodeEditorDrawer.tsx')
  const overlays = read('../src/components/ui/Overlays.tsx')
  const cmdk = read('../src/components/ui/CommandPalette.tsx')
  const tour = read('../src/components/ui/Tour.tsx')

  // NodeOnboardingModal must NOT depend on object `node` or callback `onExported` in effect/callback deps,
  // and must keep .subpanel-card mounted unconditionally to prevent open/reload height flicker.
  assert.doesNotMatch(onboarding, /\},\s*\[node\b/)
  assert.doesNotMatch(onboarding, /\[onExported\]/)
  assert.doesNotMatch(onboarding, /\{onlineResult\s*&&\s*\(/)
  assert.doesNotMatch(onboarding, /\{offlineResult\s*&&\s*\(\s*<div className="subpanel-card"/)
  assert.match(onboarding, /\[nodeId,\s*offlineMode,\s*nodeEmbedded,\s*generateOnline,\s*exportOffline\]/)

  // NodeEditorDrawer must key draft reset on primitive sessionKey, never raw `node` or `defaultName`.
  assert.doesNotMatch(editor, /\[open,\s*node,\s*defaultName/)
  assert.match(editor, /\[sessionKey,\s*isServer\]/)

  // Overlays must ref-wrap callbacks instead of re-binding global key listeners on parent clock ticks.
  assert.doesNotMatch(overlays, /\[open,\s*busy,\s*onClose\]/)
  assert.doesNotMatch(cmdk, /onClose\]/)
  assert.doesNotMatch(tour, /\[open,\s*index,\s*steps\]/)
})

test('Server clock calibration eliminates false clock-ahead warnings and all edit dialogs use centered Modal', () => {
  const editor = read('../src/components/NodeEditorDrawer.tsx')
  const proxies = read('../src/views/ProxiesView.tsx')
  const nodesView = read('../src/views/NodesView.tsx')

  // Both NodeEditorDrawer and ProxiesView mapping editor must render centered <Modal isForm ...>, never side <Drawer
  assert.doesNotMatch(editor, /<Drawer\b/)
  assert.match(editor, /<Modal[\s\S]*isForm/)
  assert.doesNotMatch(proxies, /<Drawer\b/)
  assert.match(proxies, /<Modal[\s\S]*isForm/)

  // NodesView inspector and rows must pass calibrated renderNow, never stale raw Date.now()
  assert.doesNotMatch(nodesView, /Date\.now\(\)/)
  assert.match(nodesView, /serverNowMs\(\)/)

  // Simulate server clock 10 minutes ahead of local browser + 2s React tick lag
  const host = {
    __VEILINK_CLOCK_OFFSET_MS__: 600_000,
    __VEILINK_SERVER_FLOOR_MS__: Date.now() + 600_000,
  }
  const js = ts.transpileModule(read('../src/format.ts'), {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText
  const m = { exports: {} }
  vm.runInContext(js, vm.createContext({ exports: m.exports, module: m, TextEncoder, Date, globalThis: host }))
  const format = m.exports

  const serverSec = Math.floor((Date.now() + 600_000) / 1000)
  const onlineNode = {
    id: 'gw-1',
    name: 'Edge-1',
    role: 'server',
    address: '1.2.3.4',
    port: 443,
    revoked: false,
    desired_revision: 4,
    applied_revision: 4,
    last_seen: serverSec,
    error: '',
  }
  // Even with a 3-second tick lag behind last_seen, node stays online with "0 秒前" and zero false warnings
  const laggedNow = (serverSec - 3) * 1000
  assert.equal(format.heartbeatOnline(onlineNode), true)
  assert.equal(format.heartbeatOnline(onlineNode, laggedNow), true)
  assert.deepEqual(JSON.parse(JSON.stringify(format.presence(onlineNode, laggedNow))), { text: '近期在线', tone: 'good' })
  assert.deepEqual(JSON.parse(JSON.stringify(format.attentionReasons(onlineNode, laggedNow))), [])
  assert.equal(format.seenText(serverSec, laggedNow, true), '0 秒前')

  // Meanwhile a genuinely dead node (5 minutes old on server) is still accurately reported as timed out even when browser is 10m behind
  const deadNode = { ...onlineNode, last_seen: serverSec - 300 }
  assert.equal(format.heartbeatOnline(deadNode), false)
  assert.deepEqual(JSON.parse(JSON.stringify(format.presence(deadNode))), { text: '心跳超时', tone: 'warn' })
})
