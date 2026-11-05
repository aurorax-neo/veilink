import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const css = readFileSync(new URL('../src/styles.css', import.meta.url), 'utf8')
const view = readFileSync(new URL('../src/views/ConsoleView.vue', import.meta.url), 'utf8')
const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
const rule = selector => css.match(new RegExp(`(?:^|\\n)\\s*\\${selector} \\{([^}]+)\\}`, 'm'))?.[1] || ''

test('console uses a single main vertical scroll container without sidebar or row-animation scrollbar flash', () => {
  assert.match(view, /<div class="shell">[\s\S]*<aside class="side">[\s\S]*<div class="workspace">[\s\S]*<main id="main" class="stage"/)
  assert.match(rule('.shell'), /height: 100dvh/)
  assert.match(rule('.shell'), /overflow: hidden/)
  assert.match(rule('.shell'), /grid-template-rows: minmax\(0, 1fr\)/)
  assert.match(rule('.side'), /min-height: 0; overflow: hidden/)
  assert.doesNotMatch(rule('.side'), /overflow-y:\s*auto|scrollbar-gutter/)
  assert.match(rule('.workspace'), /min-height: 0; display: flex; flex-direction: column/)
  assert.match(rule('.topbar'), /flex: none/)
  assert.match(rule('.stage'), /flex: 1 1 auto; min-height: 0/)
  assert.match(rule('.stage'), /overflow-y: auto; overflow-x: hidden; overscroll-behavior-y: contain; scrollbar-gutter: stable/)
  assert.doesNotMatch(css, /tbody tr \{[^}]*animation/)
})

test('narrow screens keep a bounded navigation scroll area above the content', () => {
  const mobile = css.slice(css.indexOf('@media (max-width: 640px) {'))
  assert.match(mobile, /\.shell \{ grid-template-columns: minmax\(0, 1fr\); grid-template-rows: auto minmax\(0, 1fr\); \}/)
  assert.match(mobile, /\.side \{ max-height: 40dvh; padding: 12px;/)
  assert.match(app, /<a class="skip" :href="phase === 'app' \? '#main' : '#login-main'"/)
  assert.match(view, /<main id="main" class="stage" tabindex="-1">/)
  // Login and boot are not inside .shell; keep natural page scrolling there.
  assert.match(app, /<LoginView v-else-if=/)
})

test('wide workspace uses available width and node columns total 100 percent', () => {
 assert.match(rule('.stage'), /width: auto/)
 assert.match(rule('.stage'), /padding: 24px 28px 40px/)
 assert.doesNotMatch(css, /1240px|min-width: 1080px/)
 assert.match(css, /\.stack \{[^}]*width: 100%/)
 assert.match(css, /\.panel, \.table-scroll, table \{ width: 100%; \}/)
 assert.equal((css.match(/^\.shell \{/gm)||[]).length,1)
 assert.match(css, /\.fit \{ display: inline-grid/)
 assert.doesNotMatch(css, /text-overflow:\s*ellipsis/)
 assert.doesNotMatch(readFileSync(new URL('../src/views/ConsoleView.vue', import.meta.url), 'utf8'), /min-width:\s*[\d.]+rem/)
})
test('mapping rows retain Pool cell so status, traffic and actions align with headers', () => {
 const source=readFileSync(new URL('../src/views/ProxiesView.vue',import.meta.url),'utf8')
 assert.match(source, /<td>\{\{ mapping.pool \|\| 1 \}\}/)
 const row=source.match(/<tbody><tr v-for="mapping in rows"[\s\S]*?<\/tr>/)[0]
 assert.equal((row.match(/<td[ >]/g)||[]).length,7)
})

test('design spec refinements: 40px hit areas, Popconfirm, Snackbar undo, 264px searchable dropdown, IME guard, and extension-preserving filenames', () => {
  const proxies = readFileSync(new URL('../src/views/ProxiesView.vue', import.meta.url), 'utf8')
  const nodes = readFileSync(new URL('../src/components/NodesTable.vue', import.meta.url), 'utf8')
  const modal = readFileSync(new URL('../src/components/Modal.vue', import.meta.url), 'utf8')
  const logs = readFileSync(new URL('../src/views/LogsView.vue', import.meta.url), 'utf8')
  const login = readFileSync(new URL('../src/views/LoginView.vue', import.meta.url), 'utf8')
  const format = readFileSync(new URL('../src/format.ts', import.meta.url), 'utf8')

  // Spec 4.1: 40px minimum hit area on icon buttons
  assert.match(rule('.icon-btn'), /min-width: 40px; min-height: 40px/)
  // Spec 2.2 & 2.4: Popconfirm anchored to row action + Snackbar undo
  assert.match(proxies, /class="popconfirm" role="dialog"/)
  assert.match(nodes, /class="popconfirm" role="dialog"/)
  assert.match(view, /class="btn small toast-undo"/)
  // Spec 2.5: Form draft recovery banner
  assert.match(proxies, /class="draft-banner"/)
  // Spec 2.6: Bottom sheet drag grip & damped gesture
  assert.match(modal, /onSheetPointerDown/)
  assert.match(modal, /class="sheet-drag-grip"/)
  // Spec 3.2: Flat segmented pills for 2-4 options & max-height 264px searchable dropdown for >10 options
  assert.match(css, /\.seg-pills \{/)
  assert.match(css, /\.select-dropdown-panel \{[^}]*max-height: 264px/)
  // Spec 6.4 & 7.2: Streaming log fade and jump-to-latest button
  assert.match(logs, /jump-latest-btn/)
  assert.match(css, /@keyframes stream-fade \{ from \{ opacity: 0; filter: blur\(6px\); \}/)
  // Spec 6.8: Copy bounce animation
  assert.match(css, /\.copy-bounce \{/)
  // Spec 7.1: IME composition Enter guard
  assert.match(login, /@compositionstart="onCompositionStart"/)
  assert.match(modal, /@compositionstart="onCompositionStart"/)
  // Spec 7.6: Truncate filename preserving extension
  assert.match(format, /export function truncateFileName/)
  // Node and Mapping editors use centered modal dialogs rather than right-side drawers
  const nodeEditor = readFileSync(new URL('../src/components/NodeEditor.vue', import.meta.url), 'utf8')
  assert.doesNotMatch(nodeEditor, /variant="drawer"/)
  assert.doesNotMatch(proxies, /variant="drawer"/)
})
