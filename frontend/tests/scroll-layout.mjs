import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const css = readFileSync(new URL('../src/styles.css', import.meta.url), 'utf8')
const view = readFileSync(new URL('../src/views/ConsoleView.vue', import.meta.url), 'utf8')
const app = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
const rule = selector => css.match(new RegExp(`(?:^|\\n)\\s*\\${selector} \\{([^}]+)\\}`, 'm'))?.[1] || ''

test('console confines scrolling to independent sidebar and content regions', () => {
  assert.match(view, /<div class="shell">[\s\S]*<aside class="side">[\s\S]*<div class="workspace">[\s\S]*<main id="main" class="stage"/)
  assert.match(rule('.shell'), /height: 100dvh/)
  assert.match(rule('.shell'), /overflow: hidden/)
  assert.match(rule('.shell'), /grid-template-rows: minmax\(0, 1fr\)/)
  assert.match(rule('.side'), /min-height: 0; overflow-y: auto; overscroll-behavior-y: contain/)
  assert.match(rule('.workspace'), /min-height: 0; display: flex; flex-direction: column/)
  assert.match(rule('.topbar'), /flex: none/)
  assert.match(rule('.stage'), /flex: 1 1 auto; min-height: 0/)
  assert.match(rule('.stage'), /overflow-y: scroll; overflow-x: hidden; overscroll-behavior-y: contain; scrollbar-gutter: stable/)
})

test('narrow screens keep a bounded navigation scroll area above the content', () => {
  const mobile = css.slice(css.indexOf('@media (max-width: 640px) {'))
  assert.match(mobile, /\.shell \{ grid-template-columns: minmax\(0, 1fr\); grid-template-rows: auto minmax\(0, 1fr\); \}/)
  assert.match(mobile, /\.side \{ max-height: 40dvh; padding: 12px; \}/)
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
})
test('mapping rows retain Pool cell so status, traffic and actions align with headers', () => {
 const source=readFileSync(new URL('../src/views/ProxiesView.vue',import.meta.url),'utf8')
 assert.match(source, /<td>\{\{ mapping.pool \|\| 1 \}\}/)
 const row=source.match(/<tbody><tr v-for="mapping in rows"[\s\S]*?<\/tr>/)[0]
 assert.equal((row.match(/<td[ >]/g)||[]).length,7)
})
