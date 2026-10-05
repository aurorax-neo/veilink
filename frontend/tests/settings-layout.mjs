import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const css = readFileSync(new URL('../src/styles.css', import.meta.url), 'utf8')
const settings = readFileSync(new URL('../src/views/SettingsView.vue', import.meta.url), 'utf8')

test('native options and placeholder text use explicit high contrast theme colors', () => {
  assert.match(css, /--input-bg:\s*#080d13/)
  assert.match(css, /option, optgroup \{ color: var\(--text\); background: var\(--input-bg\);/)
  assert.match(css, /input::placeholder, textarea::placeholder \{ color: var\(--muted\); opacity: 1;/)
  assert.match(settings, /\.tag\.admin \{[^}]*color: var\(--danger\)/)
  assert.match(settings, /\.tag\.ro \{[^}]*color: #9fc5ff/)
})

test('key creation is bottom-aligned and collapses to a single column on mobile', () => {
  assert.doesNotMatch(settings, /<span>&nbsp;<\/span>/)
  assert.match(settings, /\.key-form \{[^}]*grid-template-columns: minmax\(0, 1fr\) minmax\(0, 1fr\) auto; align-items: end;/)
  assert.match(settings, /\.key-form \{ grid-template-columns: minmax\(0, 1fr\); \}/)
  assert.match(settings, /minmax\(min\(220px, 100%\), 1fr\)/)
  assert.match(settings, /class="key-details"[\s\S]*class="key-sub muted"/)
})
