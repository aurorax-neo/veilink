import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'
import { test } from 'node:test'
import ts from 'typescript'
import { reactive, ref } from 'vue'

const source = readFileSync(new URL('../src/App.vue', import.meta.url), 'utf8')
const view = readFileSync(new URL('../src/views/ConsoleView.vue', import.meta.url), 'utf8')
const script = source.match(/<script setup lang="ts">([\s\S]*?)<\/script>/)[1].replace(/^import .*$/gm, '')
const code = ts.transpileModule(script + '\nglobalThis.result = { desk, noticeKey, resetDesk, navigate };', { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText

function setup() {
  let next = 0, unmount, onPageChange
  const timers = new Map(), delays = []
  const window = {
    setTimeout: (fn, ms) => { const id = ++next; timers.set(id, fn); delays.push(ms); return id },
    setInterval: () => 99, clearInterval: () => {},
    addEventListener: () => {}, removeEventListener: () => {},
  }
  const context = vm.createContext({ exports: {}, reactive, ref, watch: (_page, fn) => { onPageChange = fn }, provide: () => {}, onMounted: () => {}, onUnmounted: fn => { unmount = fn }, window, location: { hash: '#/dashboard' }, document: { title: '', visibilityState: 'visible' }, clearTimeout: id => timers.delete(id), deskKey: {}, navigateKey: {}, pageFromHash: () => 'dashboard' })
  vm.runInContext(code, context)
  return { ...context.result, timers, delays, onPageChange: next => onPageChange(next), unmount: () => unmount() }
}

test('success and failure have distinct lifetimes; repeating identical text resets timer and announcement key', () => {
  const s = setup()
  s.desk.notify('saved')
  assert.equal(s.delays.at(-1), 4000)
  const firstId = [...s.timers.keys()][0]
  const firstKey = s.noticeKey.value
  s.desk.notify('saved')
  assert.equal(s.delays.at(-1), 4000)
  assert.equal(s.timers.size, 1)
  assert.equal(s.noticeKey.value, firstKey + 1)
  assert.equal(s.desk.notice, 'saved')
  // The browser cannot run a cancelled timer after it has been replaced.
  assert.equal(s.timers.has(firstId), false)
  s.desk.notify('failed', true)
  assert.equal(s.delays.at(-1), 8000)
  assert.equal(s.timers.size, 1)
  assert.equal(s.desk.noticeBad, true)
  ;[...s.timers.values()][0]()
  assert.equal(s.desk.notice, '')
  assert.equal(s.desk.noticeBad, false)
  assert.equal(s.timers.size, 0)
})

test('close, page change, reset, empty message and unmount remove active timers', () => {
  const s = setup()
  s.desk.notify('next')
  s.desk.dismissNotice()
  assert.equal(s.timers.size, 0)
  s.desk.notify('change')
  s.onPageChange('servers')
  assert.equal(s.timers.size, 0)
  assert.equal(s.desk.notice, '')
  s.desk.notify('last')
  s.resetDesk()
  assert.equal(s.timers.size, 0)
  s.desk.notify('')
  assert.equal(s.timers.size, 0)
  s.desk.notify('last again')
  s.unmount()
  assert.equal(s.timers.size, 0)
  assert.equal(s.desk.notice, '')
})

test('toast has polite success announcements, assertive errors and a keyboard-operable close button', () => {
  assert.match(source, /:notice-key="noticeKey"/)
  assert.match(view, /:key="noticeKey"/)
  assert.match(view, /class="notice-layer" aria-live="polite" aria-atomic="true"/)
  assert.match(view, /:role="desk\.noticeBad \? 'alert' : undefined"/)
  assert.match(view, /<button type="button" class="icon-btn" aria-label="关闭提示" @click="desk\.dismissNotice\(\)"/)
})
