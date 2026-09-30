<script setup lang="ts">
import { onMounted, onUnmounted, provide, reactive, ref, watch } from 'vue'
import { api, ApiError, clearCsrf, setCsrf, setUnauthorized } from './api'
import { deskKey, navigateKey, type Desk } from './desk'
import { pageFromHash, pages, type Audit, type Mapping, type Node, type PageId } from './types'
import ConsoleView from './views/ConsoleView.vue'
import LoginView from './views/LoginView.vue'

const phase = ref<'boot' | 'setup-error' | 'register' | 'login' | 'app'>('boot')
const loginError = ref('')
const loginBusy = ref(false)
const account = ref('')
const page = ref<PageId>(pageFromHash())
// A new key remounts the live region when identical messages are sent again.
const noticeKey = ref(0)
let generation = 0
let noticeTimer: ReturnType<typeof setTimeout> | undefined
function dismissNotice() {
  if (noticeTimer) clearTimeout(noticeTimer)
  noticeTimer = undefined
  desk.notice = ''
  desk.noticeBad = false
}

const desk = reactive<Desk>({
  nodes: [],
  mappings: [],
  audit: [],
  traffic: [],
  trafficLoaded: false,
  trafficError: '',
  loading: false,
  loaded: false,
  error: '',
  notice: '',
  noticeBad: false,
  async reloadNodes(id: string) {
    const ticket = generation
    const previous = desk.nodes.find(node => node.id === id)
    const nodes = await api<Node[] | null>('/nodes')
    if (ticket !== generation || phase.value !== 'app' || !previous || desk.nodes.find(node => node.id === id) !== previous) return
    if (!Array.isArray(nodes)) throw new ApiError('节点数据格式不正确。', 200)
    const updated = nodes.find(node => node.id === id)
    if (!updated) throw new ApiError('节点已不存在，请刷新列表。', 404)
    desk.nodes = desk.nodes.map(node => node.id === id ? updated : node)
  },
  async reload(options?: { silent?: boolean }) {
    if (options?.silent && desk.loading) return
    const ticket = ++generation
    if (!options?.silent) desk.loading = true
    try {
      const nodes = await api<Node[] | null>('/nodes')
      if (ticket !== generation) return
      if (nodes !== null && !Array.isArray(nodes)) throw new ApiError('API 数据格式不正确。', 200)
      if (options?.silent) {
        desk.nodes = nodes || []
        if (page.value === 'proxies') await loadTraffic(ticket)
        return
      }
      const [mappings, audit] = await Promise.all([
        api<Mapping[] | null>('/mappings'),
        api<Audit[] | null>('/audit'),
      ])
      if (ticket !== generation) return
      if (![mappings, audit].every((item) => item === null || Array.isArray(item))) throw new ApiError('API 数据格式不正确。', 200)
      desk.nodes = nodes || []
      desk.mappings = mappings || []
      desk.audit = audit || []
      await loadTraffic(ticket)
      if (ticket !== generation) return
      desk.loaded = true
      desk.error = ''
    } catch (reason) {
      if (ticket !== generation || options?.silent) return
      const message = reason instanceof Error ? reason.message : '请求失败'
      desk.error = message
      desk.notify(message, true)
      throw reason
    } finally {
      if (ticket === generation && !options?.silent) desk.loading = false
    }
  },
  notify(text: string, bad = false) {
    dismissNotice()
    if (!text) return
    noticeKey.value += 1
    desk.noticeBad = bad
    desk.notice = text
    noticeTimer = window.setTimeout(dismissNotice, bad ? 8000 : 4000)
  },
  dismissNotice,
})
async function loadTraffic(ticket: number) {
  try {
    const rows = await api<import('./types').TrafficRow[] | null>('/traffic')
    if (ticket !== generation) return
    if (rows !== null && !Array.isArray(rows)) throw new Error('流量数据格式不正确')
    desk.traffic = rows || []
    desk.trafficLoaded = true
    desk.trafficError = ''
  } catch (reason) {
    if (ticket !== generation) return
    desk.trafficError = reason instanceof Error ? reason.message : '流量读取失败'
  }
}

function resetDesk() {
  generation += 1
  desk.nodes = []
  desk.mappings = []
  desk.audit = []
  desk.loaded = false
  desk.traffic = []
  desk.trafficLoaded = false
  desk.trafficError = ''
  desk.loading = false
  desk.error = ''
  dismissNotice()
}

function navigate(next: PageId) {
  page.value = next
  const hash = `#/${next}`
  if (location.hash !== hash) location.hash = hash
}

function onHash() {
  page.value = pageFromHash()
}

provide(deskKey, desk)
provide(navigateKey, navigate)

async function enter(session: { csrf?: string }, name = '') {
  if (!session.csrf) throw new Error('会话缺少 CSRF 凭据，请重新登录。')
  setCsrf(session.csrf)
  account.value = name
  phase.value = 'app'
  loginError.value = ''
  document.title = `Veilink · ${pages[page.value].title}`
  try {
    await desk.reload()
  } catch {
    // Shown in the console. A failed read is not a failed login.
  }
}

async function loadSetup(restoreSession = false) {
  phase.value = 'boot'
  try {
    const setup = await api<{ registration_required: boolean }>('/setup')
    if (typeof setup.registration_required !== 'boolean') throw new Error('初始化状态无效')
    phase.value = setup.registration_required ? 'register' : restoreSession ? 'boot' : 'login'
  } catch (reason) {
    phase.value = 'setup-error'
    loginError.value = reason instanceof Error ? reason.message : '无法确认初始化状态'
  }
}

async function submitLogin(username: string, password: string) {
  loginBusy.value = true
  loginError.value = ''
  try {
    if (phase.value === 'register') {
      await api('/register', 'POST', { username, password })
      phase.value = 'login'
      loginError.value = '注册成功，请使用新账号登录。'
    } else {
      await enter(await api<{ csrf?: string }>('/login', 'POST', { username, password }), username.trim())
    }
  } catch (reason) {
    if (reason instanceof ApiError && reason.status === 409) await loadSetup()
    loginError.value = reason instanceof Error ? reason.message : '登录失败'
  } finally {
    loginBusy.value = false
  }
}

async function logout() {
  try {
    await api('/logout', 'POST', {})
  } catch (reason) {
    desk.notify(reason instanceof Error ? reason.message : '退出失败', true)
    return
  }
  clearCsrf()
  account.value = ''
  resetDesk()
  phase.value = 'login'
  document.title = 'Veilink · 穿透控制台'
}

watch(page, (next) => {
  if (phase.value === 'app') document.title = `Veilink · ${pages[next].title}`
  dismissNotice()
})

let liveTimer: ReturnType<typeof setInterval> | undefined
let liveBusy = false
async function refreshLive() {
  if (phase.value !== 'app' || document.visibilityState === 'hidden' || desk.loading || liveBusy) return
  liveBusy = true
  try {
    await desk.reload({ silent: true })
  } finally {
    liveBusy = false
  }
}

function onVisible() { if (document.visibilityState === 'visible') void refreshLive() }
onMounted(async () => {
  setUnauthorized((path) => {
    if (path === '/session') return
    clearCsrf()
    account.value = ''
    resetDesk()
    phase.value = 'login'
    loginError.value = '会话已失效，请重新登录。'
    document.title = 'Veilink · 穿透控制台'
  })
  window.addEventListener('hashchange', onHash)
  window.addEventListener('visibilitychange', onVisible)
  liveTimer = window.setInterval(() => { void refreshLive() }, 5000)
  await loadSetup(true)
  if (phase.value !== 'boot') return
  try {
    await enter(await api<{ csrf?: string }>('/session'))
  } catch (reason) {
    phase.value = 'login'
    if (!(reason instanceof ApiError) || reason.status !== 401) {
      loginError.value = reason instanceof Error ? reason.message : '无法确认会话'
    }
  }
})

onUnmounted(() => {
  window.removeEventListener('hashchange', onHash)
  window.removeEventListener('visibilitychange', onVisible)
  if (liveTimer) window.clearInterval(liveTimer)
  dismissNotice()
})
</script>

<template>
  <a class="skip" :href="phase === 'app' ? '#main' : '#login-main'">跳转到主内容</a>
  <p v-if="phase === 'boot'" class="boot">正在确认会话…</p>
  <div v-else-if="phase === 'setup-error'" class="boot" role="alert">{{ loginError }} <button class="btn" @click="loadSetup()">重试</button></div>
  <LoginView v-else-if="phase === 'login' || phase === 'register'" :key="phase" :register="phase === 'register'" :error="loginError" :busy="loginBusy" @submit="submitLogin" />
  <ConsoleView v-else :page="page" :account="account" :notice-key="noticeKey" @navigate="navigate" @logout="logout" />
</template>
