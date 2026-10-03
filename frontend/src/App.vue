<script setup lang="ts">
import { onMounted, onUnmounted, provide, reactive, ref, watch } from 'vue'
import { api, ApiError, getApiKey, setApiKey, clearApiKey, setUnauthorized, checkApiCompatibility } from './api'
import { deskKey, navigateKey, type Desk } from './desk'
import { pageFromHash, pages, type Audit, type Mapping, type Node, type PageId } from './types'
import ConsoleView from './views/ConsoleView.vue'
import LoginView from './views/LoginView.vue'

const phase = ref<'boot' | 'login' | 'app'>('boot')
const loginError = ref('')
const loginBusy = ref(false)
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
  refreshing: false,
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
  desk.refreshing = false
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

async function enter() {
  phase.value = 'app'
  loginError.value = ''
  document.title = `Veilink · ${pages[page.value].title}`
  try {
    await desk.reload()
  } catch {
    // 数据加载失败不影响进入，控制台内会显示错误
  }
}

async function submitLogin(apiKey: string) {
  loginBusy.value = true
  loginError.value = ''
  try {
    setApiKey(apiKey)
    // 用一个轻量接口验证 Key 有效性
    await api('/stats')
    await enter()
  } catch (reason) {
    clearApiKey()
    loginError.value = reason instanceof Error ? reason.message : '连接失败'
  } finally {
    loginBusy.value = false
  }
}

function logout() {
  clearApiKey()
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
  if (phase.value !== 'app' || document.visibilityState === 'hidden' || desk.loading || desk.refreshing || liveBusy) return
  liveBusy = true
  try {
    await desk.reload({ silent: true })
  } finally {
    liveBusy = false
  }
}

function onVisible() { if (document.visibilityState === 'visible') void refreshLive() }
onMounted(async () => {
  setUnauthorized(() => {
    clearApiKey()
    resetDesk()
    phase.value = 'login'
    loginError.value = 'API Key 已失效，请重新输入。'
    document.title = 'Veilink · 穿透控制台'
  })
  window.addEventListener('hashchange', onHash)
  window.addEventListener('visibilitychange', onVisible)
  liveTimer = window.setInterval(() => { void refreshLive() }, 5000)

  // 启动时检查 API 契约版本
  try {
    await checkApiCompatibility()
  } catch (reason) {
    loginError.value = reason instanceof Error ? reason.message : '版本检查失败'
    // 版本不兼容也允许进入，由页面显示警告
  }

  // 有 Key 则尝试直接进入
  if (getApiKey()) {
    try {
      await api('/stats')
      await enter()
      return
    } catch {
      clearApiKey()
    }
  }
  phase.value = 'login'
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
  <!-- 骨架屏：布局与真实界面一致，避免闪屏 -->
  <div v-if="phase === 'boot'" class="shell skeleton" aria-hidden="true">
    <aside class="side">
      <div class="sk sk-brand"></div>
      <div class="sk sk-line" v-for="i in 6" :key="i"></div>
    </aside>
    <main class="stage">
      <div class="sk sk-title"></div>
      <div class="sk sk-line" v-for="i in 8" :key="i"></div>
    </main>
  </div>
  <LoginView v-else-if="phase === 'login'" :error="loginError" :busy="loginBusy" @submit="submitLogin" />
  <ConsoleView v-else :page="page" :notice-key="noticeKey" @navigate="navigate" @logout="logout" />
</template>
