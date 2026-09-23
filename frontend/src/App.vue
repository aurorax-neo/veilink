<script setup lang="ts">
import { onMounted, onUnmounted, provide, reactive, ref, watch } from 'vue'
import { api, ApiError, clearCsrf, setCsrf, setUnauthorized } from './api'
import { deskKey, navigateKey, type Desk } from './desk'
import { pageFromHash, pages, type Audit, type Binding, type Mapping, type Node, type PageId } from './types'
import ConsoleView from './views/ConsoleView.vue'
import LoginView from './views/LoginView.vue'

const phase = ref<'boot' | 'login' | 'app'>('boot')
const loginError = ref('')
const loginBusy = ref(false)
const account = ref('')
const page = ref<PageId>(pageFromHash())
let generation = 0

const desk = reactive<Desk>({
  nodes: [],
  bindings: [],
  mappings: [],
  audit: [],
  loading: false,
  loaded: false,
  error: '',
  notice: '',
  noticeBad: false,
  async reload() {
    const ticket = ++generation
    desk.loading = true
    try {
      const [nodes, bindings, mappings, audit] = await Promise.all([
        api<Node[] | null>('/nodes'),
        api<Binding[] | null>('/bindings'),
        api<Mapping[] | null>('/mappings'),
        api<Audit[] | null>('/audit'),
      ])
      if (ticket !== generation) return
      if (![nodes, bindings, mappings, audit].every((item) => item === null || Array.isArray(item))) {
        throw new ApiError('API 数据格式不正确。', 200)
      }
      desk.nodes = nodes || []
      desk.bindings = bindings || []
      desk.mappings = mappings || []
      desk.audit = audit || []
      desk.loaded = true
      desk.error = ''
    } catch (reason) {
      if (ticket !== generation) return
      const message = reason instanceof Error ? reason.message : '请求失败'
      desk.error = message
      desk.notify(message, true)
      throw reason
    } finally {
      if (ticket === generation) desk.loading = false
    }
  },
  notify(text: string, bad = false) {
    desk.notice = text
    desk.noticeBad = bad
  },
})

function resetDesk() {
  generation += 1
  desk.nodes = []
  desk.bindings = []
  desk.mappings = []
  desk.audit = []
  desk.loaded = false
  desk.loading = false
  desk.error = ''
  desk.notice = ''
  desk.noticeBad = false
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

async function submitLogin(username: string, password: string) {
  loginBusy.value = true
  loginError.value = ''
  try {
    await enter(await api<{ csrf?: string }>('/login', 'POST', { username, password }), username.trim())
  } catch (reason) {
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
  desk.notice = ''
  desk.noticeBad = false
})

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
  try {
    await enter(await api<{ csrf?: string }>('/session'))
  } catch (reason) {
    phase.value = 'login'
    if (!(reason instanceof ApiError) || reason.status !== 401) {
      loginError.value = reason instanceof Error ? reason.message : '无法确认会话'
    }
  }
})

onUnmounted(() => window.removeEventListener('hashchange', onHash))
</script>

<template>
  <a class="skip" :href="phase === 'app' ? '#main' : '#login-main'">跳转到主内容</a>
  <p v-if="phase === 'boot'" class="boot">正在确认会话…</p>
  <LoginView v-else-if="phase === 'login'" :error="loginError" :busy="loginBusy" @submit="submitLogin" />
  <ConsoleView v-else :page="page" :account="account" @navigate="navigate" @logout="logout" />
</template>
