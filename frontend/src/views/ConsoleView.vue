<script setup lang="ts">
import { inject, onMounted, ref } from 'vue'
import { api, getVersionInfo, type VersionInfo } from '../api'
import { deskKey } from '../desk'
import { runPageRefresh } from '../pageRefresh'
import { pages, type PageId } from '../types'
import AuditView from './AuditView.vue'
import ClientsView from './ClientsView.vue'
import DashboardView from './DashboardView.vue'
import LogsView from './LogsView.vue'
import ProxiesView from './ProxiesView.vue'
import ServersView from './ServersView.vue'
import SettingsView from './SettingsView.vue'

defineProps<{ page: PageId; noticeKey: number }>()
const emit = defineEmits<{ navigate: [page: PageId]; logout: [] }>()
const desk = inject(deskKey)!
const nav: PageId[] = ['dashboard', 'servers', 'clients', 'proxies', 'logs', 'audit', 'settings']
const software = ref<VersionInfo | null>(null)
const versionError = ref(false)
async function loadVersion() {
  versionError.value = false
  try {
    software.value = await getVersionInfo()
  } catch { versionError.value = true }
}
onMounted(loadVersion)
async function refresh() {
  if (desk.loading || desk.refreshing) return
  desk.refreshing = true
  try {
    await desk.reload()
    await runPageRefresh()
  } catch { /* desk displays the error. */ } finally { desk.refreshing = false }
}
</script>

<template>
  <div class="shell">
    <aside class="side">
      <a class="brand" href="#/dashboard">
        <svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" /><path d="M7.5 8.5h4.4L16 20.2 20.1 8.5H24.5L17.4 24.5h-2.8L7.5 8.5z" /></svg>
        veilink
      </a>
      <p class="side-label">工作空间</p>
      <nav aria-label="主导航">
        <button
          v-for="id in nav"
          :key="id"
          type="button"
          class="nav-btn"
          :class="{ on: page === id }"
          :aria-current="page === id ? 'page' : undefined"
          @click="emit('navigate', id)"
        >
          <span class="nav-icon" aria-hidden="true">{{ pages[id].icon }}</span>
          {{ pages[id].title }}
        </button>
      </nav>
    </aside>
    <div class="workspace">
      <header class="topbar">
        <p>管理中心 <span>/ {{ pages[page].title }}</span></p>
        <div class="top-actions">
          <details class="build-version">
             <summary :title="software?.backend_version"><span class="fit"><span class="fit-sizer" aria-hidden="true">软件 加载中…</span><span class="fit-sizer" aria-hidden="true">软件 未获取</span><span class="fit-sizer" aria-hidden="true">软件 {{ software?.backend_version || '加载中…' }}</span><span class="fit-value">软件 {{ software?.backend_version || (versionError ? '未获取' : '加载中…') }}</span></span></summary>
            <div class="build-details">
              <p>后端版本：{{ software?.backend_version || '未知' }}</p>
              <p>API 契约：{{ software?.api_version || '未知' }}</p>
              <p>前端版本：{{ (software?.web_version && software.web_version !== 'prebundled') ? software.web_version : (software?.backend_version || '未知') }}</p>
              <button v-if="versionError" type="button" class="btn small" @click="loadVersion">重试</button>
            </div>
          </details>
          <span class="who">API Key</span>
          <button type="button" class="btn quiet" @click="emit('logout')">断开连接</button>
        </div>
      </header>
      <main id="main" class="stage" tabindex="-1">
        <div class="page-head">
          <div>
            <h1>{{ pages[page].title }}</h1>
          </div>
           <button type="button" class="btn fit" :disabled="desk.loading || desk.refreshing" @click="refresh"><span class="fit-sizer" aria-hidden="true">刷新中…</span><span class="fit-sizer" aria-hidden="true">刷新</span><span class="fit-value">{{ desk.loading || desk.refreshing ? '刷新中…' : '刷新' }}</span></button>
        </div>
        <div class="notice-layer" aria-live="polite" aria-atomic="true">
          <div v-if="desk.notice" :key="noticeKey" class="notice toast" :class="{ bad: desk.noticeBad }" :role="desk.noticeBad ? 'alert' : undefined">
            <span class="toast-mark" aria-hidden="true">{{ desk.noticeBad ? '!' : '✓' }}</span>
            <span class="toast-text">{{ desk.notice }}</span>
            <button type="button" class="icon-btn" aria-label="关闭提示" @click="desk.dismissNotice()">×</button>
          </div>
        </div>
        <DashboardView v-if="page === 'dashboard'" />
        <ServersView v-else-if="page === 'servers'" />
        <ClientsView v-else-if="page === 'clients'" />
        <ProxiesView v-else-if="page === 'proxies'" />
        <LogsView v-else-if="page === 'logs'" />
        <AuditView v-else-if="page === 'audit'" />
        <SettingsView v-else />
      </main>
    </div>
  </div>
</template>
