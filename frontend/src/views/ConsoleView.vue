<script setup lang="ts">
import { inject, onMounted, ref } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { pages, type PageId } from '../types'
import AuditView from './AuditView.vue'
import ClientsView from './ClientsView.vue'
import DashboardView from './DashboardView.vue'
import LogsView from './LogsView.vue'
import ProxiesView from './ProxiesView.vue'
import ServersView from './ServersView.vue'

defineProps<{ page: PageId; account: string; noticeKey: number }>()
const emit = defineEmits<{ navigate: [page: PageId]; logout: [] }>()
const desk = inject(deskKey)!
const nav: PageId[] = ['dashboard', 'servers', 'clients', 'proxies', 'logs', 'audit']
const software = ref<{ version: string; commit: string } | null>(null)
const versionError = ref(false)
async function loadVersion() {
  versionError.value = false
  try { software.value = await api('/version') } catch { versionError.value = true }
}
onMounted(loadVersion)
async function refresh() {
  try { await desk.reload() } catch { /* desk displays the error. */ }
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
            <summary :title="software?.version">软件 {{ software?.version || (versionError ? '未获取' : '加载中…') }}</summary>
            <div class="build-details">
              <p>管理中心：{{ software?.version || '未知' }}</p>
              <p>构建提交：<code>{{ software?.commit || '未知' }}</code></p>
              <button v-if="versionError" type="button" class="btn small" @click="loadVersion">重试</button>
            </div>
          </details>
          <span class="who">{{ account || '当前账号' }}</span>
          <button type="button" class="btn quiet" @click="emit('logout')">退出登录</button>
        </div>
      </header>
      <main id="main" class="stage" tabindex="-1">
        <div class="page-head">
          <div>
            <h1>{{ pages[page].title }}</h1>
          </div>
          <button type="button" class="btn" :disabled="desk.loading" @click="refresh">{{ desk.loading ? '刷新中…' : '刷新' }}</button>
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
        <AuditView v-else />
      </main>
    </div>
  </div>
</template>
