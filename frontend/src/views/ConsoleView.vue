<script setup lang="ts">
import { inject } from 'vue'
import { deskKey } from '../desk'
import { pages, type PageId } from '../types'
import AuditView from './AuditView.vue'
import ClientsView from './ClientsView.vue'
import DashboardView from './DashboardView.vue'
import LogsView from './LogsView.vue'
import ProxiesView from './ProxiesView.vue'
import ServersView from './ServersView.vue'

defineProps<{ page: PageId; account: string }>()
const emit = defineEmits<{ navigate: [page: PageId]; logout: [] }>()
const desk = inject(deskKey)!
const nav: PageId[] = ['dashboard', 'servers', 'clients', 'proxies', 'logs', 'audit']
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
          <span class="who">{{ account || '管理员会话' }}</span>
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
        <p v-if="desk.notice" class="notice" :class="{ bad: desk.noticeBad }" role="status">{{ desk.notice }}</p>
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
