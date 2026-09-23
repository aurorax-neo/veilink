<script setup lang="ts">
import { inject } from 'vue'
import { deskKey } from '../desk'
import { pages, type PageId } from '../types'
import AuditView from './AuditView.vue'
import BindingsView from './BindingsView.vue'
import MappingsView from './MappingsView.vue'
import NodesView from './NodesView.vue'
import OverviewView from './OverviewView.vue'

defineProps<{ page: PageId; account: string }>()
const emit = defineEmits<{ navigate: [page: PageId]; logout: [] }>()
const desk = inject(deskKey)!
const nav: PageId[] = ['overview', 'nodes', 'bindings', 'mappings', 'audit']
</script>

<template>
  <div class="shell">
    <aside class="side">
      <a class="brand" href="#/overview">
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
          {{ pages[id].title }}
        </button>
      </nav>
      <div class="side-note">
        <span>架构</span>
        <p>控制面与数据面分开</p>
        <small>业务流量不经过管理中心</small>
      </div>
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
            <p class="kicker">{{ pages[page].kicker }}</p>
            <h1>{{ pages[page].title }}</h1>
            <p class="lead">{{ pages[page].lead }}</p>
          </div>
          <button type="button" class="btn" :disabled="desk.loading" @click="desk.reload()">{{ desk.loading ? '刷新中…' : '刷新' }}</button>
        </div>
        <p v-if="desk.notice" class="notice" :class="{ bad: desk.noticeBad }" role="status">{{ desk.notice }}</p>
        <OverviewView v-if="page === 'overview'" />
        <NodesView v-else-if="page === 'nodes'" />
        <BindingsView v-else-if="page === 'bindings'" />
        <MappingsView v-else-if="page === 'mappings'" />
        <AuditView v-else />
        <footer class="fineprint"><span>VEILINK</span><span>心跳只说明控制面还在。配置下发会短暂断开该节点已有连接。</span></footer>
      </main>
    </div>
  </div>
</template>
