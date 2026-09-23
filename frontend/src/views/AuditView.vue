<script setup lang="ts">
import { computed, inject, ref } from 'vue'
import { deskKey } from '../desk'
import { actionLabel, seenText } from '../format'
import EmptyState from '../components/EmptyState.vue'

const desk = inject(deskKey)!
const query = ref('')
const rows = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return desk.audit
  return desk.audit.filter((item) => [item.action, actionLabel(item.action), item.object].join(' ').toLowerCase().includes(q))
})
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="正在读取审计" text="正在从管理中心获取最近的写操作。" />
  <EmptyState v-else-if="!desk.loaded" title="暂时无法读取审计" :text="(desk.error || '请求失败') + ' 未显示缓存或演示数据。'" />
  <div v-else class="stack">
    <div class="toolbar">
      <input v-model="query" type="search" aria-label="搜索审计" placeholder="搜索动作或对象 ID" />
    </div>
    <p class="legend">列表按管理中心返回的顺序展示，最多 500 条。node.revoke 同时表示吊销和删除，页面不会把两者说成同一种操作。</p>
    <section class="panel">
      <header class="panel-head"><h2>审计事件</h2><small>{{ rows.length }} 条</small></header>
      <EmptyState v-if="!rows.length" title="没有匹配的审计" text="管理写操作会记在这里。只读刷新不会产生事件。" />
      <ol v-else class="timeline">
        <li v-for="(item, index) in rows" :key="`${item.at}-${item.action}-${item.object}-${index}`">
          <time>{{ seenText(item.at) }}</time>
          <div>
            <strong>{{ actionLabel(item.action) }}</strong>
            <code>{{ item.object }}</code>
            <small class="mono">{{ item.action }}</small>
          </div>
        </li>
      </ol>
    </section>
  </div>
</template>
