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
  <EmptyState v-if="!desk.loaded && desk.loading" title="加载中…" text="" />
  <EmptyState v-else-if="!desk.loaded" title="加载失败" :text="desk.error" />
  <div v-else class="stack">
    <div class="toolbar">
      <input v-model="query" type="search" aria-label="搜索审计" placeholder="搜索动作或对象 ID" />
    </div>
    <section class="panel">
      <header class="panel-head"><h2>审计事件</h2><small>{{ rows.length }} 条</small></header>
      <EmptyState v-if="!rows.length" title="暂无审计" text="" />
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
