<script setup lang="ts">
import { inject, onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { logLevelTone, seenText } from '../format'
import { nodeName } from '../format'
import type { LogEntry } from '../types'
import EmptyState from '../components/EmptyState.vue'
import Badge from '../components/Badge.vue'

const desk = inject(deskKey)!
const source = ref<'all' | 'master' | 'node'>('all')
const nodeId = ref('')
const level = ref('')
const logs = ref<LogEntry[]>([])
const loading = ref(false)
const error = ref('')
let request = 0
const autoRefresh = ref(false)
let timer: ReturnType<typeof setInterval> | null = null

async function fetchLogs() {
  const ticket = ++request
  error.value = ''
  loading.value = true
  try {
    const params = new URLSearchParams()
    if (source.value !== 'all') params.set('source', source.value)
    if (source.value === 'node' && nodeId.value) params.set('node_id', nodeId.value)
    if (level.value) params.set('level', level.value)
    params.set('limit', '200')
    const result = await api<LogEntry[]>(`/logs?${params.toString()}`)
    if (ticket === request) logs.value = result || []
  } catch (reason) {
    if (ticket === request) error.value = reason instanceof Error ? reason.message : '加载失败'
  } finally {
    if (ticket === request) loading.value = false
  }
}

function toggleAutoRefresh() {
  autoRefresh.value = !autoRefresh.value
  if (autoRefresh.value) {
    timer = setInterval(fetchLogs, 5000)
  } else if (timer) {
    clearInterval(timer)
    timer = null
  }
}

onMounted(fetchLogs)
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<template>
  <div class="stack">
    <div class="log-controls">
      <div class="chips" role="group" aria-label="来源">
        <button type="button" :aria-pressed="source === 'all'" @click="source = 'all'; fetchLogs()">全部</button>
        <button type="button" :aria-pressed="source === 'master'" @click="source = 'master'; fetchLogs()">管理中心</button>
        <button type="button" :aria-pressed="source === 'node'" @click="source = 'node'; fetchLogs()">节点</button>
      </div>
      <select v-if="source === 'node'" v-model="nodeId" aria-label="节点" @change="fetchLogs()">
        <option value="">全部节点</option>
        <option v-for="n in desk.nodes" :key="n.id" :value="n.id">{{ n.name }}</option>
      </select>
      <div class="chips" role="group" aria-label="级别">
        <button type="button" :aria-pressed="level === ''" @click="level = ''; fetchLogs()">全部</button>
        <button type="button" :aria-pressed="level === 'INFO'" @click="level = 'INFO'; fetchLogs()">INFO</button>
        <button type="button" :aria-pressed="level === 'WARN'" @click="level = 'WARN'; fetchLogs()">WARN</button>
        <button type="button" :aria-pressed="level === 'ERROR'" @click="level = 'ERROR'; fetchLogs()">ERROR</button>
      </div>
      <button type="button" class="btn small" :class="{ primary: autoRefresh }" @click="toggleAutoRefresh">{{ autoRefresh ? '停止自动刷新' : '自动刷新' }}</button>
      <button type="button" class="btn small" :disabled="loading" @click="fetchLogs">{{ loading ? '刷新中…' : '刷新' }}</button>
    </div>

    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <EmptyState v-else-if="loading && !logs.length" title="加载中…" text="" />
    <EmptyState v-else-if="!logs.length" title="暂无日志" text="" />
    <section v-else class="panel">
      <header class="panel-head"><h2>日志</h2><small>{{ logs.length }} 条</small></header>
      <ul class="log-list">
        <li v-for="(entry, index) in logs" :key="index" class="log-entry">
          <time>{{ entry.at ? seenText(entry.at) : '' }}</time>
          <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
            <Badge :text="entry.level || 'INFO'" :tone="logLevelTone(entry.level)" />
            <Badge v-if="entry.source" :text="entry.source === 'master' ? 'Master' : (entry.node_id ? nodeName(desk.nodes, entry.node_id) : entry.source)" />
          </div>
          <span class="log-msg">{{ entry.message }}</span>
        </li>
      </ul>
    </section>
  </div>
</template>
