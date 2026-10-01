<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { byNameAndId, logLevelTone, nodeName } from '../format'
import type { LogEntry } from '../types'
import EmptyState from '../components/EmptyState.vue'
import Badge from '../components/Badge.vue'

const desk = inject(deskKey)!
const source = ref<'all' | 'master' | 'node'>('all')
const nodeId = ref('')
const level = ref('')
const logs = ref<LogEntry[]>([])
const sortedNodes = computed(() => [...desk.nodes].sort(byNameAndId))
const loading = ref(false)
const error = ref('')
let request = 0
const autoRefresh = ref(false)
let timer: ReturnType<typeof setInterval> | null = null

function sourceLabel(entry: LogEntry): string {
  if (entry.source === 'master') return 'Master'
  if (!entry.node_id) return entry.source || '节点'
  const role = desk.nodes.find(n => n.id === entry.node_id)?.role
  return `${role === 'server' ? 'Server' : role === 'client' ? 'Client' : '节点'} · ${nodeName(desk.nodes, entry.node_id)}`
}
async function fetchLogs() {
  const ticket = ++request
  error.value = ''
  loading.value = true
  try {
    const params = new URLSearchParams()
    if (source.value !== 'all') params.set('source', source.value)
    if (source.value === 'node' && nodeId.value) params.set('node_id', nodeId.value)
    if (level.value) params.set('level', level.value)
    params.set('limit', '500')
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
        <option v-for="n in sortedNodes" :key="n.id" :value="n.id">{{ n.name }}</option>
      </select>
      <div class="chips" role="group" aria-label="级别">
        <button type="button" :aria-pressed="level === ''" @click="level = ''; fetchLogs()">全部</button>
        <button type="button" :aria-pressed="level === 'INFO'" @click="level = 'INFO'; fetchLogs()">INFO</button>
        <button type="button" :aria-pressed="level === 'WARN'" @click="level = 'WARN'; fetchLogs()">WARN</button>
        <button type="button" :aria-pressed="level === 'ERROR'" @click="level = 'ERROR'; fetchLogs()">ERROR</button>
      </div>
       <button type="button" class="btn small fit" :class="{ primary: autoRefresh }" @click="toggleAutoRefresh"><span class="fit-sizer" aria-hidden="true">停止自动刷新</span><span class="fit-sizer" aria-hidden="true">自动刷新</span><span class="fit-value">{{ autoRefresh ? '停止自动刷新' : '自动刷新' }}</span></button>
       <button type="button" class="btn small fit" :disabled="loading" @click="fetchLogs"><span class="fit-sizer" aria-hidden="true">刷新中…</span><span class="fit-sizer" aria-hidden="true">刷新</span><span class="fit-value">{{ loading ? '刷新中…' : '刷新' }}</span></button>
    </div>

    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <EmptyState v-else-if="loading && !logs.length" title="加载中…" text="" />
    <EmptyState v-else-if="!logs.length" title="暂无近期日志" text="节点日志需成功连接 Master 后才会上报；日志仅保存在当前 Master 内存中，重启后不保留。" />
    <section v-else class="panel">
      <header class="panel-head"><h2>最近日志</h2><small>最新 {{ logs.length }} 条 · 内存记录</small></header>
      <ul class="log-list">
        <li v-for="(entry, index) in logs" :key="index" class="log-entry">
          <time :datetime="entry.at ? new Date(entry.at * 1000).toISOString() : undefined">{{ entry.at ? new Date(entry.at * 1000).toLocaleString('zh-CN', { hour12: false }) : '时间未知' }}</time>
          <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
            <Badge :text="entry.level || 'INFO'" :tone="logLevelTone(entry.level)" />
            <Badge v-if="entry.source" :text="sourceLabel(entry)" />
          </div>
          <span class="log-msg">{{ entry.message }}</span>
        </li>
      </ul>
    </section>
  </div>
</template>
