<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { askNodes, nodeBaseline, nodeChanged, registerPageRefresh, waitForReports } from '../pageRefresh'
import { byNameAndId, formatTime, logLevelTone, nodeName } from '../format'
import type { LogEntry } from '../types'
import EmptyState from '../components/EmptyState.vue'
import Badge from '../components/Badge.vue'

const desk = inject(deskKey)!
const source = ref<'all' | 'master' | 'node'>('all')
const nodeId = ref('')
const level = ref('')
const query = ref('')
const logs = ref<LogEntry[]>([])
const sortedNodes = computed(() => [...desk.nodes].sort(byNameAndId))
const filteredLogs = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return logs.value
  return logs.value.filter(entry => [entry.message, entry.level, entry.source, sourceLabel(entry)].join(' ').toLowerCase().includes(q))
})
const loading = ref(false)
const error = ref('')
const logListRef = ref<HTMLElement | null>(null)
const showJumpLatest = ref(false)
const userScrolledAway = ref(false)
let request = 0
let active = true
let unregisterPageRefresh: (() => void) | undefined
let offStreamLog: (() => void) | undefined
const autoRefresh = ref(false)
let timer: ReturnType<typeof setInterval> | null = null

function setSource(next: 'all' | 'master' | 'node') {
  source.value = next
  try {
    globalThis.sessionStorage?.setItem('veilink_logs_source', next)
    globalThis.localStorage?.setItem('veilink_logs_source', next)
  } catch { /* ignore */ }
  void fetchLogs()
}

function setLevel(next: string) {
  level.value = next
  try {
    globalThis.sessionStorage?.setItem('veilink_logs_level', next)
    globalThis.localStorage?.setItem('veilink_logs_level', next)
  } catch { /* ignore */ }
  void fetchLogs()
}

function onLogScroll(event: Event) {
  const el = event.target as HTMLElement | null
  if (!el) return
  // Spec 7.2: <= 1 line (~32px) keeps auto-following; > 3 lines (~96px) shows "跳至最新".
  if (el.scrollTop <= 32) {
    userScrolledAway.value = false
    showJumpLatest.value = false
  } else {
    userScrolledAway.value = true
    if (el.scrollTop > 96) showJumpLatest.value = true
  }
}

function jumpToLatest() {
  userScrolledAway.value = false
  showJumpLatest.value = false
  if (logListRef.value) logListRef.value.scrollTop = 0
  const stage = globalThis.document?.getElementById('main')
  if (stage) stage.scrollTop = 0
}

function sourceLabel(entry: LogEntry): string {
  if (entry.source === 'master') return 'Master'
  if (!entry.node_id) return entry.source || '节点'
  const role = desk.nodes.find(n => n.id === entry.node_id)?.role
  return `${role === 'server' ? 'Server' : role === 'client' ? 'Client' : '节点'} · ${nodeName(desk.nodes, entry.node_id)}`
}
async function fetchLogs(options?: { silent?: boolean }) {
  const ticket = ++request
  error.value = ''
  if (!options?.silent) loading.value = true
  try {
    const params = new URLSearchParams()
    if (source.value !== 'all') params.set('source', source.value)
    if (source.value === 'node' && nodeId.value) params.set('node_id', nodeId.value)
    if (level.value) params.set('level', level.value)
    params.set('limit', '500')
    const result = await api<LogEntry[]>(`/logs?${params.toString()}`)
    if (ticket === request && active) {
      logs.value = result || []
      if (!userScrolledAway.value && logListRef.value) {
        logListRef.value.scrollTop = 0
        const stage = globalThis.document?.getElementById('main')
        if (stage) stage.scrollTop = 0
      }
    }
  } catch (reason) {
    if (ticket === request && active) error.value = reason instanceof Error ? reason.message : '加载失败'
  } finally {
    if (ticket === request && !options?.silent) loading.value = false
  }
}
async function refreshFromPage() {
  await fetchLogs()
  if (!active || source.value === 'master') return
  const ids = (source.value === 'node' && nodeId.value ? desk.nodes.filter(node => node.id === nodeId.value) : desk.nodes).filter(node => !node.revoked).map(node => node.id)
  const baseline = new Map(ids.map(id => [id, nodeBaseline(desk.nodes.find(node => node.id === id)!)]))
  const connected = await askNodes(ids)
  const waiting = () => active && connected.some(id => !nodeChanged(desk.nodes.find(node => node.id === id), baseline.get(id)!))
  await waitForReports(async () => {
    if (!active) return
    await Promise.all(connected.map(id => desk.reloadNodes(id).catch(() => undefined)))
    if (active) await fetchLogs({ silent: true })
  }, waiting)
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

onMounted(() => {
  try {
    const savedSource = globalThis.sessionStorage?.getItem('veilink_logs_source') || globalThis.localStorage?.getItem('veilink_logs_source')
    if (savedSource === 'all' || savedSource === 'master' || savedSource === 'node') source.value = savedSource
    const savedLevel = globalThis.sessionStorage?.getItem('veilink_logs_level') ?? globalThis.localStorage?.getItem('veilink_logs_level')
    if (savedLevel === '' || savedLevel === 'INFO' || savedLevel === 'WARN' || savedLevel === 'ERROR') level.value = savedLevel
  } catch { /* ignore */ }
  const stage = globalThis.document?.getElementById('main')
  stage?.addEventListener('scroll', onLogScroll, { passive: true })
  const bus = (globalThis as Record<string, unknown>).__veilinkStream as { on?: (type: string, fn: () => void) => () => void } | undefined
  offStreamLog = bus?.on?.('log', () => { if (active && !loading.value) void fetchLogs({ silent: true }) })
  void fetchLogs()
  unregisterPageRefresh = registerPageRefresh(refreshFromPage)
})
onUnmounted(() => {
  active = false
  const stage = globalThis.document?.getElementById('main')
  stage?.removeEventListener('scroll', onLogScroll)
  offStreamLog?.()
  unregisterPageRefresh?.()
  if (timer) clearInterval(timer)
})
</script>

<template>
  <div class="stack">
    <div class="log-controls">
      <div class="chips" role="group" aria-label="来源">
        <button type="button" :aria-pressed="source === 'all'" @click="setSource('all')">全部</button>
        <button type="button" :aria-pressed="source === 'master'" @click="setSource('master')">管理中心</button>
        <button type="button" :aria-pressed="source === 'node'" @click="setSource('node')">节点</button>
      </div>
      <select v-if="source === 'node'" v-model="nodeId" aria-label="节点" @change="fetchLogs()">
        <option value="">全部节点</option>
        <option v-for="n in sortedNodes" :key="n.id" :value="n.id">{{ n.name }}</option>
      </select>
      <div class="chips" role="group" aria-label="级别">
        <button type="button" :aria-pressed="level === ''" @click="setLevel('')">全部</button>
        <button type="button" :aria-pressed="level === 'INFO'" @click="setLevel('INFO')">INFO</button>
        <button type="button" :aria-pressed="level === 'WARN'" @click="setLevel('WARN')">WARN</button>
        <button type="button" :aria-pressed="level === 'ERROR'" @click="setLevel('ERROR')">ERROR</button>
      </div>
      <input v-model="query" type="search" class="log-search" aria-label="搜索日志" placeholder="搜索日志消息或节点" />
       <button type="button" class="btn small fit" :class="{ primary: autoRefresh }" @click="toggleAutoRefresh"><span class="fit-sizer" aria-hidden="true">停止自动刷新</span><span class="fit-sizer" aria-hidden="true">自动刷新</span><span class="fit-value">{{ autoRefresh ? '停止自动刷新' : '自动刷新' }}</span></button>
       <button type="button" class="btn small fit" :disabled="loading" @click="fetchLogs()"><span class="fit-sizer" aria-hidden="true">刷新中…</span><span class="fit-sizer" aria-hidden="true">刷新</span><span class="fit-value">{{ loading ? '刷新中…' : '刷新' }}</span></button>
    </div>

    <p v-if="error" class="error" role="alert">{{ error }}</p>
    <EmptyState v-if="loading && !logs.length" title="加载中…" text="" />
    <EmptyState v-else-if="!filteredLogs.length" title="暂无近期日志" :text="query.trim() ? '没有匹配的日志条目，请调整筛选条件。' : '节点日志需成功连接 Master 后才会上报；日志仅保存在当前 Master 内存中，重启后不保留。'" />
    <section v-else class="panel log-panel">
      <header class="panel-head"><h2>最近日志</h2><small>显示 {{ filteredLogs.length }} / {{ logs.length }} 条 · 内存记录</small></header>
      <ul ref="logListRef" class="log-list log-scroll-viewport" @scroll="onLogScroll">
        <li v-for="(entry, index) in filteredLogs" :key="`${entry.at}-${index}`" class="log-entry log-stream-item">
          <time :datetime="entry.at ? new Date(entry.at * 1000).toISOString() : undefined">{{ entry.at ? formatTime(entry.at * 1000) : '时间未知' }}</time>
          <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
            <Badge :text="entry.level || 'INFO'" :tone="logLevelTone(entry.level)" />
            <Badge v-if="entry.source" :text="sourceLabel(entry)" />
          </div>
          <span class="log-msg">{{ entry.message }}</span>
        </li>
      </ul>
      <button v-if="showJumpLatest" type="button" class="btn small primary jump-latest-btn" @click="jumpToLatest">↑ 跳至最新</button>
    </section>
  </div>
</template>
