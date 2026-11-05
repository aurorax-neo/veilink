<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted, ref, watch } from 'vue'
import { deskKey, navigateKey } from '../desk'
import { actionLabel, actionTone, copyText, formatTime } from '../format'
import type { Audit, PageId } from '../types'
import Badge from '../components/Badge.vue'
import EmptyState from '../components/EmptyState.vue'

const desk = inject(deskKey)!
const navigate = inject(navigateKey, () => {})
const PAGE_STEP = 100
const query = ref('')
const category = ref<'all' | 'node' | 'mapping'>('all')
const visibleLimit = ref(PAGE_STEP)
const now = ref(Date.now())
const copiedKey = ref('')
let timer: ReturnType<typeof setInterval> | undefined

try {
  const saved = globalThis.sessionStorage?.getItem('veilink_audit_category') || globalThis.localStorage?.getItem('veilink_audit_category')
  if (saved === 'all' || saved === 'node' || saved === 'mapping') category.value = saved
} catch { /* ignore */ }

function setCategory(next: 'all' | 'node' | 'mapping') {
  category.value = next
  visibleLimit.value = PAGE_STEP
  try {
    globalThis.sessionStorage?.setItem('veilink_audit_category', next)
    globalThis.localStorage?.setItem('veilink_audit_category', next)
  } catch { /* ignore */ }
}

watch(query, () => {
  visibleLimit.value = PAGE_STEP
})

const counts = computed(() => {
  let node = 0
  let mapping = 0
  for (const item of desk.audit) {
    if (item.action.startsWith('node.')) node += 1
    else if (item.action.startsWith('mapping.')) mapping += 1
  }
  return { all: desk.audit.length, node, mapping }
})

function resolveTarget(item: Audit): { kind: string; name: string; page: PageId | null } {
  if (item.action.startsWith('node.')) {
    const node = desk.nodes.find((n) => n.id === item.object)
    if (node) {
      return {
        kind: node.role === 'server' ? '公网网关' : '内网节点',
        name: node.name,
        page: node.role === 'client' ? 'clients' : 'servers',
      }
    }
    return { kind: '节点', name: '', page: null }
  }
  if (item.action.startsWith('mapping.')) {
    const mapping = desk.mappings.find((m) => m.id === item.object)
    if (mapping) {
      return { kind: '端口映射', name: mapping.name, page: 'proxies' }
    }
    return { kind: '端口映射', name: '', page: null }
  }
  return { kind: '系统对象', name: '', page: null }
}

function relativeAge(unix: number, current = now.value): string {
  if (!unix) return ''
  const delta = Math.max(0, Math.round(current / 1000 - unix))
  if (delta < 60) return `${delta} 秒前`
  const minutes = Math.floor(delta / 60)
  if (minutes < 60) return `${minutes} 分钟前`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours} 小时前`
  const days = Math.floor(hours / 24)
  return `${days} 天前`
}

const rows = computed(() => {
  const q = query.value.trim().toLowerCase()
  return desk.audit.filter((item) => {
    if (category.value === 'node' && !item.action.startsWith('node.')) return false
    if (category.value === 'mapping' && !item.action.startsWith('mapping.')) return false
    if (!q) return true
    const target = resolveTarget(item)
    return [item.action, actionLabel(item.action), item.object, target.name, target.kind].join(' ').toLowerCase().includes(q)
  })
})

const visibleRows = computed(() => rows.value.slice(0, visibleLimit.value))
const remainingCount = computed(() => Math.max(0, rows.value.length - visibleRows.value.length))

async function copyObjectId(id: string, key: string) {
  try {
    await copyText(id)
    copiedKey.value = key
    globalThis.setTimeout?.(() => {
      if (copiedKey.value === key) copiedKey.value = ''
    }, 1800)
  } catch (reason) {
    desk.notify(reason instanceof Error ? reason.message : '复制失败', true)
  }
}

onMounted(() => {
  timer = globalThis.setInterval?.(() => { now.value = Date.now() }, 10000)
})
onUnmounted(() => {
  if (timer) globalThis.clearInterval?.(timer)
})
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="加载中…" text="" />
  <EmptyState v-else-if="!desk.loaded" title="加载失败" :text="desk.error" />
  <div v-else class="stack">
    <div class="toolbar">
      <div class="chips" role="group" aria-label="审计分类">
        <button type="button" :aria-pressed="category === 'all'" @click="setCategory('all')">全部 ({{ counts.all }})</button>
        <button type="button" :aria-pressed="category === 'node'" @click="setCategory('node')">节点变更 ({{ counts.node }})</button>
        <button type="button" :aria-pressed="category === 'mapping'" @click="setCategory('mapping')">映射变更 ({{ counts.mapping }})</button>
      </div>
      <input v-model="query" type="search" class="audit-search" aria-label="搜索审计" placeholder="搜索动作、名称或对象 ID" />
      <button v-if="query.trim() || category !== 'all'" type="button" class="btn small quiet" @click="query = ''; setCategory('all')">重置筛选</button>
    </div>
    <section class="panel">
      <header class="panel-head">
        <h2>审计事件</h2>
        <small class="live-number">{{ rows.length === desk.audit.length ? `共 ${rows.length} 条` : `显示 ${rows.length} / ${desk.audit.length} 条` }}</small>
      </header>
      <EmptyState v-if="!rows.length" title="暂无审计" :text="query.trim() || category !== 'all' ? '没有匹配的审计记录，请调整筛选条件。' : '节点与映射的配置变更、令牌签发与凭据重置操作会自动记录在此。'" />
      <ol v-else class="timeline">
        <li v-for="(item, index) in visibleRows" :key="`${item.at}-${item.action}-${item.object}-${index}`">
          <div class="audit-time">
            <time class="live-number" :datetime="item.at ? new Date(item.at * 1000).toISOString() : undefined">{{ formatTime(item.at * 1000) }}</time>
            <small class="audit-age live-number">{{ relativeAge(item.at, now) }}</small>
          </div>
          <div class="audit-badges">
            <Badge :text="actionLabel(item.action)" :tone="actionTone(item.action)" />
            <Badge :text="resolveTarget(item).kind" />
          </div>
          <div class="audit-target">
            <button
              v-if="resolveTarget(item).name && resolveTarget(item).page"
              type="button"
              class="text-btn audit-target-name"
              @click="navigate(resolveTarget(item).page!)"
            >
              {{ resolveTarget(item).name }}
            </button>
            <code v-if="item.object" class="audit-object-code">{{ item.object }}</code>
            <button
              v-if="item.object"
              type="button"
              class="btn small quiet fit audit-copy-btn"
              :class="{ 'copy-bounce': copiedKey === `${item.at}-${index}` }"
              @click="copyObjectId(item.object, `${item.at}-${index}`)"
            >
              <span class="fit-sizer" aria-hidden="true">✓ 已复制</span>
              <span class="fit-sizer" aria-hidden="true">复制 ID</span>
              <span class="fit-value">{{ copiedKey === `${item.at}-${index}` ? '✓ 已复制' : '复制 ID' }}</span>
            </button>
          </div>
        </li>
      </ol>
      <div v-if="remainingCount > 0" class="row end" style="padding: 12px 16px; border-top: 1px solid var(--line);">
        <button type="button" class="btn small quiet" @click="visibleLimit += PAGE_STEP">
          加载更多（剩余 {{ remainingCount }} 条）
        </button>
      </div>
    </section>
  </div>
</template>
