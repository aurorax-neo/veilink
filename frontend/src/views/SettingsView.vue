<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError } from '../api'

interface WebStatus {
  mode: string
  want_version: string
  active_version: string
  mirror: string
  repo: string
  serving: boolean
  prebundled: boolean
}

interface ProbeResult {
  url: string
  ok: boolean
  status?: number
  elapsed_ms: number
  error?: string
}

const presets = [
  { label: '直连', value: '' },
  { label: 'ghfast.top', value: 'https://ghfast.top' },
  { label: 'ghproxy.com', value: 'https://ghproxy.com/https://github.com' },
]

const status = ref<WebStatus | null>(null)
const loading = ref(true)
const loadError = ref('')
const mirror = ref('')
const saving = ref(false)
const saveMsg = ref('')
const saveBad = ref(false)
const probing = ref(false)
const probes = ref<ProbeResult[] | null>(null)
const updating = ref(false)
const updateVersion = ref('')

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    status.value = await api<WebStatus>('/web/config')
    mirror.value = status.value.mirror
  } catch (e) {
    loadError.value = e instanceof ApiError ? e.message : '加载失败'
  } finally {
    loading.value = false
  }
}

async function save() {
  saving.value = true
  saveMsg.value = ''
  saveBad.value = false
  try {
    status.value = await api<WebStatus>('/web/config', 'POST', { mirror: mirror.value.trim() })
    mirror.value = status.value.mirror
    saveMsg.value = '已保存。拉取失败时会自动尝试内置加速地址。'
  } catch (e) {
    saveBad.value = true
    saveMsg.value = e instanceof ApiError ? e.message : '保存失败'
  } finally {
    saving.value = false
  }
}

async function probe() {
  probing.value = true
  probes.value = null
  try {
    const r = await api<{ results: ProbeResult[] }>('/web/probe', 'POST', {})
    probes.value = r.results
  } catch {
    probes.value = []
  } finally {
    probing.value = false
  }
}

async function update() {
  updating.value = true
  saveMsg.value = ''
  saveBad.value = false
  try {
    await api<{ ok: boolean }>('/web/update', 'POST', { version: updateVersion.value.trim() })
    saveMsg.value = '前端更新成功，已切换到新版本。'
    await load()
  } catch (e) {
    saveBad.value = true
    saveMsg.value = e instanceof ApiError ? e.message : '更新失败'
  } finally {
    updating.value = false
  }
}

onMounted(load)
</script>

<template>
  <div v-if="loading" class="stack"><p class="muted">加载中…</p></div>
  <div v-else-if="loadError" class="stack"><p class="bad">{{ loadError }}</p></div>
  <div v-else-if="status" class="stack">
    <section class="panel">
      <header class="panel-head"><h2>前端状态</h2></header>
      <dl class="kv">
        <div><dt>托管模式</dt><dd>{{ status.mode }}</dd></div>
        <div><dt>运行版本</dt><dd>{{ status.active_version || '—' }}</dd></div>
        <div><dt>目标版本</dt><dd>{{ status.want_version || 'latest' }}</dd></div>
        <div><dt>服务中</dt><dd>{{ status.serving ? '是' : '否' }}</dd></div>
        <div v-if="status.prebundled"><dt>预置版本</dt><dd>是（统一镜像内置，无需下载）</dd></div>
      </dl>
    </section>

    <section class="panel">
      <header class="panel-head"><h2>下载加速</h2></header>
      <p class="muted">拉取前端时按顺序尝试：配置的地址 → 直连 GitHub → 内置加速地址（ghfast.top 等）。GitHub 不通时自动切换，无需手动干预。</p>
      <div class="toolbar">
        <div class="seg" role="group" aria-label="加速预设">
          <button
            v-for="p in presets"
            :key="p.label"
            type="button"
            class="chip"
            :class="{ on: mirror === p.value }"
            @click="mirror = p.value"
          >{{ p.label }}</button>
        </div>
      </div>
      <div class="toolbar">
        <input v-model="mirror" type="url" aria-label="加速地址" placeholder="https://ghfast.top（留空 = 直连）" />
        <button type="button" class="btn primary" :disabled="saving" @click="save">
          {{ saving ? '保存中…' : '保存' }}
        </button>
        <button type="button" class="btn" :disabled="probing" @click="probe">
          {{ probing ? '检测中…' : '检测连通性' }}
        </button>
      </div>
      <p v-if="saveMsg" class="muted" :class="{ bad: saveBad }">{{ saveMsg }}</p>
      <ul v-if="probes && probes.length" class="probe-list">
        <li v-for="r in probes" :key="r.url" :class="{ ok: r.ok, bad: !r.ok }">
          <span class="probe-dot" aria-hidden="true">{{ r.ok ? '●' : '○' }}</span>
          <code>{{ r.url }}</code>
          <small>{{ r.ok ? `${r.status} · ${r.elapsed_ms}ms` : (r.error || '失败') }}</small>
        </li>
      </ul>
      <p v-else-if="probes && !probes.length" class="muted bad">检测失败，请检查网络。</p>
    </section>

    <section class="panel">
      <header class="panel-head"><h2>版本更新</h2></header>
      <p class="muted">留空 = 最新版（latest），或指定 web-v1.2.0 这样的版本号。</p>
      <div class="toolbar">
        <input v-model="updateVersion" type="text" aria-label="前端版本" placeholder="web-v1.2.0（留空拉取最新）" />
        <button type="button" class="btn primary" :disabled="updating" @click="update">
          {{ updating ? '更新中…' : '拉取更新' }}
        </button>
      </div>
    </section>
  </div>
</template>

<style scoped>
.kv { display: grid; gap: 0.5rem; margin: 0; }
.kv > div { display: flex; gap: 1rem; }
.kv dt { color: var(--muted); min-width: 5rem; }
.kv dd { margin: 0; }
.seg { display: flex; gap: 0.5rem; flex-wrap: wrap; }
.chip.on { border-color: var(--accent); color: var(--accent); }
.probe-list { list-style: none; margin: 0.75rem 0 0; padding: 0; display: grid; gap: 0.5rem; }
.probe-list li { display: flex; align-items: center; gap: 0.75rem; padding: 0.5rem 0.75rem; border: 1px solid var(--border); border-radius: 0.5rem; }
.probe-list li.ok .probe-dot { color: var(--ok, #4ade80); }
.probe-list li.bad .probe-dot { color: var(--bad, #f87171); }
.probe-list code { flex: 1; overflow: hidden; text-overflow: ellipsis; }
.probe-list small { color: var(--muted); }
.muted.bad, .bad { color: var(--bad, #f87171); }
</style>
