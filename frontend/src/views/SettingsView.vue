<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, ApiError } from '../api'
import EmptyState from '../components/EmptyState.vue'

interface WebStatus {
  mode: string
  want_version: string
  active_version: string
  mirrors: string[]
  frontend_url: string
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

const builtinPresets = [
  { label: 'ghfast.top', value: 'https://ghfast.top', desc: '国内加速' },
  { label: 'ghproxy.com', value: 'https://ghproxy.com/https://github.com', desc: '代理加速' },
  { label: 'mirror.ghproxy.com', value: 'https://mirror.ghproxy.com', desc: '备用镜像' },
]

const status = ref<WebStatus | null>(null)
const loading = ref(true)
const loadError = ref('')

// 镜像列表管理
const mirrors = ref<string[]>([])
const newMirror = ref('')
const mirrorError = ref('')
const savingMirrors = ref(false)

// 前端地址（CPA）
const frontendUrl = ref('')
const savingUrl = ref(false)
const urlMsg = ref('')
const urlBad = ref(false)

// 探测
const probing = ref(false)
const probes = ref<ProbeResult[] | null>(null)

// 版本更新
const updating = ref(false)
const updateVersion = ref('')
const updateMsg = ref('')
const updateBad = ref(false)

const hasChanges = computed(() => {
  if (!status.value) return false
  const a = [...mirrors.value].sort()
  const b = [...(status.value.mirrors || [])].sort()
  return a.length !== b.length || a.some((v, i) => v !== b[i])
})

function normalizeUrl(v: string): string {
  v = v.trim()
  if (!v) return ''
  if (!/^https?:\/\//i.test(v)) v = 'https://' + v
  return v.replace(/\/+$/, '')
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    status.value = await api<WebStatus>('/web/config')
    mirrors.value = [...(status.value.mirrors || [])]
    frontendUrl.value = status.value.frontend_url || ''
  } catch (e) {
    loadError.value = e instanceof ApiError ? e.message : '加载失败'
  } finally {
    loading.value = false
  }
}

function addMirror(preset?: string) {
  mirrorError.value = ''
  const v = normalizeUrl(preset ?? newMirror.value)
  if (!v) {
    mirrorError.value = '请输入有效的加速地址'
    return
  }
  if (mirrors.value.some(m => m.toLowerCase().replace(/\/+$/, '') === v.toLowerCase())) {
    mirrorError.value = '该地址已在列表中'
    return
  }
  mirrors.value.push(v)
  newMirror.value = ''
}

function removeMirror(index: number) {
  mirrors.value.splice(index, 1)
  mirrorError.value = ''
}

function moveMirror(index: number, dir: -1 | 1) {
  const j = index + dir
  if (j < 0 || j >= mirrors.value.length) return
  const tmp = mirrors.value[index]
  mirrors.value[index] = mirrors.value[j]
  mirrors.value[j] = tmp
}

async function saveMirrors() {
  savingMirrors.value = true
  mirrorError.value = ''
  try {
    status.value = await api<WebStatus>('/web/config', 'POST', { mirrors: mirrors.value })
    mirrors.value = [...(status.value.mirrors || [])]
  } catch (e) {
    mirrorError.value = e instanceof ApiError ? e.message : '保存失败'
  } finally {
    savingMirrors.value = false
  }
}

async function saveFrontendUrl() {
  savingUrl.value = true
  urlMsg.value = ''
  urlBad.value = false
  try {
    const v = frontendUrl.value.trim() ? normalizeUrl(frontendUrl.value) : ''
    status.value = await api<WebStatus>('/web/config', 'POST', { frontend_url: v })
    frontendUrl.value = status.value.frontend_url || ''
    urlMsg.value = v ? '已保存，访问 / 将跳转到该地址' : '已清空，恢复内置前端'
  } catch (e) {
    urlBad.value = true
    urlMsg.value = e instanceof ApiError ? e.message : '保存失败'
  } finally {
    savingUrl.value = false
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
  updateMsg.value = ''
  updateBad.value = false
  try {
    await api<{ ok: boolean }>('/web/update', 'POST', { version: updateVersion.value.trim() })
    updateMsg.value = '前端更新成功，已切换到新版本'
    await load()
  } catch (e) {
    updateBad.value = true
    updateMsg.value = e instanceof ApiError ? e.message : '更新失败'
  } finally {
    updating.value = false
  }
}

onMounted(load)
</script>

<template>
  <EmptyState v-if="loading" title="加载中…" text="" />
  <EmptyState v-else-if="loadError" title="加载失败" :text="loadError" />
  <div v-else-if="status" class="settings">
    <!-- 状态概览 -->
    <section class="hero" aria-label="前端状态">
      <div class="hero-main">
        <p class="kicker">Frontend</p>
        <h1>前端设置</h1>
        <p class="lead">管理控制台前端的托管方式、下载加速与版本更新。</p>
      </div>
      <dl class="hero-stats">
        <div class="stat">
          <dt>托管模式</dt>
          <dd><code>{{ status.mode }}</code></dd>
        </div>
        <div class="stat">
          <dt>运行版本</dt>
          <dd><code>{{ status.active_version || '—' }}</code></dd>
        </div>
        <div class="stat">
          <dt>加速地址</dt>
          <dd><strong>{{ mirrors.length }}</strong> 个</dd>
        </div>
        <div class="stat">
          <dt>服务状态</dt>
          <dd>
            <span class="dot" :class="{ on: status.serving }" aria-hidden="true"></span>
            {{ status.serving ? '服务中' : '未托管' }}
          </dd>
        </div>
      </dl>
    </section>

    <!-- 前端地址（CPA） -->
    <section class="panel">
      <header class="panel-head">
        <div>
          <h2>前端地址</h2>
          <p class="muted">CPA 式分离部署：设置后访问 <code>/</code> 将跳转到该地址，适用于前端部署在 CDN 或独立域名。</p>
        </div>
      </header>
      <div class="url-row">
        <input
          v-model="frontendUrl"
          type="url"
          placeholder="https://veilink.example.com（留空使用内置前端）"
          aria-label="自定义前端地址"
        />
        <button type="button" class="btn primary" :disabled="savingUrl" @click="saveFrontendUrl">
          {{ savingUrl ? '保存中…' : '保存' }}
        </button>
      </div>
      <p v-if="urlMsg" class="hint" :class="{ bad: urlBad }">{{ urlMsg }}</p>
      <p v-else-if="status.prebundled" class="hint">当前为统一镜像预置版本，无需下载。</p>
    </section>

    <!-- 下载加速 -->
    <section class="panel">
      <header class="panel-head">
        <div>
          <h2>下载加速</h2>
          <p class="muted">按列表顺序尝试拉取，失败自动切换到下一个，最后尝试内置公共镜像。</p>
        </div>
        <button
          type="button"
          class="btn primary"
          :disabled="savingMirrors || !hasChanges"
          @click="saveMirrors"
        >
          {{ savingMirrors ? '保存中…' : hasChanges ? '保存更改' : '已保存' }}
        </button>
      </header>

      <!-- 已添加列表 -->
      <ul v-if="mirrors.length" class="mirror-list">
        <li v-for="(m, i) in mirrors" :key="m" class="mirror-item">
          <span class="mirror-order" aria-hidden="true">{{ i + 1 }}</span>
          <code class="mirror-url">{{ m }}</code>
          <div class="mirror-actions">
            <button type="button" class="icon-btn sm" :disabled="i === 0" @click="moveMirror(i, -1)" aria-label="上移" title="上移">↑</button>
            <button type="button" class="icon-btn sm" :disabled="i === mirrors.length - 1" @click="moveMirror(i, 1)" aria-label="下移" title="下移">↓</button>
            <button type="button" class="icon-btn sm danger" @click="removeMirror(i)" aria-label="删除" title="删除">×</button>
          </div>
        </li>
      </ul>
      <p v-else class="hint">未配置加速地址，将直连 GitHub（失败时仍会尝试内置镜像）。</p>

      <!-- 添加 -->
      <div class="add-row">
        <input
          v-model="newMirror"
          type="url"
          placeholder="https://ghfast.top"
          aria-label="新增加速地址"
          @keyup.enter="addMirror()"
        />
        <button type="button" class="btn" @click="addMirror()">添加</button>
      </div>
      <div class="presets">
        <span class="muted">快速添加：</span>
        <button
          v-for="p in builtinPresets"
          :key="p.value"
          type="button"
          class="chip"
          :title="p.desc"
          @click="addMirror(p.value)"
        >{{ p.label }}</button>
      </div>
      <p v-if="mirrorError" class="hint bad">{{ mirrorError }}</p>

      <!-- 探测 -->
      <div class="probe-actions">
        <button type="button" class="btn" :disabled="probing" @click="probe">
          {{ probing ? '检测中…' : '检测连通性' }}
        </button>
      </div>
      <ul v-if="probes && probes.length" class="probe-list">
        <li v-for="r in probes" :key="r.url" :class="{ ok: r.ok }">
          <span class="probe-dot" aria-hidden="true"></span>
          <code>{{ r.url }}</code>
          <small>{{ r.ok ? `${r.status} · ${r.elapsed_ms}ms` : (r.error || '失败') }}</small>
        </li>
      </ul>
      <p v-else-if="probes && !probes.length" class="hint bad">检测失败，请检查网络。</p>
    </section>

    <!-- 版本更新 -->
    <section class="panel">
      <header class="panel-head">
        <div>
          <h2>版本更新</h2>
          <p class="muted">留空拉取最新版，或指定 <code>web-v1.2.0</code> 这样的版本号。</p>
        </div>
      </header>
      <div class="url-row">
        <input
          v-model="updateVersion"
          type="text"
          placeholder="web-v1.2.0（留空拉取最新）"
          aria-label="前端版本"
        />
        <button type="button" class="btn primary" :disabled="updating" @click="update">
          {{ updating ? '更新中…' : '拉取更新' }}
        </button>
      </div>
      <p v-if="updateMsg" class="hint" :class="{ bad: updateBad }">{{ updateMsg }}</p>
    </section>
  </div>
</template>

<style scoped>
.settings { display: grid; gap: 20px; max-width: 860px; }
.hero {
  background: linear-gradient(135deg, var(--surface-raised), var(--surface));
  border: 1px solid var(--line);
  border-radius: 14px;
  padding: 24px;
}
.hero-main h1 { margin: 4px 0 8px; }
.hero-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin: 20px 0 0;
  padding: 0;
}
.stat {
  background: rgba(0, 0, 0, 0.2);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 12px 14px;
  margin: 0;
}
.stat dt { font-size: 11px; color: var(--faint); text-transform: uppercase; letter-spacing: 0.08em; }
.stat dd { margin: 6px 0 0; font-size: 15px; display: flex; align-items: center; gap: 8px; }
.stat code { font-size: 13px; }
.dot { width: 8px; height: 8px; border-radius: 50%; background: var(--faint); flex: none; }
.dot.on { background: var(--good); box-shadow: 0 0 8px var(--good); }

.panel-head > div { flex: 1; }
.panel-head h2 { margin-bottom: 4px; }
.panel-head .muted { margin: 0; font-size: 12px; }

.url-row { display: flex; gap: 10px; margin-top: 12px; }
.url-row input { flex: 1; }
.hint { margin: 10px 0 0; font-size: 12px; color: var(--muted); }
.hint.bad { color: var(--danger); }

.mirror-list { list-style: none; margin: 12px 0 0; padding: 0; display: grid; gap: 8px; }
.mirror-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 12px;
  background: var(--surface-raised);
  border: 1px solid var(--line);
  border-radius: 10px;
  transition: border-color 140ms ease;
}
.mirror-item:hover { border-color: var(--line-strong); }
.mirror-order {
  flex: none;
  width: 24px; height: 24px;
  display: grid; place-items: center;
  background: var(--accent-soft);
  color: var(--accent-strong);
  border-radius: 6px;
  font-size: 12px; font-weight: 700;
}
.mirror-url { flex: 1; font-size: 13px; overflow: hidden; text-overflow: ellipsis; }
.mirror-actions { display: flex; gap: 2px; flex: none; }
.icon-btn.sm { font-size: 14px; padding: 4px 8px; border-radius: 6px; }
.icon-btn.sm:hover { background: var(--surface-hover); }
.icon-btn.sm.danger { color: var(--muted); }
.icon-btn.sm.danger:hover { color: var(--danger); background: rgba(228, 135, 135, 0.1); }
.icon-btn.sm:disabled { opacity: 0.3; }

.add-row { display: flex; gap: 10px; margin-top: 12px; }
.add-row input { flex: 1; }
.presets { display: flex; align-items: center; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
.chip {
  border: 1px solid var(--line);
  background: var(--surface-soft);
  border-radius: 20px;
  padding: 5px 12px;
  font-size: 12px;
  cursor: pointer;
  transition: all 140ms ease;
}
.chip:hover { border-color: var(--accent); color: var(--accent-strong); }

.probe-actions { margin-top: 16px; }
.probe-list { list-style: none; margin: 12px 0 0; padding: 0; display: grid; gap: 8px; }
.probe-list li {
  display: flex; align-items: center; gap: 10px;
  padding: 9px 12px;
  background: var(--surface-raised);
  border: 1px solid var(--line);
  border-radius: 8px;
  font-size: 12px;
}
.probe-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--danger); flex: none; }
.probe-list li.ok .probe-dot { background: var(--good); box-shadow: 0 0 6px var(--good); }
.probe-list code { flex: 1; overflow: hidden; text-overflow: ellipsis; color: var(--muted); }
.probe-list small { color: var(--faint); flex: none; }
.probe-list li.ok small { color: var(--good); }

@media (max-width: 640px) {
  .hero-stats { grid-template-columns: repeat(2, 1fr); }
  .url-row, .add-row { flex-direction: column; }
  .mirror-actions .icon-btn.sm { padding: 6px 10px; }
}
</style>
