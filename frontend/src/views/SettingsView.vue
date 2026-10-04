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

// ---- 服务配置 ----
const service = ref({
  listen_addr: '',
  scheme: 'http',
  cert_file: '',
  key_file: '',
  web_mode: 'pull',
})
const savingService = ref(false)
const serviceMsg = ref('')
const serviceBad = ref(false)

async function loadService() {
  try {
    const cfg = await api<typeof service.value>('/master/config')
    service.value = { ...service.value, ...cfg }
  } catch { /* 忽略，保持默认值 */ }
}

async function saveService() {
  savingService.value = true
  serviceMsg.value = ''
  serviceBad.value = false
  try {
    const res = await api<{ ok: boolean; need_restart: string[] }>('/master/config', 'POST', service.value)
    const need = res.need_restart || []
    serviceMsg.value = need.length ? `已保存，${need.length} 项需重启生效` : '已保存并生效'
  } catch (e) {
    serviceBad.value = true
    serviceMsg.value = e instanceof ApiError ? e.message : '保存失败'
  } finally {
    savingService.value = false
  }
}

// ---- API Key ----
interface ApiKey {
  id: number
  name: string
  role: string
  prefix: string
  created_at: string
}
const keys = ref<ApiKey[]>([])
const showKeyForm = ref(false)
const newKey = ref({ name: '', role: 'admin' })
const creatingKey = ref(false)
const createdKeyPlain = ref('')
const keyMsg = ref('')
const keyBad = ref(false)
const currentKeyId = ref(-1)

async function loadKeys() {
  try {
    keys.value = await api<ApiKey[]>('/keys')
  } catch { keys.value = [] }
}

async function createKey() {
  creatingKey.value = true
  keyMsg.value = ''
  keyBad.value = false
  createdKeyPlain.value = ''
  try {
    const res = await api<{ key: string; name: string }>('/keys', 'POST', {
      name: newKey.value.name.trim(),
      role: newKey.value.role,
    })
    createdKeyPlain.value = res.key
    newKey.value.name = ''
    showKeyForm.value = false
    await loadKeys()
  } catch (e) {
    keyBad.value = true
    keyMsg.value = e instanceof ApiError ? e.message : '创建失败'
  } finally {
    creatingKey.value = false
  }
}

async function revokeKey(k: ApiKey) {
  if (!confirm(`确定撤销 Key「${k.name}」？撤销后立即失效。`)) return
  keyMsg.value = ''
  keyBad.value = false
  try {
    await api<{ ok: boolean }>(`/keys/${k.id}`, 'DELETE')
    await loadKeys()
  } catch (e) {
    keyBad.value = true
    keyMsg.value = e instanceof ApiError ? e.message : '撤销失败'
  }
}

function copyKey() {
  navigator.clipboard?.writeText(createdKeyPlain.value)
  keyMsg.value = '已复制到剪贴板'
  keyBad.value = false
}

onMounted(() => {
  load()
  loadService()
  loadKeys()
})
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
        <button
          v-for="p in builtinPresets"
          :key="p.value"
          type="button"
          class="chip"
          :title="p.desc"
          @click="addMirror(p.value)"
        ><span class="chip-plus" aria-hidden="true">+</span>{{ p.label }}</button>
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

    <section class="panel">
      <header class="panel-head">
        <div>
          <h2>服务配置</h2>
          <p class="muted">监听地址、协议与证书。修改后<span class="tag warn">需重启</span>生效。</p>
        </div>
        <button type="button" class="btn" :disabled="savingService" @click="saveService">
          {{ savingService ? '保存中…' : '保存' }}
        </button>
      </header>
      <div class="form-grid">
        <label class="field">
          <span>监听地址</span>
          <input v-model="service.listen_addr" type="text" placeholder=":8080 或 127.0.0.1:8080" />
        </label>
        <label class="field">
          <span>协议</span>
          <select v-model="service.scheme">
            <option value="http">http</option>
            <option value="https">https</option>
          </select>
        </label>
        <label v-if="service.scheme === 'https'" class="field">
          <span>证书文件</span>
          <input v-model="service.cert_file" type="text" placeholder="/path/to/cert.pem" />
        </label>
        <label v-if="service.scheme === 'https'" class="field">
          <span>私钥文件</span>
          <input v-model="service.key_file" type="text" placeholder="/path/to/key.pem" />
        </label>
        <label class="field">
          <span>Web 模式</span>
          <select v-model="service.web_mode">
            <option value="pull">pull（拉取托管前端）</option>
            <option value="off">off（纯 API 模式）</option>
          </select>
        </label>
      </div>
      <p v-if="serviceMsg" class="hint" :class="{ bad: serviceBad }">{{ serviceMsg }}</p>
    </section>

    <section class="panel">
      <header class="panel-head">
        <div>
          <h2>API Key</h2>
          <p class="muted">管理访问密钥。明文只在创建时显示一次，请妥善保存。</p>
        </div>
        <button type="button" class="btn primary" @click="showKeyForm = !showKeyForm">
          {{ showKeyForm ? '取消' : '新建 Key' }}
        </button>
      </header>
      <div v-if="showKeyForm" class="form-grid key-form">
        <label class="field">
          <span>名称</span>
          <input v-model="newKey.name" type="text" placeholder="留空自动生成" />
        </label>
        <label class="field">
          <span>角色</span>
          <select v-model="newKey.role">
            <option value="admin">admin（完全控制）</option>
            <option value="readonly">readonly（只读）</option>
          </select>
        </label>
        <div class="field">
          <span>&nbsp;</span>
          <button type="button" class="btn primary" :disabled="creatingKey" @click="createKey">
            {{ creatingKey ? '创建中…' : '创建' }}
          </button>
        </div>
      </div>
      <div v-if="createdKeyPlain" class="new-key">
        <p class="hint good">创建成功，明文只显示一次：</p>
        <code class="key-plain">{{ createdKeyPlain }}</code>
        <button type="button" class="btn small" @click="copyKey">复制</button>
      </div>
      <ul v-if="keys.length" class="key-list">
        <li v-for="k in keys" :key="k.id" class="key-item">
          <div class="key-meta">
            <strong>{{ k.name }}</strong>
            <span class="tag" :class="k.role === 'admin' ? 'admin' : 'ro'">{{ k.role }}</span>
            <span class="muted mono">{{ k.prefix }}…</span>
          </div>
          <div class="key-sub muted">{{ k.created_at }}</div>
          <button
            type="button"
            class="btn danger small"
            :disabled="k.id === currentKeyId"
            :title="k.id === currentKeyId ? '当前使用的 Key 不能删除' : '撤销'"
            @click="revokeKey(k)"
          >撤销</button>
        </li>
      </ul>
      <p v-else class="muted">暂无 Key。</p>
      <p v-if="keyMsg" class="hint" :class="{ bad: keyBad }">{{ keyMsg }}</p>
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
  display: inline-flex; align-items: center; gap: 6px;
  border: 1px dashed var(--line-strong);
  background: transparent;
  border-radius: 20px;
  padding: 5px 12px 5px 8px;
  font-size: 12px;
  color: var(--muted);
  cursor: pointer;
  transition: all 140ms ease;
}
.chip:hover { border-color: var(--accent); color: var(--accent-strong); border-style: solid; }
.chip-plus {
  display: inline-grid; place-items: center;
  width: 16px; height: 16px;
  border-radius: 50%;
  background: var(--accent-soft);
  color: var(--accent-strong);
  font-size: 12px; line-height: 1; font-weight: 700;
}

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

.form-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
  gap: 12px;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 13px;
}
.field > span:first-child {
  color: var(--muted);
  font-size: 12px;
}
.field input[type="text"],
.field input[type="number"],
.field select {
  background: var(--input-bg);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 9px 12px;
  color: var(--text);
  font-size: 13px;
}
.field input:disabled {
  opacity: 0.45;
  cursor: not-allowed;
}
.field.check {
  flex-direction: row;
  align-items: center;
  gap: 8px;
}
.field.check input {
  width: 16px;
  height: 16px;
}
.tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 10px;
  font-size: 11px;
  font-weight: 600;
}
.tag.warn {
  background: rgba(245, 158, 11, 0.15);
  color: #f59e0b;
}
.tag.admin {
  background: rgba(239, 68, 68, 0.12);
  color: #ef4444;
}
.tag.ro {
  background: rgba(59, 130, 246, 0.12);
  color: #3b82f6;
}
.mono { font-family: ui-monospace, monospace; font-size: 12px; }
.key-form { margin-bottom: 12px; }
.key-list {
  list-style: none;
  margin: 12px 0 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.key-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  background: var(--surface-soft);
  border: 1px solid var(--line);
  border-radius: 10px;
  padding: 10px 14px;
}
.key-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.key-sub {
  font-size: 12px;
  margin-top: 2px;
}
.new-key {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  background: rgba(34, 197, 94, 0.08);
  border: 1px solid rgba(34, 197, 94, 0.3);
  border-radius: 10px;
  padding: 10px 14px;
  margin-top: 12px;
}
.key-plain {
  font-family: ui-monospace, monospace;
  font-size: 13px;
  background: var(--input-bg);
  padding: 6px 10px;
  border-radius: 6px;
  word-break: break-all;
}
.btn.danger {
  border-color: rgba(239, 68, 68, 0.4);
  color: #ef4444;
}
.btn.danger:hover:not(:disabled) {
  background: rgba(239, 68, 68, 0.1);
}
.btn.small { padding: 5px 10px; font-size: 12px; }
.hint.good { color: #22c55e; }
</style>
