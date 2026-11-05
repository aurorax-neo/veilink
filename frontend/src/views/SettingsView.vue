<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError, getApiKey } from '../api'
import { formatTime } from '../format'
import EmptyState from '../components/EmptyState.vue'
import Modal from '../components/Modal.vue'

interface WebStatus { mode: string; active_version: string; serving: boolean; prebundled: boolean }
const status = ref<WebStatus | null>(null)
const loading = ref(true)
const loadError = ref('')
async function load() {
  loading.value = true
  loadError.value = ''
  try { status.value = await api<WebStatus>('/web/config') }
  catch (e) { loadError.value = e instanceof ApiError ? e.message : '加载失败' }
  finally { loading.value = false }
}
const service = ref({ listen_addr: '', scheme: 'http', cert_file: '', key_file: '' })
const savingService = ref(false)
const serviceMsg = ref('')
const serviceBad = ref(false)
const serviceLoaded = ref(false)
async function loadService() {
  try { service.value = await api<typeof service.value>('/master/config'); serviceLoaded.value = true }
  catch (e) { serviceBad.value = true; serviceMsg.value = e instanceof ApiError ? e.message : '服务配置加载失败' }
}
async function saveService() {
  savingService.value = true
  serviceMsg.value = ''
  serviceBad.value = false
  try {
    const res = await api<{ ok: boolean; need_restart: string[] }>('/master/config', 'POST', service.value)
    serviceMsg.value = res.need_restart?.length ? '已保存，需重启生效' : '已保存'
  } catch (e) { serviceBad.value = true; serviceMsg.value = e instanceof ApiError ? e.message : '保存失败' }
  finally { savingService.value = false }
}
interface ApiKey { id: number; name: string; role: string; key_prefix: string; created_at: string; last_used?: string }
const keys = ref<ApiKey[]>([])
const showKeyForm = ref(false)
const newKey = ref({ name: '', role: 'admin' })
const creatingKey = ref(false)
const createdKeyPlain = ref('')
const keyMsg = ref('')
const keyBad = ref(false)
const copiedKey = ref(false)
function isCurrentKey(k: ApiKey): boolean {
  const current = typeof getApiKey === 'function' ? getApiKey() : null
  return !!current && !!k.key_prefix && current.startsWith(k.key_prefix)
}
function adminKeyCount(): number {
  return keys.value.filter((k) => k.role === 'admin').length
}
function canRevokeKey(k: ApiKey): boolean {
  if (k.role === 'admin' && adminKeyCount() <= 1) return false
  return true
}
async function loadKeys() {
  try { keys.value = await api<ApiKey[]>('/keys') }
  catch (e) { keyBad.value = true; keyMsg.value = e instanceof ApiError ? e.message : '密钥加载失败' }
}
async function createKey() {
  creatingKey.value = true
  keyMsg.value = ''
  keyBad.value = false
  createdKeyPlain.value = ''
  try {
    const res = await api<{ key: string; name: string }>('/keys', 'POST', { name: newKey.value.name.trim(), role: newKey.value.role })
    createdKeyPlain.value = res.key
    newKey.value.name = ''
    showKeyForm.value = false
    await loadKeys()
  } catch (e) { keyBad.value = true; keyMsg.value = e instanceof ApiError ? e.message : '创建失败' }
  finally { creatingKey.value = false }
}
const pendingKey = ref<ApiKey | null>(null)
const confirmRevoke = ref<{ open: () => void } | null>(null)
function revokeKey(k: ApiKey) {
  pendingKey.value = k
  confirmRevoke.value?.open()
}
async function commitRevoke() {
  const k = pendingKey.value
  if (!k) return false
  keyMsg.value = ''
  keyBad.value = false
  try { await api(`/keys/${k.id}`, 'DELETE'); await loadKeys(); return true }
  catch (e) { keyBad.value = true; keyMsg.value = e instanceof ApiError ? e.message : '撤销失败'; return false }
}
async function copyKey() {
  try {
    if (!navigator.clipboard) throw new Error('剪贴板不可用')
    await navigator.clipboard.writeText(createdKeyPlain.value)
    keyMsg.value = '已复制到剪贴板'; keyBad.value = false
    copiedKey.value = true
    globalThis.setTimeout?.(() => { copiedKey.value = false }, 2500)
  } catch { keyBad.value = true; keyMsg.value = '复制失败' }
}
onMounted(() => { void load(); void loadService(); void loadKeys() })
</script>

<template>
  <EmptyState v-if="loading" title="加载中…" text="" />
  <EmptyState v-else-if="loadError" title="加载失败" :text="loadError" />
  <div v-else-if="status" class="settings">
    <section class="panel runtime" aria-label="运行版本">
      <header class="panel-head">
        <h2>运行状态</h2>
        <span class="tag" :class="status.serving ? 'ok' : 'admin'">{{ status.serving ? '服务正常' : '不可用' }}</span>
      </header>
      <div class="panel-body">
        <dl class="runtime-grid">
          <div><dt>运行版本</dt><dd><code class="live-number">{{ status.active_version }}</code><span class="tag ro">内置 Web</span></dd></div>
          <div><dt>监听端点</dt><dd><code class="live-number">{{ serviceLoaded && service.listen_addr ? `${service.scheme}://${service.listen_addr}` : '加载中…' }}</code></dd></div>
          <div><dt>API 密钥数</dt><dd class="live-number">{{ keys.length }} 个（管理员 {{ adminKeyCount() }} 个）</dd></div>
        </dl>
      </div>
    </section>
    <section class="panel service-section">
      <header class="panel-head"><h2>服务配置</h2><button type="button" class="btn primary" :disabled="savingService || !serviceLoaded" @click="saveService">{{ savingService ? '保存中…' : '保存配置' }}</button></header>
      <div class="panel-body">
        <div class="form-grid">
          <label class="field"><span>监听地址</span><input v-model="service.listen_addr" type="text" placeholder="127.0.0.1:2545" :disabled="!serviceLoaded" /></label>
          <div class="field">
            <span>协议</span>
            <div class="seg-pills" role="group" aria-label="服务协议">
              <button type="button" :disabled="!serviceLoaded" :aria-pressed="service.scheme === 'http'" @click="service.scheme = 'http'">HTTP</button>
              <button type="button" :disabled="!serviceLoaded" :aria-pressed="service.scheme === 'https'" @click="service.scheme = 'https'">HTTPS</button>
            </div>
            <select class="sr-only-select" v-model="service.scheme" :disabled="!serviceLoaded"><option value="http">HTTP</option><option value="https">HTTPS</option></select>
          </div>
          <label v-if="service.scheme === 'https'" class="field"><span>证书文件</span><input v-model="service.cert_file" type="text" placeholder="/data/cert.pem" /></label>
          <label v-if="service.scheme === 'https'" class="field"><span>私钥文件</span><input v-model="service.key_file" type="text" placeholder="/data/key.pem" /></label>
        </div>
        <p v-if="serviceMsg" class="hint" :class="{ bad: serviceBad }" role="status">{{ serviceMsg }}</p>
      </div>
    </section>
    <section class="panel service-section">
      <header class="panel-head">
        <div><h2>API Key</h2></div>
        <button type="button" class="btn primary" @click="showKeyForm = !showKeyForm">{{ showKeyForm ? '取消' : '新建 Key' }}</button>
      </header>
      <div class="panel-body">
        <div v-if="showKeyForm" class="form-grid key-form">
          <label class="field"><span>名称</span><input v-model="newKey.name" type="text" placeholder="留空自动生成" /></label>
          <div class="field">
            <span>角色</span>
            <div class="seg-pills" role="group" aria-label="密钥角色">
              <button type="button" :aria-pressed="newKey.role === 'admin'" @click="newKey.role = 'admin'">admin（完全控制）</button>
              <button type="button" :aria-pressed="newKey.role === 'readonly'" @click="newKey.role = 'readonly'">readonly（只读）</button>
            </div>
            <select class="sr-only-select" v-model="newKey.role"><option value="admin">admin（完全控制）</option><option value="readonly">readonly（只读）</option></select>
          </div>
          <div class="key-create"><button type="button" class="btn primary" :disabled="creatingKey" @click="createKey">{{ creatingKey ? '创建中…' : '创建' }}</button></div>
        </div>
        <div v-if="createdKeyPlain" class="new-key">
          <div class="new-key-head"><strong>新密钥已生成（仅显示一次，请立即复制保存）</strong></div>
          <div class="new-key-row">
            <code class="key-plain">{{ createdKeyPlain }}</code>
            <button type="button" class="btn small primary fit" :class="{ 'copy-bounce': copiedKey }" @click="copyKey"><span class="fit-sizer" aria-hidden="true">✓ 已复制</span><span class="fit-sizer" aria-hidden="true">复制密钥</span><span class="fit-value">{{ copiedKey ? '✓ 已复制' : '复制密钥' }}</span></button>
            <button type="button" class="btn small" @click="createdKeyPlain = ''; copiedKey = false">收起</button>
          </div>
        </div>
        <ul v-if="keys.length" class="key-list">
          <li v-for="k in keys" :key="k.id" class="key-item">
            <div class="key-details">
              <div class="key-meta">
                <strong>{{ k.name }}</strong>
                <span class="tag" :class="k.role === 'admin' ? 'admin' : 'ro'">{{ k.role }}</span>
                <span v-if="isCurrentKey(k)" class="tag ok">当前会话</span>
                <code class="muted mono">{{ k.key_prefix }}…</code>
              </div>
              <div class="key-sub muted">
                <span>创建于 {{ formatTime(k.created_at) }}</span>
                <span v-if="k.last_used"> · 最近使用 {{ formatTime(k.last_used) }}</span>
              </div>
            </div>
            <button
              type="button"
              class="btn danger small"
              :disabled="!canRevokeKey(k)"
              :title="!canRevokeKey(k) ? '至少需要保留一个管理员密钥' : undefined"
              @click="revokeKey(k)"
            >
              撤销
            </button>
          </li>
        </ul>
        <p v-else-if="!keyBad" class="muted">暂无 Key。</p>
        <p v-if="keyMsg" class="hint" :class="{ bad: keyBad }" role="status">{{ keyMsg }}</p>
      </div>
    </section>
    <Modal ref="confirmRevoke" size="small" title="撤销 API Key" save-label="确认撤销密钥" danger :submit="commitRevoke" @close="pendingKey = null"><p>确定撤销 Key「{{ pendingKey?.name }}」？撤销后立即失效。</p></Modal>
  </div>
</template>

<style scoped>
.settings { display: grid; gap: 16px; width: 100%; }
.service-section, .runtime { min-width: 0; }
.runtime-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(220px, 100%), 1fr)); gap: 16px; margin: 0; }
.runtime dt { color: var(--muted); font-size: 12px; }
.runtime dd { margin: 6px 0 0; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; overflow-wrap: anywhere; font-weight: 500; }
.panel-body { padding: 16px 18px; }
.hint { margin: 10px 0 0; font-size: 12px; color: var(--muted); }
.hint.bad, .btn.danger { color: var(--danger); }
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(220px, 100%), 1fr)); gap: 12px; }
.field { min-width: 0; margin: 0; display: flex; flex-direction: column; gap: 6px; font-size: 13px; }
.field > span:first-child { color: var(--muted); font-size: 12px; }
.field input, .field select { width: 100%; min-width: 0; background: var(--input-bg); border: 1px solid var(--line-strong); border-radius: 8px; padding: 9px 12px; color: var(--text); font-size: 13px; }
.tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
.tag.admin { background: rgba(239, 68, 68, 0.12); color: var(--danger); }
.tag.ro { background: rgba(59, 130, 246, 0.12); color: #9fc5ff; }
.tag.ok { background: rgba(52, 211, 153, 0.14); color: var(--good); }
.mono { font-family: ui-monospace, monospace; font-size: 12px; }
.key-form { margin-bottom: 14px; padding-bottom: 14px; border-bottom: 1px solid var(--line); grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto; align-items: end; }
.key-create .btn { min-height: 40px; }
.key-details { min-width: 0; flex: 1; }
.key-item > .btn { flex: none; }
.key-meta strong, .key-sub { overflow-wrap: anywhere; }
.key-list { list-style: none; margin: 0; padding: 0; }
.key-item { display: flex; align-items: center; justify-content: space-between; gap: 12px; border-bottom: 1px solid var(--line); padding: 12px 0; }
.key-item:first-child { padding-top: 4px; }
.key-item:last-child { border-bottom: 0; padding-bottom: 0; }
.key-meta { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.key-sub { font-size: 12px; margin-top: 4px; }
.new-key { display: grid; gap: 8px; padding: 12px 14px; margin-bottom: 14px; background: var(--accent-soft); border: 1px solid rgba(45, 212, 191, 0.3); border-radius: 8px; }
.new-key-head { font-size: 12px; color: var(--accent-strong); }
.new-key-row { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.key-plain { flex: 1 1 260px; padding: 6px 10px; background: var(--input-bg); border: 1px solid var(--line); border-radius: 6px; font-family: ui-monospace, monospace; font-size: 13px; word-break: break-all; }
.btn.small { padding: 5px 10px; font-size: 12px; }
@media (max-width: 640px) {
  .key-form { grid-template-columns: minmax(0, 1fr); }
  .key-create .btn { width: 100%; }
}
</style>
