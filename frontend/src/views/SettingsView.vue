<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError } from '../api'
import EmptyState from '../components/EmptyState.vue'

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
interface ApiKey { id: number; name: string; role: string; prefix: string; created_at: string }
const keys = ref<ApiKey[]>([])
const showKeyForm = ref(false)
const newKey = ref({ name: '', role: 'admin' })
const creatingKey = ref(false)
const createdKeyPlain = ref('')
const keyMsg = ref('')
const keyBad = ref(false)
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
async function revokeKey(k: ApiKey) {
  if (!confirm(`确定撤销 Key「${k.name}」？撤销后立即失效。`)) return
  keyMsg.value = ''
  keyBad.value = false
  try { await api(`/keys/${k.id}`, 'DELETE'); await loadKeys() }
  catch (e) { keyBad.value = true; keyMsg.value = e instanceof ApiError ? e.message : '撤销失败' }
}
async function copyKey() {
  try {
    if (!navigator.clipboard) throw new Error('剪贴板不可用')
    await navigator.clipboard.writeText(createdKeyPlain.value)
    keyMsg.value = '已复制到剪贴板'; keyBad.value = false
  } catch { keyBad.value = true; keyMsg.value = '复制失败' }
}
onMounted(() => { void load(); void loadService(); void loadKeys() })
</script>

<template>
  <EmptyState v-if="loading" title="加载中…" text="" />
  <EmptyState v-else-if="loadError" title="加载失败" :text="loadError" />
  <div v-else-if="status" class="settings">
    <section class="runtime" aria-label="运行版本">
      <h2>Veilink</h2>
      <dl><div><dt>运行版本</dt><dd><code>{{ status.active_version }}</code><span class="tag ro">内置 Web</span></dd></div><div><dt>Web 状态</dt><dd>{{ status.serving ? '服务中' : '不可用' }}</dd></div></dl>
    </section>
    <section class="service-section">
      <header class="panel-head"><h2>服务配置</h2><button type="button" class="btn" :disabled="savingService || !serviceLoaded" @click="saveService">{{ savingService ? '保存中…' : '保存' }}</button></header>
      <div class="panel-body">
        <div class="form-grid">
          <label class="field"><span>监听地址</span><input v-model="service.listen_addr" type="text" placeholder="127.0.0.1:2545" :disabled="!serviceLoaded" /></label>
          <label class="field"><span>协议</span><select v-model="service.scheme" :disabled="!serviceLoaded"><option value="http">HTTP</option><option value="https">HTTPS</option></select></label>
          <label v-if="service.scheme === 'https'" class="field"><span>证书文件</span><input v-model="service.cert_file" type="text" placeholder="/data/cert.pem" /></label>
          <label v-if="service.scheme === 'https'" class="field"><span>私钥文件</span><input v-model="service.key_file" type="text" placeholder="/data/key.pem" /></label>
        </div>
        <p v-if="serviceMsg" class="hint" :class="{ bad: serviceBad }" role="status">{{ serviceMsg }}</p>
      </div>
    </section>
    <section class="service-section">
      <header class="panel-head"><h2>API Key</h2><button type="button" class="btn primary" @click="showKeyForm = !showKeyForm">{{ showKeyForm ? '取消' : '新建 Key' }}</button></header>
      <div class="panel-body">
        <div v-if="showKeyForm" class="form-grid key-form">
          <label class="field"><span>名称</span><input v-model="newKey.name" type="text" placeholder="留空自动生成" /></label>
          <label class="field"><span>角色</span><select v-model="newKey.role"><option value="admin">admin（完全控制）</option><option value="readonly">readonly（只读）</option></select></label>
          <div class="key-create"><button type="button" class="btn primary" :disabled="creatingKey" @click="createKey">{{ creatingKey ? '创建中…' : '创建' }}</button></div>
        </div>
        <div v-if="createdKeyPlain" class="new-key"><code class="key-plain">{{ createdKeyPlain }}</code><button type="button" class="btn small" @click="copyKey">复制</button></div>
        <ul v-if="keys.length" class="key-list">
          <li v-for="k in keys" :key="k.id" class="key-item">
            <div class="key-details"><div class="key-meta"><strong>{{ k.name }}</strong><span class="tag" :class="k.role === 'admin' ? 'admin' : 'ro'">{{ k.role }}</span><span class="muted mono">{{ k.prefix }}…</span></div><div class="key-sub muted">{{ k.created_at }}</div></div>
            <button type="button" class="btn danger small" @click="revokeKey(k)">撤销</button>
          </li>
        </ul>
        <p v-else-if="!keyBad" class="muted">暂无 Key。</p>
        <p v-if="keyMsg" class="hint" :class="{ bad: keyBad }" role="status">{{ keyMsg }}</p>
      </div>
    </section>
  </div>
</template>

<style scoped>
.settings { display: grid; gap: 20px; max-width: 860px; margin: 0 auto; width: 100%; }
.service-section, .runtime { border-bottom: 1px solid var(--line); padding-bottom: 16px; min-width: 0; }
.runtime dl { display: flex; gap: 32px; flex-wrap: wrap; }
.runtime dt { color: var(--muted); font-size: 12px; }
.runtime dd { margin: 8px 0 0; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; overflow-wrap: anywhere; }
.panel-head { padding: 0; }
.panel-head h2 { font-size: 18px; margin: 0; }
.panel-body { padding-top: 16px; }
.hint { margin: 10px 0 0; font-size: 12px; color: var(--muted); }
.hint.bad, .btn.danger { color: var(--danger); }
.form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(220px, 100%), 1fr)); gap: 12px; }
.field { min-width: 0; margin: 0; display: flex; flex-direction: column; gap: 6px; font-size: 13px; }
.field > span:first-child { color: var(--muted); font-size: 12px; }
.field input, .field select { width: 100%; min-width: 0; background: var(--input-bg); border: 1px solid var(--line); border-radius: 8px; padding: 9px 12px; color: var(--text); font-size: 13px; }
.tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
.tag.admin { background: rgba(239, 68, 68, 0.12); color: var(--danger); }
.tag.ro { background: rgba(59, 130, 246, 0.12); color: #9fc5ff; }
.mono { font-family: ui-monospace, monospace; font-size: 12px; }
.key-form { margin-bottom: 12px; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr) auto; align-items: end; }
.key-create .btn { min-height: 40px; }
.key-details { min-width: 0; flex: 1; }
.key-item > .btn { flex: none; }
.key-meta strong, .key-sub { overflow-wrap: anywhere; }
.key-list { list-style: none; margin: 12px 0 0; padding: 0; }
.key-item { display: flex; align-items: center; justify-content: space-between; gap: 12px; border-bottom: 1px solid var(--line); padding: 12px 0; }
.key-meta { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.key-sub { font-size: 12px; margin-top: 2px; }
.new-key { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; padding: 10px 0; }
.key-plain { font-family: ui-monospace, monospace; font-size: 13px; word-break: break-all; }
.btn.small { padding: 5px 10px; font-size: 12px; }
@media (max-width: 640px) {
  .key-form { grid-template-columns: minmax(0, 1fr); }
  .key-create .btn { width: 100%; }
}
</style>
