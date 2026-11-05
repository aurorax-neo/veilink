<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted, reactive, ref, watch, watchEffect } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { askNodes, nodeBaseline, nodeChanged, registerPageRefresh, waitForReports } from '../pageRefresh'
import { byNameAndId, endpoint, formatTime, heartbeatOnline, nodeName, validateMapping } from '../format'
import type { Mapping, TrafficRow } from '../types'
import Badge from '../components/Badge.vue'
import EmptyState from '../components/EmptyState.vue'
import Modal from '../components/Modal.vue'

const desk = inject(deskKey)!
const filter = ref('all')
const query = ref('')
const editor = ref<InstanceType<typeof Modal> | null>(null)
const confirm = ref<InstanceType<typeof Modal> | null>(null)
const pending = ref<Mapping | null>(null)
const action = ref<'toggle' | 'delete'>('toggle')
const popconfirmId = ref('')
const togglingBusy = ref(false)
const poolDropdownOpen = ref(false)
const poolSearch = ref('')
const hasSavedDraft = ref(false)
const now = ref(Date.now())

const DRAFT_STORAGE_KEY = 'veilink_mapping_draft_v1'
const FILTER_STORAGE_KEY = 'veilink_proxies_filter'

function setFilter(next: 'all' | 'on' | 'off') {
  filter.value = next
  try {
    globalThis.sessionStorage?.setItem(FILTER_STORAGE_KEY, next)
    globalThis.localStorage?.setItem(FILTER_STORAGE_KEY, next)
  } catch { /* ignore */ }
}
type EndpointStatus = { acknowledged: boolean; reason: string; linked?: boolean }
type MappingStatus = { server: EndpointStatus; client: EndpointStatus }
const statuses = ref<Record<string, MappingStatus>>({})
const statusError = ref('')
let statusGeneration = 0
let active = false
let unregisterPageRefresh: (() => void) | undefined
let clock: ReturnType<typeof setInterval> | undefined
let statusClock: ReturnType<typeof setInterval> | undefined
let offStreamTunnel: (() => void) | undefined
let offStreamNode: (() => void) | undefined
async function refreshStatus() {
  const generation = ++statusGeneration
  statusError.value = ''
  try {
    const result = await api<Record<string, MappingStatus>>('/mappings/status')
    if (!active || generation !== statusGeneration) return
    if (!result || typeof result !== 'object' || Array.isArray(result)) throw new Error('状态格式无效')
    statuses.value = result
  } catch {
    if (active && generation === statusGeneration) { statuses.value = {}; statusError.value = '映射状态读取失败，请稍后重试。' }
  }
}
onMounted(() => {
  active = true
  try {
    const savedFilter = globalThis.sessionStorage?.getItem(FILTER_STORAGE_KEY) || globalThis.localStorage?.getItem(FILTER_STORAGE_KEY)
    if (savedFilter === 'all' || savedFilter === 'on' || savedFilter === 'off') filter.value = savedFilter
  } catch { /* ignore */ }
  clock = setInterval(() => { now.value = Date.now() }, 1000)
  statusClock = setInterval(() => { void refreshStatus() }, 5000)
  const bus = (globalThis as Record<string, unknown>).__veilinkStream as { on?: (type: string, fn: () => void) => () => void } | undefined
  offStreamTunnel = bus?.on?.('tunnel', () => { if (active) void refreshStatus() })
  offStreamNode = bus?.on?.('node', () => { if (active) void refreshStatus() })
  void refreshStatus()
  unregisterPageRefresh = registerPageRefresh(refreshReported)
})
onUnmounted(() => { active = false; ++statusGeneration; unregisterPageRefresh?.(); unregisterPageRefresh = undefined; offStreamTunnel?.(); offStreamNode?.(); if (clock) clearInterval(clock); if (statusClock) clearInterval(statusClock) })
async function refreshReported() {
  const ids = [...new Set(desk.mappings.flatMap(mapping => [mapping.server_id, mapping.client_id]))].filter(id => {
    const node = desk.nodes.find(item => item.id === id)
    return !!node && !node.revoked
  })
  const baseline = new Map(ids.map(id => [id, nodeBaseline(desk.nodes.find(item => item.id === id)!)]))
  const connected = await askNodes(ids)
  const waiting = () => active && connected.some(id => !nodeChanged(desk.nodes.find(item => item.id === id), baseline.get(id)!))
  await waitForReports(async () => {
    if (!active) return
    await desk.reload({ silent: true })
    if (active) await refreshStatus()
  }, waiting)
}
watch(() => desk.mappings, () => { if (active) void refreshStatus() })
watch(() => desk.loading, (loading, previous) => { if (active && previous && !loading) void refreshStatus() })

const draft = reactive({ id: '', name: '', serverId: '', clientId: '', connectEndpointId: '', bandwidthLimit: '0', pool: 1, listenHost: '0.0.0.0', listenPort: '', targetHost: '', targetPort: '', network: 'tcp', enabled: true })
const defaultMuxType = 'smux'
const muxType = ref('')
let openingEditor = false
const filteredPools = computed(() => {
  const q = poolSearch.value.trim()
  const all = Array.from({ length: 32 }, (_, i) => i + 1)
  return q ? all.filter(n => String(n).includes(q)) : all
})
watch(() => draft.network, network => { if (network !== 'tcp') muxType.value = '' }, { flush: 'sync' })
watch(
  () => [draft.id, draft.name, draft.serverId, draft.clientId, draft.connectEndpointId, draft.bandwidthLimit, draft.pool, draft.listenHost, draft.listenPort, draft.targetHost, draft.targetPort, draft.network, draft.enabled, muxType.value],
  () => {
    if (openingEditor || draft.id || (!draft.name && !draft.listenPort && !draft.targetPort)) return
    try {
      globalThis.sessionStorage?.setItem(DRAFT_STORAGE_KEY, JSON.stringify({ ...draft, muxType: muxType.value }))
    } catch { /* ignore */ }
  },
)
function restoreSavedDraft() {
  try {
    const raw = globalThis.sessionStorage?.getItem(DRAFT_STORAGE_KEY)
    if (!raw) return
    const parsed = JSON.parse(raw)
    if (parsed && typeof parsed === 'object' && !parsed.id) {
      const { muxType: savedMux, ...rest } = parsed
      Object.assign(draft, rest)
      if (typeof savedMux === 'string') muxType.value = draft.network === 'tcp' ? savedMux : ''
      hasSavedDraft.value = false
    }
  } catch { /* ignore */ }
}
function discardSavedDraft() {
  hasSavedDraft.value = false
  try { globalThis.sessionStorage?.removeItem(DRAFT_STORAGE_KEY) } catch { /* ignore */ }
}
const servers = computed(() => desk.nodes.filter(n => n.role === 'server' && !n.revoked).sort(byNameAndId))
const clients = computed(() => desk.nodes.filter(n => n.role === 'client' && !n.revoked).sort(byNameAndId))
function connectionOptions(serverId: string) {
  const server = servers.value.find(node => node.id === serverId)
  if (!server) return []
  const candidates = server.connect_endpoints?.length ? server.connect_endpoints : server.address && server.port ? [{ id: 'primary', name: '首选地址', host: server.address, port: server.port, enabled: true }] : []
  return candidates.filter(candidate => candidate.enabled)
}
const connections = computed(() => connectionOptions(draft.serverId))
const missingConnection = computed(() => !!draft.connectEndpointId && !connections.value.some(candidate => candidate.id === draft.connectEndpointId))
watch(() => draft.serverId, () => { draft.connectEndpointId = connections.value[0]?.id || '' }, { flush: 'sync' })
function connectionLabel(mapping: Mapping) {
  if (!mapping.connect_endpoint_id) return '自动按服务端地址顺序切换'
  const candidate = connectionOptions(mapping.server_id).find(item => item.id === mapping.connect_endpoint_id)
  return candidate ? `${candidate.name} · ${endpoint(candidate.host, candidate.port)}` : '连接地址不可用，请重新选择'
}
function tunnelState(mapping: Mapping): { text: string; tone: '' | 'good' | 'warn' | 'bad' } {
  if (!mapping.enabled) return { text: '已停用', tone: '' }
  const server = desk.nodes.find(node => node.id === mapping.server_id)
  const client = desk.nodes.find(node => node.id === mapping.client_id)
  if (!server || !client || server.revoked || client.revoked) return { text: '节点不可用', tone: 'warn' }
  if (server.disabled || client.disabled) return { text: server.disabled && client.disabled ? '两端已停用' : server.disabled ? '服务端已停用' : '客户端已停用', tone: '' }
  const currentNow = Math.max(now.value, Date.now())
  const serverOnline = heartbeatOnline(server, currentNow)
  const clientOnline = heartbeatOnline(client, currentNow)
  if (!serverOnline || !clientOnline) return { text: !serverOnline && !clientOnline ? '两端离线' : !serverOnline ? '服务端离线' : '客户端离线', tone: 'warn' }
  const status = statuses.value[mapping.id]
  const serverDown = status?.server?.linked !== true
  const clientDown = status?.client?.linked !== true
  if (!serverDown && !clientDown) return { text: '已连接', tone: 'good' }
  if (serverDown && clientDown) return { text: '未连接', tone: 'warn' }
  return { text: serverDown ? '服务端未连接' : '客户端未连接', tone: 'warn' }
}
function traffic(mapping: Mapping): TrafficRow | undefined { return desk.traffic.find(row => row.mapping_id === mapping.id) }
function bytes(n: number): string {
  if (!Number.isSafeInteger(n) || n < 0) return '—'
  if (n < 1024) return `${n} B`
  const unit = Math.min(Math.floor(Math.log(n) / Math.log(1024)), 4)
  return `${(n / 1024 ** unit).toFixed(1)} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][unit]}`
}
function trafficLine(mapping: Mapping): string {
  if (desk.trafficError) return '读取失败'
  if (!desk.trafficLoaded) return '加载中…'
  if (!mapping.enabled) return '—'
  const row = traffic(mapping)
  if (row?.reported_at) return `${bytes(row.up_bytes)} / ${bytes(row.down_bytes)}`
  return '尚无流量上报'
}
function reportedClock(iso: string) {
  return formatTime(iso)
}
function trafficWidth(mapping: Mapping) {
  const line = trafficLine(mapping)
  const row = traffic(mapping)
  const stamp = !desk.trafficError && desk.trafficLoaded && mapping.enabled && row?.reported_at ? `服务端本次进程 · ${reportedClock(row.reported_at)} 上报` : ''
  return stamp.length > line.length ? stamp : line
}
const trafficFit = reactive<Record<string, string>>({})
watchEffect(() => {
  for (const mapping of desk.mappings) {
    const text = trafficWidth(mapping)
    const prev = trafficFit[mapping.id]
    if (!prev || text.length > prev.length) trafficFit[mapping.id] = text
  }
})
const rows = computed(() => desk.mappings.filter(m => (filter.value === 'all' || m.enabled === (filter.value === 'on')) && [m.name, m.listen_host, m.target_host, nodeName(desk.nodes, m.server_id), nodeName(desk.nodes, m.client_id)].join(' ').toLowerCase().includes(query.value.trim().toLowerCase())).sort(byNameAndId))
function fields(m: Mapping) {
  const limit = m.bandwidth_limit?.match(/^([0-9]+(?:\.[0-9]+)?)(Kbps|Mbps|Gbps)$/)
  const bandwidthLimit = limit ? String(Number((Number(limit[1]) * ({ Kbps: 0.001, Mbps: 1, Gbps: 1000 }[limit[2]] || 0)).toFixed(6))) : '0'
  return { id: m.id, name: m.name, serverId: m.server_id, clientId: m.client_id, connectEndpointId: m.connect_endpoint_id || '', bandwidthLimit, pool: m.pool || 1, listenHost: m.listen_host, listenPort: String(m.listen_port), targetHost: m.target_host, targetPort: String(m.target_port), network: m.network || 'tcp', enabled: m.enabled }
}
function open(mapping?: Mapping) {
  openingEditor = true
  poolDropdownOpen.value = false
  poolSearch.value = ''
  try {
    Object.assign(draft, mapping ? fields(mapping) : { id: '', name: '', serverId: servers.value[0]?.id || '', clientId: clients.value[0]?.id || '', bandwidthLimit: '0', pool: 1, listenHost: '0.0.0.0', listenPort: '', targetHost: '127.0.0.1', targetPort: '', network: 'tcp', enabled: true })
    draft.connectEndpointId = mapping ? mapping.connect_endpoint_id || '' : connections.value[0]?.id || ''
    muxType.value = draft.network === 'tcp' && mapping?.mux ? mapping.mux_type || defaultMuxType : ''
  } finally {
    openingEditor = false
  }
  if (!mapping) {
    try { hasSavedDraft.value = !!globalThis.sessionStorage?.getItem(DRAFT_STORAGE_KEY) } catch { hasSavedDraft.value = false }
  } else {
    hasSavedDraft.value = false
  }
  editor.value?.open()
}
async function save() {
  const problem = validateMapping(draft, desk.nodes, desk.mappings, draft.id)
  if (problem) throw new Error(problem)
  await api(draft.id ? `/mappings/${encodeURIComponent(draft.id)}` : '/mappings', draft.id ? 'PUT' : 'POST', {
    name: draft.name.trim(), server_id: draft.serverId, client_id: draft.clientId, pool: draft.pool, mux: draft.network === 'tcp' && muxType.value !== '',
    mux_type: draft.network === 'tcp' ? muxType.value : '',
    connect_endpoint_id: draft.connectEndpointId,
    bandwidth_limit: Number(draft.bandwidthLimit) > 0 ? (Number(draft.bandwidthLimit) === Number(Number(draft.bandwidthLimit).toFixed(3)) ? `${Number(draft.bandwidthLimit)}Mbps` : `${Number((Number(draft.bandwidthLimit) * 1000).toFixed(3))}Kbps`) : '',
    listen_host: draft.listenHost.trim(), listen_port: Number(draft.listenPort), target_host: draft.targetHost.trim(), target_port: Number(draft.targetPort), network: draft.network, enabled: draft.enabled,
  })
  if (!draft.id) discardSavedDraft()
  await desk.reload(); if (active) void refreshStatus(); desk.notify('映射已保存。')
  return true
}
function ask(mapping: Mapping, operation: 'toggle' | 'delete') {
  pending.value = mapping
  action.value = operation
  if (operation === 'toggle') {
    popconfirmId.value = popconfirmId.value === mapping.id ? '' : mapping.id
  } else {
    popconfirmId.value = ''
    confirm.value?.open()
  }
}
async function confirmInlineToggle() {
  if (togglingBusy.value) return
  togglingBusy.value = true
  try {
    await run()
    popconfirmId.value = ''
  } catch (reason) {
    desk.notify(reason instanceof Error ? reason.message : '操作失败', true)
  } finally {
    togglingBusy.value = false
  }
}
async function run() {
  const mapping = pending.value
  if (!mapping) return false
  const wasEnabled = mapping.enabled
  if (action.value === 'toggle') {
    if (!mapping.enabled) {
      const problem = validateMapping({ ...fields(mapping), enabled: true }, desk.nodes, desk.mappings, mapping.id)
      if (problem) throw new Error(problem)
    }
    await api(`/mappings/${encodeURIComponent(mapping.id)}`, 'PUT', { ...mapping, enabled: !mapping.enabled })
  } else await api(`/mappings/${encodeURIComponent(mapping.id)}`, 'DELETE')
  popconfirmId.value = ''
  await desk.reload()
  if (active) void refreshStatus()
  if (action.value === 'delete') {
    desk.notify('映射已删除。')
  } else {
    desk.notify('状态已更新。', false, {
      label: '撤销',
      run: async () => {
        await api(`/mappings/${encodeURIComponent(mapping.id)}`, 'PUT', { ...mapping, enabled: wasEnabled })
        await desk.reload()
        if (active) void refreshStatus()
        desk.notify('已撤销映射状态变更。')
      },
    })
  }
  return true
}
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="加载中…" text="" />
  <EmptyState v-else-if="!desk.loaded" title="加载失败" :text="desk.error" />
  <div v-else class="stack">
    <div class="toolbar">
      <div class="chips" role="group" aria-label="映射筛选"><button v-for="item in [{id: 'all', text: '全部'}, {id: 'on', text: '启用'}, {id: 'off', text: '停用'}]" :key="item.id" type="button" :aria-pressed="filter === item.id" @click="setFilter(item.id as 'all' | 'on' | 'off')">{{ item.text }}</button></div>
      <input v-model="query" type="search" aria-label="搜索映射" placeholder="搜索名称、节点或地址" />
      <button type="button" class="btn primary" @click="open()">新建映射</button>
    </div>
    <div class="page-alert" aria-live="polite">
      <p v-if="desk.trafficError" class="error" role="alert">流量读取失败：{{ desk.trafficError }}；可点击刷新重试。</p>
      <p v-else-if="statusError" class="error" role="alert">{{ statusError }}</p>
    </div>
    <EmptyState v-if="!rows.length" title="暂无映射" text="新建映射或调整筛选。" />
    <div v-else class="panel table-scroll" tabindex="0" role="region" aria-label="映射列表">
      <table>
        <thead><tr><th scope="col">名称</th><th scope="col">服务端 → 客户端</th><th scope="col">路径</th><th scope="col">Pool</th><th scope="col">隧道状态</th><th scope="col">流量（上行 / 下行）</th><th scope="col">操作</th></tr></thead>
        <tbody><tr v-for="mapping in rows" :key="mapping.id">
          <td><strong>{{ mapping.name }}</strong><Badge :text="(mapping.network || 'tcp').toUpperCase()" /></td>
          <td>{{ nodeName(desk.nodes, mapping.server_id) }}<small>→ {{ nodeName(desk.nodes, mapping.client_id) }}</small><small>隧道入口：{{ connectionLabel(mapping) }}</small></td>
          <td><code>{{ endpoint(mapping.listen_host, mapping.listen_port) }}</code><small>→ <code>{{ endpoint(mapping.target_host, mapping.target_port) }}</code></small></td>
          <td>{{ mapping.pool || 1 }}<small>{{ mapping.network === 'udp' ? 'XUDP' : mapping.mux ? (mapping.mux_type || 'smux') : 'mux 关闭' }}</small><small v-if="mapping.bandwidth_limit">{{ mapping.bandwidth_limit }}</small></td>
          <td><Badge reserve="客户端未连接" :text="tunnelState(mapping).text" :tone="tunnelState(mapping).tone" title="隧道会话是否保持" /></td>
          <td><span class="fit traffic-figure"><span class="fit-sizer" aria-hidden="true">{{ trafficFit[mapping.id] || trafficWidth(mapping) }}</span><span class="fit-value">{{ trafficLine(mapping) }}</span></span><small v-if="!desk.trafficError && desk.trafficLoaded && mapping.enabled && traffic(mapping)?.reported_at" class="traffic-figure">服务端本次进程 · {{ reportedClock(traffic(mapping)!.reported_at!) }} 上报</small></td>
          <td>
            <div class="actions popconfirm-anchor">
              <button type="button" class="btn small" @click="open(mapping)">编辑</button>
              <button type="button" class="btn small" :aria-expanded="popconfirmId === mapping.id && action === 'toggle'" @click="ask(mapping, 'toggle')">{{ mapping.enabled ? '停用' : '启用' }}</button>
              <button type="button" class="btn small danger" @click="ask(mapping, 'delete')">删除</button>
              <div v-if="popconfirmId === mapping.id && action === 'toggle'" class="popconfirm" role="dialog" :aria-label="`${mapping.enabled ? '停用' : '启用'}映射确认`">
                <p class="popconfirm-title">确认{{ mapping.enabled ? '停用' : '启用' }}「{{ mapping.name }}」？</p>
                <div class="popconfirm-actions">
                  <button type="button" class="btn small quiet" :disabled="togglingBusy" @click="popconfirmId = ''">保留当前</button>
                  <button type="button" class="btn small primary" :disabled="togglingBusy" @click="confirmInlineToggle">{{ togglingBusy ? '处理中…' : `确认${mapping.enabled ? '停用' : '启用'}` }}</button>
                </div>
              </div>
            </div>
          </td>
        </tr></tbody>
      </table>
    </div>
  </div>
  <Modal ref="editor" size="large" :title="draft.id ? '编辑映射' : '新建映射'" :disabled="!servers.length || !clients.length" :submit="save">
    <div v-if="hasSavedDraft && !draft.id" class="draft-banner" role="status">
      <span>检测到上次未提交的映射草稿</span>
      <div class="actions">
        <button type="button" class="btn small primary" @click="restoreSavedDraft">恢复草稿</button>
        <button type="button" class="btn small quiet" @click="discardSavedDraft">忽略</button>
      </div>
    </div>
    <p v-if="!servers.length || !clients.length" class="help">请先创建可用的服务端和客户端。</p>
    <label for="map-name">名称</label><input id="map-name" v-model="draft.name" maxlength="128" required />
    <div class="grid-2">
      <div><label for="map-server">服务端</label><select id="map-server" v-model="draft.serverId" required :disabled="!servers.length"><option value="" disabled>请选择</option><option v-for="node in servers" :key="node.id" :value="node.id">{{ node.name }}</option></select></div>
      <div><label for="map-client">客户端</label><select id="map-client" v-model="draft.clientId" required :disabled="!clients.length"><option value="" disabled>请选择</option><option v-for="node in clients" :key="node.id" :value="node.id">{{ node.name }}</option></select></div>
    </div>
    <label for="map-connection">客户端连接服务端的地址</label>
    <select id="map-connection" v-model="draft.connectEndpointId" :disabled="!connections.length" aria-describedby="map-connection-help" :aria-invalid="missingConnection">
      <option value="">自动按服务端地址顺序切换</option>
      <option v-if="missingConnection" :value="draft.connectEndpointId" disabled>原连接地址不可用，请重新选择</option>
      <option v-for="candidate in connections" :key="candidate.id" :value="candidate.id">{{ candidate.name }} · {{ endpoint(candidate.host, candidate.port) }}</option>
    </select>
    <p id="map-connection-help" class="help">用于 Client 建立到 Server 的隧道，不是映射监听地址或内网目标。指定入口后只连接该地址；选择自动时按服务端启用地址顺序切换。协议、证书信任和密钥仍由服务端统一下发。</p>
    <p v-if="!connections.length" class="error" role="status">所选服务端没有启用的连接地址，请先编辑服务端。</p>
    <p v-else-if="missingConnection" class="error" role="status">原连接地址已停用或删除，请重新选择后保存。</p>
    <div class="grid-2">
      <div>
        <label for="map-network">协议</label>
        <div class="seg-pills" role="group" aria-label="协议选择">
          <button type="button" :aria-pressed="draft.network === 'tcp'" @click="draft.network = 'tcp'">TCP</button>
          <button type="button" :aria-pressed="draft.network === 'udp'" @click="draft.network = 'udp'">UDP</button>
        </div>
        <select id="map-network" class="sr-only-select" v-model="draft.network"><option value="tcp">TCP</option><option value="udp">UDP</option></select>
      </div>
      <div class="searchable-select-wrap">
        <label for="map-pool">Pool</label>
        <div class="pool-control-row">
          <select id="map-pool" v-model.number="draft.pool"><option v-for="n in 32" :key="n" :value="n">{{ n }}</option></select>
          <button type="button" class="btn small quiet" :aria-expanded="poolDropdownOpen" @click="poolDropdownOpen = !poolDropdownOpen">搜索 1-32</button>
        </div>
        <div v-if="poolDropdownOpen" class="select-dropdown-panel" role="listbox" aria-label="Pool 数量选择">
          <input v-model="poolSearch" type="search" class="select-search-input" placeholder="搜索并发连接数 (1-32)…" aria-label="搜索 Pool" />
          <div class="select-options-scroll">
            <button
              v-for="n in filteredPools"
              :key="n"
              type="button"
              class="select-option-item"
              :class="{ active: draft.pool === n }"
              role="option"
              :aria-selected="draft.pool === n"
              @click="draft.pool = n; poolDropdownOpen = false"
            >
              <span>Pool {{ n }}</span>
              <span v-if="draft.pool === n" aria-hidden="true">✓</span>
            </button>
          </div>
        </div>
      </div>
    </div>
    <label for="map-mux-type">TCP mux（默认关闭）</label>
    <div class="seg-pills" role="group" aria-label="TCP mux 协议">
      <button v-for="opt in [{ value: '', label: '关闭' }, { value: 'smux', label: 'smux' }, { value: 'yamux', label: 'yamux' }, { value: 'h2mux', label: 'h2mux' }]" :key="opt.value" type="button" :disabled="draft.network !== 'tcp'" :aria-pressed="muxType === opt.value" @click="muxType = opt.value">{{ opt.label }}</button>
    </div>
    <select id="map-mux-type" class="sr-only-select" v-model="muxType" :disabled="draft.network !== 'tcp'"><option value="">关闭</option><option value="smux">smux</option><option value="yamux">yamux</option><option value="h2mux">h2mux</option></select>
    <label for="map-bandwidth">带宽上限（Mbps）</label><input id="map-bandwidth" v-model="draft.bandwidthLimit" type="number" min="0" max="100000" step="0.000001" placeholder="0（不限速）" />
    <div class="grid-2">
      <div><label for="map-listen">监听 IP</label><input id="map-listen" v-model="draft.listenHost" required spellcheck="false" /></div>
      <div><label for="map-port">监听端口</label><input id="map-port" v-model="draft.listenPort" type="number" min="1" max="65535" required /></div>
    </div>
    <div class="grid-2">
      <div><label for="map-target">目标地址</label><input id="map-target" v-model="draft.targetHost" required spellcheck="false" /></div>
      <div><label for="map-target-port">目标端口</label><input id="map-target-port" v-model="draft.targetPort" type="number" min="1" max="65535" required /></div>
    </div>
    <label class="check" for="map-enabled"><input id="map-enabled" v-model="draft.enabled" type="checkbox" /> 启用</label>
  </Modal>
  <Modal ref="confirm" size="small" :title="action === 'delete' ? '删除映射' : pending?.enabled ? '停用映射' : '启用映射'" :save-label="action === 'delete' ? '确认删除映射' : pending?.enabled ? '确认停用映射' : '确认启用映射'" :danger="action === 'delete'" :submit="run"><p>确认修改「{{ pending?.name }}」？现有连接可能断开。</p></Modal>
</template>
