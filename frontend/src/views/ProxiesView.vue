<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted, reactive, ref, watch, watchEffect } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { askNodes, nodeBaseline, nodeChanged, registerPageRefresh, waitForReports } from '../pageRefresh'
import { byNameAndId, endpoint, heartbeatOnline, nodeName, validateMapping } from '../format'
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
const now = ref(Date.now())
type EndpointStatus = { acknowledged: boolean; reason: string; linked?: boolean }
type MappingStatus = { server: EndpointStatus; client: EndpointStatus }
const statuses = ref<Record<string, MappingStatus>>({})
const statusError = ref('')
let statusGeneration = 0
let active = false
let unregisterPageRefresh: (() => void) | undefined
let clock: ReturnType<typeof setInterval> | undefined
let statusClock: ReturnType<typeof setInterval> | undefined
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
  clock = setInterval(() => { now.value = Date.now() }, 1000)
  statusClock = setInterval(() => { void refreshStatus() }, 5000)
  void refreshStatus()
  unregisterPageRefresh = registerPageRefresh(refreshReported)
})
onUnmounted(() => { active = false; ++statusGeneration; unregisterPageRefresh?.(); unregisterPageRefresh = undefined; if (clock) clearInterval(clock); if (statusClock) clearInterval(statusClock) })
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

const draft = reactive({ id: '', name: '', serverId: '', clientId: '', connectEndpointId: '', pool: 1, listenHost: '0.0.0.0', listenPort: '', targetHost: '', targetPort: '', network: 'tcp', enabled: true })
const defaultMuxType = 'smux'
const muxType = ref('')
watch(() => draft.network, network => { if (network !== 'tcp') muxType.value = '' }, { flush: 'sync' })
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
  const serverOnline = heartbeatOnline(server, now.value)
  const clientOnline = heartbeatOnline(client, now.value)
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
  return new Date(iso).toLocaleString('zh-CN', { hour12: false, year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
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
  return { id: m.id, name: m.name, serverId: m.server_id, clientId: m.client_id, connectEndpointId: m.connect_endpoint_id || '', pool: m.pool || 1, listenHost: m.listen_host, listenPort: String(m.listen_port), targetHost: m.target_host, targetPort: String(m.target_port), network: m.network || 'tcp', enabled: m.enabled }
}
function open(mapping?: Mapping) {
  Object.assign(draft, mapping ? fields(mapping) : { id: '', name: '', serverId: servers.value[0]?.id || '', clientId: clients.value[0]?.id || '', pool: 1, listenHost: '0.0.0.0', listenPort: '', targetHost: '127.0.0.1', targetPort: '', network: 'tcp', enabled: true })
  draft.connectEndpointId = mapping ? mapping.connect_endpoint_id || '' : connections.value[0]?.id || ''
  muxType.value = draft.network === 'tcp' && mapping?.mux ? mapping.mux_type || defaultMuxType : ''
  editor.value?.open()
}
async function save() {
  const problem = validateMapping(draft, desk.nodes, desk.mappings, draft.id)
  if (problem) throw new Error(problem)
  await api(draft.id ? `/mappings/${encodeURIComponent(draft.id)}` : '/mappings', draft.id ? 'PUT' : 'POST', {
    name: draft.name.trim(), server_id: draft.serverId, client_id: draft.clientId, pool: draft.pool, mux: draft.network === 'tcp' && muxType.value !== '',
    mux_type: draft.network === 'tcp' ? muxType.value : '',
    connect_endpoint_id: draft.connectEndpointId,
    listen_host: draft.listenHost.trim(), listen_port: Number(draft.listenPort), target_host: draft.targetHost.trim(), target_port: Number(draft.targetPort), network: draft.network, enabled: draft.enabled,
  })
  await desk.reload(); if (active) void refreshStatus(); desk.notify('映射已保存。')
  return true
}
function ask(mapping: Mapping, operation: 'toggle' | 'delete') { pending.value = mapping; action.value = operation; confirm.value?.open() }
async function run() {
  const mapping = pending.value
  if (!mapping) return false
  if (action.value === 'toggle') {
    if (!mapping.enabled) {
      const problem = validateMapping({ ...fields(mapping), enabled: true }, desk.nodes, desk.mappings, mapping.id)
      if (problem) throw new Error(problem)
    }
    await api(`/mappings/${encodeURIComponent(mapping.id)}`, 'PUT', { ...mapping, enabled: !mapping.enabled })
  } else await api(`/mappings/${encodeURIComponent(mapping.id)}`, 'DELETE')
  await desk.reload(); if (active) void refreshStatus(); desk.notify(action.value === 'delete' ? '映射已删除。' : '状态已更新。')
  return true
}
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="加载中…" text="" />
  <EmptyState v-else-if="!desk.loaded" title="加载失败" :text="desk.error" />
  <div v-else class="stack">
    <div class="toolbar">
      <div class="chips" role="group" aria-label="映射筛选"><button v-for="item in [{id: 'all', text: '全部'}, {id: 'on', text: '启用'}, {id: 'off', text: '停用'}]" :key="item.id" type="button" :aria-pressed="filter === item.id" @click="filter = item.id">{{ item.text }}</button></div>
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
          <td>{{ mapping.pool || 1 }}<small>{{ mapping.network === 'udp' ? 'XUDP' : mapping.mux ? (mapping.mux_type || 'smux') : 'mux 关闭' }}</small></td>
          <td><Badge reserve="客户端未连接" :text="tunnelState(mapping).text" :tone="tunnelState(mapping).tone" title="隧道会话是否保持" /></td>
          <td><span class="fit traffic-figure"><span class="fit-sizer" aria-hidden="true">{{ trafficFit[mapping.id] || trafficWidth(mapping) }}</span><span class="fit-value">{{ trafficLine(mapping) }}</span></span><small v-if="!desk.trafficError && desk.trafficLoaded && mapping.enabled && traffic(mapping)?.reported_at" class="traffic-figure">服务端本次进程 · {{ reportedClock(traffic(mapping)!.reported_at!) }} 上报</small></td>
          <td><div class="actions"><button type="button" class="btn small" @click="open(mapping)">编辑</button><button type="button" class="btn small" @click="ask(mapping, 'toggle')">{{ mapping.enabled ? '停用' : '启用' }}</button><button type="button" class="btn small danger" @click="ask(mapping, 'delete')">删除</button></div></td>
        </tr></tbody>
      </table>
    </div>
  </div>
  <Modal ref="editor" :title="draft.id ? '编辑映射' : '新建映射'" :disabled="!servers.length || !clients.length" :submit="save">
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
      <div><label for="map-network">协议</label><select id="map-network" v-model="draft.network"><option value="tcp">TCP</option><option value="udp">UDP</option></select></div>
      <div><label for="map-pool">Pool</label><select id="map-pool" v-model.number="draft.pool"><option v-for="n in 32" :key="n" :value="n">{{ n }}</option></select></div>
    </div>
    <label for="map-mux-type">TCP mux（默认关闭）</label>
    <select id="map-mux-type" v-model="muxType" :disabled="draft.network !== 'tcp'"><option value="">关闭</option><option value="smux">smux</option><option value="yamux">yamux</option><option value="h2mux">h2mux</option></select>
    <p class="help">关闭：每条 TCP 流使用独立认证连接；开启：多条 TCP 流共享连接，Vision 不直拷。UDP 始终使用 XUDP，不受此开关影响。Pool 控制共享会话或独立连接的预备数量。保存后自动重建相关隧道，现有连接会断开。</p>
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
  <Modal ref="confirm" :title="action === 'delete' ? '删除映射' : pending?.enabled ? '停用映射' : '启用映射'" save-label="确认" :danger="action === 'delete'" :submit="run"><p>确认修改「{{ pending?.name }}」？现有连接可能断开。</p></Modal>
</template>
