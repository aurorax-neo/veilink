<script setup lang="ts">
import { computed, inject, reactive, ref, watch } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { endpoint, nodeName, validateMapping } from '../format'
import type { Mapping } from '../types'
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
const draft = reactive({ id: '', name: '', serverId: '', clientId: '', pool: 1, listenHost: '0.0.0.0', listenPort: '', targetHost: '', targetPort: '', network: 'tcp', enabled: true })
const defaultMuxType = 'smux'
const muxType = ref('')
watch(() => draft.network, network => { if (network !== 'tcp') muxType.value = '' }, { flush: 'sync' })
const servers = computed(() => desk.nodes.filter(n => n.role === 'server' && !n.revoked))
const clients = computed(() => desk.nodes.filter(n => n.role === 'client' && !n.revoked))
const rows = computed(() => desk.mappings.filter(m => (filter.value === 'all' || m.enabled === (filter.value === 'on')) && [m.name, m.listen_host, m.target_host, nodeName(desk.nodes, m.server_id), nodeName(desk.nodes, m.client_id)].join(' ').toLowerCase().includes(query.value.trim().toLowerCase())))
function fields(m: Mapping) {
  return { id: m.id, name: m.name, serverId: m.server_id, clientId: m.client_id, pool: m.pool || 1, listenHost: m.listen_host, listenPort: String(m.listen_port), targetHost: m.target_host, targetPort: String(m.target_port), network: m.network || 'tcp', enabled: m.enabled }
}
function open(mapping?: Mapping) {
  Object.assign(draft, mapping ? fields(mapping) : { id: '', name: '', serverId: servers.value[0]?.id || '', clientId: clients.value[0]?.id || '', pool: 1, listenHost: '0.0.0.0', listenPort: '', targetHost: '127.0.0.1', targetPort: '', network: 'tcp', enabled: true })
  muxType.value = draft.network === 'tcp' && mapping?.mux ? mapping.mux_type || defaultMuxType : ''
  editor.value?.open()
}
async function save() {
  const problem = validateMapping(draft, desk.nodes, desk.mappings, draft.id)
  if (problem) throw new Error(problem)
  await api(draft.id ? `/mappings/${encodeURIComponent(draft.id)}` : '/mappings', draft.id ? 'PUT' : 'POST', {
    name: draft.name.trim(), server_id: draft.serverId, client_id: draft.clientId, pool: draft.pool, mux: draft.network === 'tcp' && muxType.value !== '',
    mux_type: draft.network === 'tcp' ? muxType.value : '',
    listen_host: draft.listenHost.trim(), listen_port: Number(draft.listenPort), target_host: draft.targetHost.trim(), target_port: Number(draft.targetPort), network: draft.network, enabled: draft.enabled,
  })
  await desk.reload(); desk.notify('映射已保存。')
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
  await desk.reload(); desk.notify(action.value === 'delete' ? '映射已删除。' : '状态已更新。')
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
    <EmptyState v-if="!rows.length" title="暂无映射" text="新建映射或调整筛选。" />
    <div v-else class="panel table-scroll" tabindex="0" role="region" aria-label="映射列表">
      <table>
        <thead><tr><th scope="col">名称</th><th scope="col">服务端 → 客户端</th><th scope="col">路径</th><th scope="col">Pool</th><th scope="col">状态</th><th scope="col">操作</th></tr></thead>
        <tbody><tr v-for="mapping in rows" :key="mapping.id">
          <td><strong>{{ mapping.name }}</strong><Badge :text="(mapping.network || 'tcp').toUpperCase()" /></td>
          <td>{{ nodeName(desk.nodes, mapping.server_id) }}<small>→ {{ nodeName(desk.nodes, mapping.client_id) }}</small></td>
          <td><code>{{ endpoint(mapping.listen_host, mapping.listen_port) }}</code><small>→ <code>{{ endpoint(mapping.target_host, mapping.target_port) }}</code></small></td>
          <td>{{ mapping.pool || 1 }}<small>{{ mapping.network === 'udp' ? 'XUDP' : mapping.mux ? (mapping.mux_type || 'smux') : 'mux 关闭' }}</small></td><td><Badge :text="mapping.enabled ? '启用' : '停用'" :tone="mapping.enabled ? 'good' : ''" /></td>
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
