<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted, ref } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { byNameAndId, endpoint, needsAttention, presence, revisionState, seenText } from '../format'
import type { Node } from '../types'
import Badge from './Badge.vue'
import EmptyState from './EmptyState.vue'
import Modal from './Modal.vue'
import NodeEditor from './NodeEditor.vue'
import NodeOnboarding from './NodeOnboarding.vue'

const props = defineProps<{ role: 'server' | 'client' }>()
const desk = inject(deskKey)!
const query = ref('')
const selectedId = ref('')
const editor = ref<InstanceType<typeof NodeEditor> | null>(null)
const onboarding = ref<InstanceType<typeof NodeOnboarding> | null>(null)
const confirm = ref<InstanceType<typeof Modal> | null>(null)
const pending = ref<Node | null>(null)
const configModal = ref<InstanceType<typeof Modal> | null>(null)
const configNode = ref<Node | null>(null)
const action = ref<'revoke' | 'delete'>('delete')
const label = computed(() => props.role === 'server' ? '服务端' : '客户端')
const refreshing = ref(new Set<string>())
const refreshFeedback = ref<Record<string, { text: string; bad: boolean }>>({})
let active = true
const now = ref(Date.now())
let clockTimer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  clockTimer = setInterval(() => { now.value = Date.now() }, 1000)
})
onUnmounted(() => {
  active = false
  if (clockTimer) clearInterval(clockTimer)
  clockTimer = undefined
})
const defaultName = computed(() => {
  const used = new Set(desk.nodes.filter(node => node.role === props.role).map(node => node.name.trim()))
  let number = 1
  while (used.has(String(number))) number++
  return String(number)
})
const rows = computed(() => desk.nodes.filter(n => n.role === props.role && [n.name, n.id, n.address, n.error].join(' ').toLowerCase().includes(query.value.trim().toLowerCase())).sort((a, b) => Number(needsAttention(b, now.value)) - Number(needsAttention(a, now.value)) || byNameAndId(a, b)))
const selected = computed(() => desk.nodes.find(n => n.id === selectedId.value))
function mappings(id: string) { return desk.mappings.filter(m => props.role === 'server' ? m.server_id === id : m.client_id === id) }
function effectiveSources(node: Node) {
  const ids = new Set(desk.mappings.filter(m => m.client_id === node.id).map(m => m.server_id))
  return node.revoked ? [] : desk.nodes.filter(n => n.role === 'server' && !n.revoked && ids.has(n.id)).sort(byNameAndId)
}
function tunnelLabel(node: Node) {
  const t = node.tunnel
  const protocol = t?.protocol || (t?.hysteria2?.password ? 'hysteria2' : 'vless')
  const enc = protocol === 'vless' ? t?.decryption : ''
  const additive = enc && enc !== 'none' ? ' + Encryption' : ''
  if (protocol === 'hysteria2') return 'Hysteria2 / QUIC + TLS'
  if (t?.xhttp?.path) return `VLESS / XHTTP · ${t.xhttp.mode || 'packet-up'} · 连接 ${t.xhttp.tls ? 'HTTPS' : 'HTTP'} · 回源 ${t.transport_security === 'tls' ? 'HTTPS' : 'HTTP'}${additive}`
  if (t?.reality && Object.values(t.reality).some(Boolean)) return `VLESS / TCP · REALITY${additive}`
  if (t?.transport_security === 'plain') return `VLESS / TCP · Encryption`
  if (t?.transport_security === 'tls') return `VLESS / TCP · TLS${additive}`
  return '未配置安全模式'
}
function localListen(node: Node) { return endpoint(node.tunnel?.listen_host || '127.0.0.1', node.tunnel?.listen_port || 0) }
function connectList(node: Node) { return (node.connect_endpoints || []).filter(item => item.enabled) }
function openConfig(node: Node) { configNode.value = node; configModal.value?.open() }
async function saved() { await desk.reload(); desk.notify('节点已保存，配置等待节点上报确认应用状态。') }
function ask(node: Node, operation: 'revoke' | 'delete') { if (node.embedded) return; pending.value = node; action.value = operation; confirm.value?.open() }
function revisionLabel(node: Node) {
  if (node.revoked) return '不再同步'
  if (node.error) return '应用失败'
  if (!node.desired_revision) return '尚无配置'
  if (!node.last_seen && !node.applied_revision) return '未上报'
  return node.applied_revision === node.desired_revision ? '最新' : '未同步'
}
function revisionDescription(node: Node) {
  if (!node.revoked && !node.last_seen && !node.applied_revision && node.desired_revision) return '节点尚未上报心跳；请检查节点容器日志、Master 地址和网络连通性'
  return `${revisionLabel(node)}；配置是否最新以节点上报为准，在线状态另见状态列`
}
function setRefreshing(id: string, busy: boolean) {
  const next = new Set(refreshing.value)
  if (busy) next.add(id); else next.delete(id)
  refreshing.value = next
}
async function refreshNode(node: Node) {
  if (!active || node.revoked || refreshing.value.has(node.id)) return
  setRefreshing(node.id, true)
  delete refreshFeedback.value[node.id]
  try {
    const result = await api<{ connected: boolean }>(`/nodes/${encodeURIComponent(node.id)}/refresh`, 'POST', {})
    if (!active) return
    if (!result || typeof result.connected !== 'boolean') throw new Error('刷新响应无效，请重试。')
    await desk.reloadNodes(node.id)
    if (!active) return
    refreshFeedback.value[node.id] = {
      text: result.connected ? '已请求上报，等待节点反馈' : '推送通道未连接，重连后自动同步',
      bad: false,
    }
  } catch (error) {
    if (active) refreshFeedback.value[node.id] = { text: error instanceof Error ? error.message : '请求节点更新状态失败，请稍后重试。', bad: true }
  } finally {
    setRefreshing(node.id, false)
  }
}
async function run() {
  if (!pending.value || pending.value.embedded) return false
  const path = `/nodes/${encodeURIComponent(pending.value.id)}`
  await api(action.value === 'revoke' ? `${path}/revoke` : path, action.value === 'revoke' ? 'POST' : 'DELETE', action.value === 'revoke' ? {} : undefined)
  await desk.reload()
  desk.notify(action.value === 'revoke' ? '节点已吊销。' : '节点已删除。')
  return true
}
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="加载中…" text="" />
  <EmptyState v-else-if="!desk.loaded" title="加载失败" :text="desk.error" />
  <div v-else class="stack">
    <div class="toolbar">
      <input v-model="query" type="search" :aria-label="`搜索${label}`" placeholder="搜索名称、地址或 ID" />
      <button class="btn primary" type="button" @click="editor?.open()">新建{{ label }}</button>
    </div>
    <EmptyState v-if="!rows.length" title="暂无节点" text="新建节点或调整搜索。" />
    <div v-else class="panel table-scroll" tabindex="0" role="region" :aria-label="`${label}列表`">
      <table class="nodes-table" :class="{ 'nodes-table-client': role === 'client' }">
        <thead><tr><th scope="col">名称 / 软件版本</th><th scope="col">状态</th><th v-if="role === 'server'" scope="col">本地监听 / 客户端连接地址</th><th v-if="role === 'server'" scope="col">隧道</th><th scope="col">映射</th><th scope="col">配置是否最新</th><th scope="col">操作</th></tr></thead>
        <tbody><tr v-for="node in rows" :key="node.id" :class="{ selected: selectedId === node.id }">
          <td><button type="button" class="text-btn" :aria-expanded="selectedId === node.id" @click="selectedId = selectedId === node.id ? '' : node.id">{{ node.name }}</button><small class="node-id" :title="node.id">{{ node.id }}</small><small v-if="node.embedded">内置节点</small><small class="software-version" :title="node.software_version || '等待节点上报运行版本'">软件：{{ node.software_version || '未上报' }}</small></td>
          <td><div class="node-presence"><Badge :text="presence(node, now).text" :tone="presence(node, now).tone" /><button type="button" class="icon-btn refresh-node" :disabled="node.revoked || refreshing.has(node.id)" @click="refreshNode(node)" :class="{ spinning: refreshing.has(node.id) }" :aria-busy="refreshing.has(node.id)" title="请求节点刷新状态" :aria-label="`刷新节点 ${node.name}`"><span aria-hidden="true">↻</span></button></div><small class="last-seen">最后在线：{{ seenText(node.last_seen, now) }}</small><span v-if="refreshFeedback[node.id]" class="node-refresh-feedback" :class="{ bad: refreshFeedback[node.id]!.bad }" role="status">{{ refreshFeedback[node.id]!.text }}</span></td>
          <td v-if="role === 'server'"><small>监听：{{ localListen(node) }} · {{ node.tunnel?.protocol === 'hysteria2' || node.tunnel?.hysteria2?.password ? 'UDP' : 'TCP' }}</small><small v-for="item in connectList(node)" :key="item.id">{{ item.name }} · {{ endpoint(item.host, item.port) }}</small></td>
          <td v-if="role === 'server'">{{ tunnelLabel(node) }}</td><td>{{ mappings(node.id).length }}</td>
          <td><div class="revision-status" role="group" :title="revisionDescription(node)" :aria-label="revisionDescription(node)"><Badge :text="revisionLabel(node)" :tone="revisionState(node).tone" /></div></td>
          <td><div class="actions"><button type="button" class="btn small" :disabled="node.revoked" @click="editor?.open(node)">编辑</button><button v-if="role === 'client'" type="button" class="btn small" :disabled="node.revoked || !effectiveSources(node).length" @click="openConfig(node)">查看配置</button><button v-if="!node.embedded" type="button" class="btn small" :disabled="node.revoked" @click="onboarding?.open(node)">快捷接入</button><button v-if="!node.embedded" type="button" class="btn small danger" @click="ask(node, 'delete')">删除</button></div></td>
        </tr></tbody>
      </table>
    </div>
    <section v-if="selected" class="node-detail" aria-label="节点详情">
      <header class="panel-head"><h2>{{ selected.name }}</h2><button class="btn quiet" type="button" @click="selectedId = ''">收起</button></header>
      <dl class="detail-grid"><div><dt>ID</dt><dd><code>{{ selected.id }}</code></dd></div><div><dt>心跳</dt><dd>{{ seenText(selected.last_seen, now) }}</dd></div></dl>
      <dl class="detail-grid"><div><dt>软件版本（节点上报，未验真）</dt><dd>{{ selected.software_version || '未上报' }}</dd></div><div><dt>构建提交（节点上报）</dt><dd><code>{{ selected.software_commit || '未上报' }}</code></dd></div></dl>
      <p class="help">上报信息不等于二进制验真。请通过可信 Docker 管理通道运行 tools/verify-node.py，对照独立可信的发布 SHA-256、实际运行文件与管理 API；结果仅代表核验时刻。</p>
      <p v-if="selected.error" class="detail-error" role="status">{{ selected.error }}</p>
      <p v-if="selected.embedded" class="help">内置节点由管理中心维护；支持编辑配置，不支持快捷接入、吊销或删除。</p>
      <div v-if="!selected.embedded" class="actions"><button class="btn" type="button" :disabled="selected.revoked" @click="onboarding?.open(selected)">快捷接入</button><button class="btn danger" type="button" :disabled="selected.revoked" @click="ask(selected, 'revoke')">吊销节点</button></div>
    </section>
  </div>
  <NodeEditor ref="editor" :role="role" :saved="saved" :default-name="defaultName" />
  <NodeOnboarding ref="onboarding" />
  <Modal ref="confirm" :title="action === 'revoke' ? '吊销节点' : '删除节点'" save-label="确认" danger :submit="run">
    <p v-if="action === 'revoke'">吊销「{{ pending?.name }}」的节点凭据？此操作不可撤销。</p>
    <p v-else>删除「{{ pending?.name }}」及其 {{ pending ? mappings(pending.id).length : 0 }} 条映射？此操作不可撤销。</p>
  </Modal>
  <Modal ref="configModal" title="有效隧道配置（只读）" :hide-save="true">
    <p class="help">由映射服务端自动派生并统一下发。此处为期望配置，实际应用状态请查看节点的配置修订；rN 不是软件版本。</p>
    <p v-if="!configNode || !effectiveSources(configNode).length" class="help">未关联可用服务端，暂无下发配置。</p>
    <div v-for="source in configNode ? effectiveSources(configNode) : []" :key="source.id">
      <label :for="`effective-modal-${source.id}`">来源：{{ source.name }} · {{ endpoint(source.address, source.port) }}</label>
      <textarea :id="`effective-modal-${source.id}`" class="mono" :value="source.client_tunnel ? JSON.stringify(source.client_tunnel, null, 2) : '服务端尚无下发模板'" readonly rows="10" :spellcheck="false" />
    </div>
  </Modal>
</template>
