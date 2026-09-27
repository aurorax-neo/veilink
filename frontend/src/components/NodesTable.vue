<script setup lang="ts">
import { computed, inject, ref } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { endpoint, needsAttention, presence, revisionState, seenText } from '../format'
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
const rows = computed(() => desk.nodes.filter(n => n.role === props.role && [n.name, n.id, n.address, n.error].join(' ').toLowerCase().includes(query.value.trim().toLowerCase())).sort((a, b) => Number(needsAttention(b)) - Number(needsAttention(a)) || a.name.localeCompare(b.name, 'zh-CN')))
const selected = computed(() => desk.nodes.find(n => n.id === selectedId.value))
function mappings(id: string) { return desk.mappings.filter(m => props.role === 'server' ? m.server_id === id : m.client_id === id) }
function effectiveSources(node: Node) {
  const ids = new Set(desk.mappings.filter(m => m.client_id === node.id).map(m => m.server_id))
  return node.revoked ? [] : desk.nodes.filter(n => n.role === 'server' && !n.revoked && ids.has(n.id))
}
function tunnelLabel(node: Node) {
  if (props.role === 'client') return effectiveSources(node).length ? '服务端统一下发' : '未关联服务端'
  const t = node.tunnel
  const enc = t?.decryption
  const additive = enc && enc !== 'none' ? ' + Encryption' : ''
  if (t?.xhttp?.path) return `XHTTP / packet-up · 连接 ${t.xhttp.tls ? 'HTTPS' : 'HTTP'} · 回源 ${t.transport_security === 'tls' ? 'HTTPS' : 'HTTP'}${additive}`
  if (t?.hysteria2?.password) return `Hysteria2 / TLS${additive}`
  if (t?.reality && Object.values(t.reality).some(Boolean)) return `TCP / REALITY${additive}`
  if (t?.transport_security === 'plain') return 'TCP / Encryption'
  if (t?.transport_security === 'tls') return `TCP / TLS${additive}`
  return '未配置安全模式'
}
function localListen(node: Node) { return endpoint(node.tunnel?.listen_host || '127.0.0.1', node.tunnel?.listen_port || 0) }
function connectList(node: Node) { return (node.connect_endpoints || []).filter(item => item.enabled) }
function openConfig(node: Node) { configNode.value = node; configModal.value?.open() }
async function saved() { await desk.reload(); desk.notify('节点已保存。') }
function ask(node: Node, operation: 'revoke' | 'delete') { if (node.embedded) return; pending.value = node; action.value = operation; confirm.value?.open() }
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
      <table class="nodes-table">
        <thead><tr><th scope="col">名称 / 软件版本</th><th scope="col">状态</th><th scope="col">本地监听 / 客户端连接地址</th><th scope="col">隧道</th><th scope="col">映射</th><th scope="col">配置修订</th><th scope="col">操作</th></tr></thead>
        <tbody><tr v-for="node in rows" :key="node.id" :class="{ selected: selectedId === node.id }">
          <td><button type="button" class="text-btn" :aria-expanded="selectedId === node.id" @click="selectedId = selectedId === node.id ? '' : node.id">{{ node.name }}</button><small class="node-id" :title="node.id">{{ node.id }}</small><small v-if="node.embedded">内置节点</small><small class="software-version" :title="node.software_version || '等待节点上报运行版本'">软件：{{ node.software_version || '未上报' }}</small></td>
          <td><Badge :text="presence(node).text" :tone="presence(node).tone" /></td>
          <td><template v-if="role === 'server'"><small>监听：{{ localListen(node) }} · {{ node.tunnel?.hysteria2?.password ? 'UDP' : 'TCP' }}</small><small v-for="item in connectList(node)" :key="item.id">{{ item.name }} · {{ endpoint(item.host, item.port) }}</small></template><template v-else>—</template></td>
          <td>{{ tunnelLabel(node) }}</td><td>{{ mappings(node.id).length }}</td>
          <td><Badge :text="revisionState(node).text" :tone="revisionState(node).tone" /><small>期望 r{{ node.desired_revision }}</small><small>已应用 r{{ node.applied_revision }}</small></td>
          <td><div class="actions"><button type="button" class="btn small" :disabled="node.revoked" @click="editor?.open(node)">编辑</button><button v-if="role === 'client'" type="button" class="btn small" :disabled="node.revoked || !effectiveSources(node).length" @click="openConfig(node)">查看配置</button><button v-if="!node.embedded" type="button" class="btn small" :disabled="node.revoked" @click="onboarding?.open(node)">快捷接入</button><button v-if="!node.embedded" type="button" class="btn small danger" @click="ask(node, 'delete')">删除</button></div></td>
        </tr></tbody>
      </table>
    </div>
    <section v-if="selected" class="node-detail" aria-label="节点详情">
      <header class="panel-head"><h2>{{ selected.name }}</h2><button class="btn quiet" type="button" @click="selectedId = ''">收起</button></header>
      <dl class="detail-grid"><div><dt>ID</dt><dd><code>{{ selected.id }}</code></dd></div><div><dt>心跳</dt><dd>{{ seenText(selected.last_seen) }}</dd></div></dl>
      <dl class="detail-grid"><div><dt>软件版本（节点上报，未验真）</dt><dd>{{ selected.software_version || '未上报' }}</dd></div><div><dt>构建提交（节点上报）</dt><dd><code>{{ selected.software_commit || '未上报' }}</code></dd></div></dl>
      <p class="help">上报信息不等于二进制验真。请通过可信 Docker 管理通道运行 tools/verify-node.py，对照独立可信的发布 SHA-256、实际运行文件与管理 API；结果仅代表核验时刻。</p>
      <p v-if="selected.error" class="detail-error" role="status">{{ selected.error }}</p>
      <p v-if="selected.embedded" class="help">内置节点由管理中心维护；支持编辑配置，不支持快捷接入、吊销或删除。</p>
      <div v-if="!selected.embedded" class="actions"><button class="btn" type="button" :disabled="selected.revoked" @click="onboarding?.open(selected)">快捷接入</button><button class="btn danger" type="button" :disabled="selected.revoked" @click="ask(selected, 'revoke')">吊销节点</button></div>
    </section>
  </div>
  <NodeEditor ref="editor" :role="role" :saved="saved" />
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
