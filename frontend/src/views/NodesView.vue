<script setup lang="ts">
import { computed, inject, reactive, ref } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { copyText, endpoint, needsAttention, presence, revisionState, seenText, validateNode } from '../format'
import type { Node } from '../types'
import Badge from '../components/Badge.vue'
import EmptyState from '../components/EmptyState.vue'
import Modal from '../components/Modal.vue'

const desk = inject(deskKey)!
const filter = ref<'all' | 'server' | 'client' | 'attention'>('all')
const query = ref('')
const selectedId = ref('')
const editor = ref<InstanceType<typeof Modal> | null>(null)
const confirm = ref<InstanceType<typeof Modal> | null>(null)
const enroll = ref<InstanceType<typeof Modal> | null>(null)
const token = ref('')
const tokenNode = ref<Node | null>(null)
const confirmText = ref('')
const confirmTitle = ref('')
const confirmLabel = ref('确认')
let confirmRun: () => Promise<void> = async () => {}

const draft = reactive({ id: '', name: '', role: 'server', address: '', port: '443', serverName: '' })

const rows = computed(() => {
  const q = query.value.trim().toLowerCase()
  return desk.nodes
    .filter((node) => {
      if (filter.value === 'server' && node.role !== 'server') return false
      if (filter.value === 'client' && node.role !== 'client') return false
      if (filter.value === 'attention' && !needsAttention(node)) return false
      if (!q) return true
      return [node.name, node.id, node.address, node.server_name, node.error].join(' ').toLowerCase().includes(q)
    })
    .sort((a, b) => Number(needsAttention(b)) - Number(needsAttention(a)) || a.name.localeCompare(b.name, 'zh-CN'))
})

const selected = computed(() => desk.nodes.find((node) => node.id === selectedId.value) || rows.value[0] || null)

function bindingCount(id: string) {
  return desk.bindings.filter((binding) => binding.server_id === id || binding.client_id === id).length
}

function openCreate() {
  Object.assign(draft, { id: '', name: '', role: 'server', address: '', port: '443', serverName: '' })
  editor.value?.open()
}

function openEdit(node: Node) {
  Object.assign(draft, {
    id: node.id,
    name: node.name,
    role: node.role,
    address: node.address,
    port: String(node.port || 443),
    serverName: node.server_name,
  })
  editor.value?.open()
}

async function saveNode() {
  const problem = validateNode(draft)
  if (problem) throw new Error(problem)
  const server = draft.role === 'server'
  await api(draft.id ? `/nodes/${encodeURIComponent(draft.id)}` : '/nodes', draft.id ? 'PUT' : 'POST', {
    name: draft.name.trim(),
    role: draft.role,
    address: server ? draft.address.trim() : '',
    port: server ? Number(draft.port) : 0,
    server_name: server ? draft.serverName.trim() : '',
  })
  await desk.reload()
  desk.notify(draft.id ? '节点已保存，等待节点应用配置。' : '节点已创建。接下来生成一次性注册令牌。')
  return true
}

function ask(title: string, text: string, label: string, run: () => Promise<void>) {
  confirmTitle.value = title
  confirmText.value = text
  confirmLabel.value = label
  confirmRun = run
  confirm.value?.open()
}

async function runConfirm() {
  await confirmRun()
  return true
}

function revoke(node: Node) {
  ask('吊销节点凭据', `确定吊销「${node.name}」？吊销后不能再注册或拉取配置。已经建立的数据连接不会立刻断开，要等网关应用到新配置。此操作不可撤销。`, '吊销', async () => {
    await api(`/nodes/${encodeURIComponent(node.id)}/revoke`, 'POST', {})
    await desk.reload()
    desk.notify('已提交吊销。')
  })
}

function remove(node: Node) {
  const count = bindingCount(node.id)
  ask('删除节点', `确定删除「${node.name}」？会同时移除它的 ${count} 条绑定，以及这些绑定上的映射。已经建立的连接不会因为这次点击立刻断开。此操作不可撤销。`, '删除', async () => {
    await api(`/nodes/${encodeURIComponent(node.id)}`, 'DELETE')
    if (selectedId.value === node.id) selectedId.value = ''
    await desk.reload()
    desk.notify('节点已删除。')
  })
}

function openEnroll(node: Node) {
  token.value = ''
  tokenNode.value = node
  enroll.value?.open()
}

async function issueToken() {
  if (!tokenNode.value) throw new Error('没有选中节点。')
  const result = await api<{ token?: string }>(`/nodes/${encodeURIComponent(tokenNode.value.id)}/enroll`, 'POST', { ttl_seconds: 3600 })
  if (!result?.token) throw new Error('管理中心没有返回令牌。')
  token.value = result.token
  return false
}

function closeEnroll() {
  token.value = ''
  tokenNode.value = null
}

async function copy(value: string) {
  try {
    await copyText(value)
    desk.notify('已复制。')
  } catch (reason) {
    desk.notify(reason instanceof Error ? reason.message : '无法复制。', true)
  }
}
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="正在读取节点" text="正在从管理中心获取最新列表。" />
  <EmptyState v-else-if="!desk.loaded" title="暂时无法读取节点" :text="(desk.error || '请求失败') + ' 未显示缓存或演示数据。'" />
  <div v-else class="stack">
    <div class="toolbar">
      <div class="chips" role="tablist" aria-label="节点筛选">
        <button type="button" :aria-selected="filter === 'all'" @click="filter = 'all'">全部 {{ desk.nodes.length }}</button>
        <button type="button" :aria-selected="filter === 'server'" @click="filter = 'server'">网关 {{ desk.nodes.filter((node) => node.role === 'server').length }}</button>
        <button type="button" :aria-selected="filter === 'client'" @click="filter = 'client'">内网 {{ desk.nodes.filter((node) => node.role === 'client').length }}</button>
        <button type="button" :aria-selected="filter === 'attention'" @click="filter = 'attention'">需处理 {{ desk.nodes.filter((node) => needsAttention(node)).length }}</button>
      </div>
      <input v-model="query" type="search" aria-label="搜索节点" placeholder="搜索名称、地址或 ID" />
      <button type="button" class="btn primary" @click="openCreate">新建节点</button>
    </div>
    <p class="legend">近期在线：未吊销，且 last_seen 距本机时钟不足 90 秒。时钟偏差会让这个判断失真。它不代表目标服务可达。</p>
    <div class="work">
      <section class="panel">
        <header class="panel-head"><h2>节点</h2><small>{{ rows.length }} 条</small></header>
        <EmptyState v-if="!rows.length" title="没有匹配的节点" text="换一个筛选，或新建公网网关与内网节点。" />
        <div v-else class="table-scroll" tabindex="0" role="region" aria-label="节点列表，可横向滚动">
          <table>
            <thead>
              <tr>
                <th scope="col">节点</th>
                <th scope="col">心跳</th>
                <th scope="col">版本</th>
                <th scope="col">绑定</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="node in rows" :key="node.id" :class="{ selected: selected?.id === node.id }" @click="selectedId = node.id">
                <td>
                  <strong>{{ node.name }}</strong>
                  <small>{{ node.role === 'server' ? 'SERVER' : 'CLIENT' }} · {{ node.id }}</small>
                </td>
                <td>
                  <Badge :text="presence(node).text" :tone="presence(node).tone" />
                  <small>{{ seenText(node.last_seen) }}</small>
                </td>
                <td>
                  <div class="mono">r{{ node.desired_revision }} / r{{ node.applied_revision }}</div>
                  <Badge :text="revisionState(node).text" :tone="revisionState(node).tone" />
                </td>
                <td class="mono">{{ bindingCount(node.id) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
      <aside v-if="selected" class="detail" aria-live="polite">
        <p class="kicker">{{ selected.role === 'server' ? '公网网关' : '内网节点' }}</p>
        <h2>{{ selected.name }}</h2>
        <dl>
          <div><dt>ID</dt><dd><code>{{ selected.id }}</code><button type="button" class="btn small" @click="copy(selected.id)">复制</button></dd></div>
          <div><dt>心跳</dt><dd>{{ presence(selected).text }} · {{ seenText(selected.last_seen) }}</dd></div>
          <div><dt>版本</dt><dd>期望 r{{ selected.desired_revision }} / 已应用 r{{ selected.applied_revision }}</dd></div>
          <div v-if="selected.role === 'server'"><dt>数据面</dt><dd class="mono">{{ endpoint(selected.address, selected.port) }}</dd></div>
          <div v-if="selected.role === 'server'"><dt>TLS 名称</dt><dd class="mono">{{ selected.server_name }}</dd></div>
          <div><dt>绑定</dt><dd>{{ bindingCount(selected.id) }} 条</dd></div>
        </dl>
        <p v-if="selected.error" class="detail-error">{{ selected.error }}</p>
        <div class="actions">
          <button type="button" class="btn small" :disabled="selected.revoked" @click="openEdit(selected)">编辑</button>
          <button type="button" class="btn small" :disabled="selected.revoked" @click="openEnroll(selected)">注册令牌</button>
          <button type="button" class="btn small danger" :disabled="selected.revoked" @click="revoke(selected)">吊销</button>
          <button type="button" class="btn small danger" @click="remove(selected)">删除</button>
        </div>
      </aside>
    </div>
    <Modal ref="editor" :title="draft.id ? '编辑节点' : '新建节点'" :submit="saveNode">
      <label for="node-name">节点名称</label>
      <input id="node-name" v-model="draft.name" maxlength="128" required />
      <label for="node-role">角色</label>
      <select id="node-role" v-model="draft.role" :disabled="!!draft.id">
        <option value="server">公网网关 · Server</option>
        <option value="client">内网节点 · Client</option>
      </select>
      <template v-if="draft.role === 'server'">
        <label for="node-address">网关地址</label>
        <input id="node-address" v-model="draft.address" spellcheck="false" required />
        <small class="help">内网节点要连接的域名或 IP，不要写协议和端口。</small>
        <label for="node-port">VLESS 端口</label>
        <input id="node-port" v-model="draft.port" inputmode="numeric" required />
        <label for="node-sni">TLS 服务器名称</label>
        <input id="node-sni" v-model="draft.serverName" spellcheck="false" required />
        <small class="help">要和网关证书一致。REALITY 时，这也是客户端发送的伪装 SNI。证书和密钥只放在节点本机。</small>
      </template>
    </Modal>
    <Modal ref="confirm" :title="confirmTitle" save-label="确认" :submit="runConfirm" danger :kicker="confirmLabel">
      <p class="lead">{{ confirmText }}</p>
    </Modal>
    <Modal ref="enroll" :title="token ? '令牌只显示这一次' : '生成一次性注册令牌'" :save-label="'生成令牌'" :hide-save="!!token" :submit="issueToken" kicker="注册" @close="closeEnroll">
      <template v-if="!token">
        <p class="lead">为「{{ tokenNode?.name }}」生成 1 小时内有效的一次性令牌。关闭窗口后不能再查看，也不会写入浏览器存储。</p>
      </template>
      <template v-else>
        <p class="callout">请立刻写进该节点的本地配置。不要提交到版本库，也不要打进日志。</p>
        <p class="field-label">node_id</p>
        <pre class="secret">{{ tokenNode?.id }}</pre>
        <p class="field-label">enroll_token</p>
        <pre class="secret">{{ token }}</pre>
        <button type="button" class="btn small" @click="copy(token)">复制令牌</button>
      </template>
    </Modal>
  </div>
</template>
