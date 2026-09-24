<script setup lang="ts">
import { computed, inject, reactive, ref } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { copyText, endpoint, needsAttention, presence, revisionState, seenText, validateNode } from '../format'
import type { Node, TunnelConfig } from '../types'
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

const draft = reactive({
  id: '',
  name: '',
  role: 'server',
  address: '',
  port: '443',
  serverName: '',
  transport: 'tls', // 'tls' | 'reality' | 'hysteria2'
  flow: '',
  enc: 'none',
  pool: '',
  realityDest: '',
  realityPrivateKey: '',
  realityPublicKey: '',
  realityShortIDs: '',
  realityServerNames: '',
  realityFingerprint: 'chrome',
  hysteria2Password: '',
})

function isReality(node?: Node | null): boolean {
  if (!node?.tunnel?.reality) return false
  const r = node.tunnel.reality
  return !!(r.dest || r.public_key || r.private_key || r.short_ids || r.short_id || r.server_names)
}

function transportLabel(node: Node): string {
  if (node.tunnel?.hysteria2?.password) return 'Hysteria2'
  if (isReality(node)) return 'REALITY'
  return '标准 TLS'
}

function transportTone(node: Node): '' | 'good' | 'warn' | 'bad' {
  if (node.tunnel?.hysteria2?.password) return 'good'
  if (isReality(node)) return 'good'
  return ''
}

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
  Object.assign(draft, {
    id: '',
    name: '',
    role: 'server',
    address: '',
    port: '443',
    serverName: '',
    transport: 'tls',
    flow: '',
    enc: 'none',
    pool: '',
    realityDest: '',
    realityPrivateKey: '',
    realityPublicKey: '',
    realityShortIDs: '',
    realityServerNames: '',
    realityFingerprint: 'chrome',
    hysteria2Password: '',
  })
  editor.value?.open()
}

function openEdit(node: Node) {
  let transport = 'tls'
  if (node.tunnel?.hysteria2?.password) {
    transport = 'hysteria2'
  } else if (isReality(node)) {
    transport = 'reality'
  }
  const isServer = node.role === 'server'
  Object.assign(draft, {
    id: node.id,
    name: node.name,
    role: node.role,
    address: node.address,
    port: String(node.port || 443),
    serverName: node.server_name,
    transport,
    flow: node.tunnel?.flow || '',
    enc: (isServer ? node.tunnel?.decryption : node.tunnel?.encryption) || 'none',
    pool: node.tunnel?.pool ? String(node.tunnel.pool) : '',
    realityDest: node.tunnel?.reality?.dest || '',
    realityPrivateKey: node.tunnel?.reality?.private_key || '',
    realityPublicKey: node.tunnel?.reality?.public_key || '',
    realityShortIDs: node.tunnel?.reality?.short_ids || node.tunnel?.reality?.short_id || '',
    realityServerNames: node.tunnel?.reality?.server_names || '',
    realityFingerprint: node.tunnel?.reality?.fingerprint || 'chrome',
    hysteria2Password: node.tunnel?.hysteria2?.password || '',
  })
  editor.value?.open()
}

async function saveNode() {
  const problem = validateNode(draft)
  if (problem) throw new Error(problem)
  const server = draft.role === 'server'
  const tunnel: TunnelConfig = {}
  if (draft.flow) {
    tunnel.flow = draft.flow
  }
  if (draft.enc && draft.enc !== 'none') {
    if (server) {
      tunnel.decryption = draft.enc
    } else {
      tunnel.encryption = draft.enc
    }
  }
  if (draft.pool && Number(draft.pool) > 0) {
    tunnel.pool = Number(draft.pool)
  }
  if (draft.transport === 'reality') {
    tunnel.reality = {
      dest: draft.realityDest.trim(),
      private_key: draft.realityPrivateKey.trim(),
      public_key: draft.realityPublicKey.trim(),
      short_ids: draft.realityShortIDs.trim(),
      server_names: draft.realityServerNames.trim(),
      fingerprint: draft.realityFingerprint.trim() || 'chrome',
    }
  } else if (draft.transport === 'hysteria2') {
    tunnel.hysteria2 = {
      password: draft.hysteria2Password.trim(),
    }
  }

  await api(draft.id ? `/nodes/${encodeURIComponent(draft.id)}` : '/nodes', draft.id ? 'PUT' : 'POST', {
    name: draft.name.trim(),
    role: draft.role,
    address: server ? draft.address.trim() : '',
    port: server ? Number(draft.port) : 0,
    server_name: server ? draft.serverName.trim() : '',
    tunnel,
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
                <th scope="col">传输</th>
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
                  <Badge :text="transportLabel(node)" :tone="transportTone(node)" />
                  <small v-if="node.tunnel?.flow" class="mono">{{ node.tunnel.flow }}</small>
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
          <div><dt>传输方式</dt><dd><Badge :text="transportLabel(selected)" :tone="transportTone(selected)" /></dd></div>
          <div v-if="selected.tunnel?.flow"><dt>流控模式</dt><dd class="mono">{{ selected.tunnel.flow }}</dd></div>
          <div v-if="selected.tunnel?.decryption || selected.tunnel?.encryption">
            <dt>数据加密</dt>
            <dd class="mono">{{ selected.role === 'server' ? '解密: ' + selected.tunnel.decryption : '加密: ' + selected.tunnel.encryption }}</dd>
          </div>
          <div v-if="selected.tunnel?.pool"><dt>连接池</dt><dd class="mono">{{ selected.tunnel.pool }} 路</dd></div>
          <template v-if="isReality(selected)">
            <div v-if="selected.tunnel?.reality?.dest"><dt>REALITY 目标</dt><dd class="mono">{{ selected.tunnel.reality.dest }}</dd></div>
            <div v-if="selected.tunnel?.reality?.public_key"><dt>REALITY 公钥</dt><dd class="mono" style="word-break: break-all;">{{ selected.tunnel.reality.public_key }}</dd></div>
            <div v-if="selected.tunnel?.reality?.short_ids || selected.tunnel?.reality?.short_id"><dt>Short ID</dt><dd class="mono">{{ selected.tunnel.reality.short_ids || selected.tunnel.reality.short_id }}</dd></div>
            <div v-if="selected.tunnel?.reality?.server_names"><dt>伪装域名</dt><dd class="mono">{{ selected.tunnel.reality.server_names }}</dd></div>
          </template>
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

      <p class="field-label" style="margin-top: 16px; font-weight: 600;">隧道传输与安全</p>
      
      <label for="node-transport">传输方式</label>
      <select id="node-transport" v-model="draft.transport">
        <option value="tls">标准 TLS (TCP 证书)</option>
        <option value="reality">REALITY 伪装 (无须域名证书)</option>
        <option value="hysteria2">Hysteria2 (QUIC UDP 传输)</option>
      </select>

      <div class="grid-2">
        <div>
          <label for="node-flow">流控模式 (Flow)</label>
          <select id="node-flow" v-model="draft.flow">
            <option value="">无 (普通 VLESS)</option>
            <option value="xtls-rprx-vision">xtls-rprx-vision</option>
          </select>
        </div>
        <div>
          <label for="node-enc">{{ draft.role === 'server' ? '解密算法' : '加密算法' }}</label>
          <select id="node-enc" v-model="draft.enc">
            <option value="none">none (标准)</option>
            <option value="xor">xor (对称混淆)</option>
          </select>
        </div>
      </div>

      <label for="node-pool">反向连接池容量 (Pool)</label>
      <input id="node-pool" v-model="draft.pool" type="number" min="0" max="64" placeholder="默认 0 (自动/单连接)" />
      <small class="help">并发反向连接池数量，客户端与服务端复用连接。</small>

      <template v-if="draft.transport === 'reality'">
        <p class="field-label" style="margin-top: 12px; font-weight: 600;">REALITY 伪装参数</p>
        <template v-if="draft.role === 'server'">
          <label for="reality-dest">回落目标 (Dest)</label>
          <input id="reality-dest" v-model="draft.realityDest" placeholder="例如 www.apple.com:443" />
          <small class="help">REALITY 握手探测失败时的转发目标地址与端口。</small>

          <label for="reality-priv">X25519 私钥 (Private Key)</label>
          <input id="reality-priv" v-model="draft.realityPrivateKey" type="password" placeholder="留空则保持现有私钥不变" />
          <small class="help">服务端的 REALITY 私钥。公钥会自动从该私钥推导并下发给客户端。</small>

          <label for="reality-short-ids">Short IDs</label>
          <input id="reality-short-ids" v-model="draft.realityShortIDs" placeholder="例如 0123456789abcdef (逗号分隔)" />

          <label for="reality-names">伪装域名 (Server Names)</label>
          <input id="reality-names" v-model="draft.realityServerNames" placeholder="例如 www.apple.com,gateway.icloud.com" />
        </template>
        <template v-else>
          <label for="reality-pub">X25519 公钥 (Public Key)</label>
          <input id="reality-pub" v-model="draft.realityPublicKey" placeholder="留空则自动从网关节点继承" />
          <small class="help">客户端连接使用的网关 REALITY 公钥（可留空继承）。</small>

          <label for="reality-short-id">Short ID</label>
          <input id="reality-short-id" v-model="draft.realityShortIDs" placeholder="留空则自动从网关节点继承" />

          <label for="reality-fp">客户端指纹 (Fingerprint)</label>
          <select id="reality-fp" v-model="draft.realityFingerprint">
            <option value="chrome">chrome</option>
            <option value="firefox">firefox</option>
            <option value="safari">safari</option>
            <option value="ios">ios</option>
            <option value="android">android</option>
            <option value="edge">edge</option>
            <option value="random">random</option>
          </select>
        </template>
      </template>

      <template v-if="draft.transport === 'hysteria2'">
        <p class="field-label" style="margin-top: 12px; font-weight: 600;">Hysteria2 QUIC 配置</p>
        <label for="hy2-pass">认证密码 (Password)</label>
        <input id="hy2-pass" v-model="draft.hysteria2Password" type="password" :placeholder="draft.role === 'client' ? '留空则自动从绑定的网关继承' : '输入共享认证密码'" />
        <small class="help">{{ draft.role === 'server' ? '网关与客户端之间 QUIC 握手的鉴权密码。' : '内网节点连接网关的鉴权密码。若留空则自动继承网关配置。' }}</small>
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
