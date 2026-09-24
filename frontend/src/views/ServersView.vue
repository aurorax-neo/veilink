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
const query = ref('')
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

const servers = computed(() => {
  const q = query.value.trim().toLowerCase()
  return desk.nodes
    .filter((node) => {
      if (node.role !== 'server') return false
      if (!q) return true
      return [node.name, node.id, node.address, node.server_name, node.error].join(' ').toLowerCase().includes(q)
    })
    .sort((a, b) => Number(needsAttention(b)) - Number(needsAttention(a)) || a.name.localeCompare(b.name, 'zh-CN'))
})

function bindingCount(id: string) {
  return desk.bindings.filter((b) => b.server_id === id).length
}

function boundClients(serverId: string): string[] {
  return desk.bindings
    .filter((b) => b.server_id === serverId)
    .map((b) => {
      const c = desk.nodes.find((n) => n.id === b.client_id)
      return c?.name || b.client_id
    })
}

function serverMappings(serverId: string) {
  const bindingIds = new Set(desk.bindings.filter((b) => b.server_id === serverId).map((b) => b.id))
  return desk.mappings.filter((m) => bindingIds.has(m.binding_id))
}

function openCreate() {
  Object.assign(draft, {
    id: '', name: '', role: 'server', address: '', port: '443', serverName: '',
    transport: 'tls', flow: '', enc: 'none', pool: '',
    realityDest: '', realityPrivateKey: '', realityPublicKey: '',
    realityShortIDs: '', realityServerNames: '', realityFingerprint: 'chrome', hysteria2Password: '',
  })
  editor.value?.open()
}

function openEdit(node: Node) {
  let transport = 'tls'
  if (node.tunnel?.hysteria2?.password) transport = 'hysteria2'
  else if (isReality(node)) transport = 'reality'
  Object.assign(draft, {
    id: node.id, name: node.name, role: node.role,
    address: node.address, port: String(node.port || 443), serverName: node.server_name,
    transport,
    flow: node.tunnel?.flow || '',
    enc: node.tunnel?.decryption || 'none',
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
  const tunnel: TunnelConfig = {}
  if (draft.flow) tunnel.flow = draft.flow
  if (draft.enc && draft.enc !== 'none') tunnel.decryption = draft.enc
  if (draft.pool && Number(draft.pool) > 0) tunnel.pool = Number(draft.pool)
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
    tunnel.hysteria2 = { password: draft.hysteria2Password.trim() }
  }
  await api(draft.id ? `/nodes/${encodeURIComponent(draft.id)}` : '/nodes', draft.id ? 'PUT' : 'POST', {
    name: draft.name.trim(), role: 'server',
    address: draft.address.trim(), port: Number(draft.port), server_name: draft.serverName.trim(),
    tunnel,
  })
  await desk.reload()
  desk.notify(draft.id ? '节点已保存，等待节点应用配置。' : '节点已创建。接下来生成一次性注册令牌。')
  return true
}

function ask(title: string, text: string, label: string, run: () => Promise<void>) {
  confirmTitle.value = title; confirmText.value = text; confirmLabel.value = label; confirmRun = run
  confirm.value?.open()
}

async function runConfirm() { await confirmRun(); return true }

function revoke(node: Node) {
  ask('吊销节点凭据', `确定吊销「${node.name}」？吊销后不能再注册或拉取配置。已经建立的数据连接不会立刻断开，要等网关应用到新配置。此操作不可撤销。`, '吊销', async () => {
    await api(`/nodes/${encodeURIComponent(node.id)}/revoke`, 'POST', {})
    await desk.reload(); desk.notify('已提交吊销。')
  })
}

function remove(node: Node) {
  const count = bindingCount(node.id)
  ask('删除节点', `确定删除「${node.name}」？会同时移除它的 ${count} 条绑定，以及这些绑定上的映射。此操作不可撤销。`, '删除', async () => {
    await api(`/nodes/${encodeURIComponent(node.id)}`, 'DELETE')
    await desk.reload(); desk.notify('节点已删除。')
  })
}

function openEnroll(node: Node) {
  token.value = ''; tokenNode.value = node; enroll.value?.open()
}

async function issueToken() {
  if (!tokenNode.value) throw new Error('没有选中节点。')
  const result = await api<{ token?: string }>(`/nodes/${encodeURIComponent(tokenNode.value.id)}/enroll`, 'POST', { ttl_seconds: 3600 })
  if (!result?.token) throw new Error('管理中心没有返回令牌。')
  token.value = result.token; return false
}

function closeEnroll() { token.value = ''; tokenNode.value = null }

async function copy(value: string) {
  try { await copyText(value); desk.notify('已复制。') }
  catch (reason) { desk.notify(reason instanceof Error ? reason.message : '无法复制。', true) }
}
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="正在读取节点" text="正在从管理中心获取最新列表。" />
  <EmptyState v-else-if="!desk.loaded" title="暂时无法读取节点" :text="(desk.error || '请求失败') + ' 未显示缓存或演示数据。'" />
  <div v-else class="stack">
    <div class="toolbar">
      <input v-model="query" type="search" aria-label="搜索服务端" placeholder="搜索名称、地址或 ID" />
      <button type="button" class="btn primary" @click="openCreate">新建服务端</button>
    </div>

    <EmptyState v-if="!servers.length" title="没有匹配的服务端" text="换一个搜索词，或新建公网网关节点。" />
    <div v-else class="node-cards">
      <article v-for="node in servers" :key="node.id" class="node-card panel">
        <header>
          <div>
            <strong style="font-size: 16px;">{{ node.name }}</strong>
            <Badge :text="presence(node).text" :tone="presence(node).tone" />
          </div>
          <Badge :text="revisionState(node).text" :tone="revisionState(node).tone" />
        </header>
        <dl class="node-meta">
          <div v-if="node.address"><dt>数据面地址</dt><dd class="mono">{{ endpoint(node.address, node.port) }}</dd></div>
          <div v-if="node.server_name"><dt>TLS 名称</dt><dd class="mono">{{ node.server_name }}</dd></div>
          <div><dt>传输</dt><dd><Badge :text="transportLabel(node)" :tone="transportTone(node)" /></dd></div>
          <div v-if="node.tunnel?.flow"><dt>流控</dt><dd class="mono">{{ node.tunnel.flow }}</dd></div>
          <div v-if="node.tunnel?.decryption && node.tunnel.decryption !== 'none'"><dt>解密</dt><dd class="mono">{{ node.tunnel.decryption }}</dd></div>
          <div v-if="node.tunnel?.pool"><dt>连接池</dt><dd class="mono">{{ node.tunnel.pool }} 路</dd></div>
          <div><dt>绑定客户端</dt><dd>{{ bindingCount(node.id) }} 个 <template v-if="boundClients(node.id).length">· {{ boundClients(node.id).join(', ') }}</template></dd></div>
          <div><dt>映射</dt><dd>{{ serverMappings(node.id).length }} 条（{{ serverMappings(node.id).filter((m) => m.enabled).length }} 启用）</dd></div>
          <div><dt>心跳</dt><dd>{{ seenText(node.last_seen) }}</dd></div>
        </dl>
        <div class="node-tags">
          <Badge v-if="node.tunnel?.hysteria2?.password" text="QUIC" tone="good" />
          <Badge v-if="isReality(node)" text="REALITY" tone="good" />
        </div>
        <p v-if="node.error" class="detail-error">{{ node.error }}</p>
        <footer>
          <button type="button" class="btn small" :disabled="node.revoked" @click="openEdit(node)">编辑</button>
          <button type="button" class="btn small" :disabled="node.revoked" @click="openEnroll(node)">注册令牌</button>
          <button type="button" class="btn small danger" :disabled="node.revoked" @click="revoke(node)">吊销</button>
          <button type="button" class="btn small danger" @click="remove(node)">删除</button>
        </footer>
      </article>
    </div>

    <Modal ref="editor" :title="draft.id ? '编辑服务端' : '新建服务端'" :submit="saveNode">
      <label for="srv-name">节点名称</label>
      <input id="srv-name" v-model="draft.name" maxlength="128" required />
      <label for="srv-address">网关地址</label>
      <input id="srv-address" v-model="draft.address" spellcheck="false" required />
      <small class="help">内网节点要连接的域名或 IP，不要写协议和端口。</small>
      <label for="srv-port">VLESS 端口</label>
      <input id="srv-port" v-model="draft.port" inputmode="numeric" required />
      <label for="srv-sni">TLS 服务器名称</label>
      <input id="srv-sni" v-model="draft.serverName" spellcheck="false" required />
      <small class="help">要和网关证书一致。REALITY 时，这也是客户端发送的伪装 SNI。</small>

      <p class="field-label" style="margin-top: 16px; font-weight: 600;">隧道传输与安全</p>
      <label for="srv-transport">传输方式</label>
      <select id="srv-transport" v-model="draft.transport">
        <option value="tls">标准 TLS (TCP 证书)</option>
        <option value="reality">REALITY 伪装 (无须域名证书)</option>
        <option value="hysteria2">Hysteria2 (QUIC UDP 传输)</option>
      </select>
      <div class="grid-2">
        <div>
          <label for="srv-flow">流控模式 (Flow)</label>
          <select id="srv-flow" v-model="draft.flow">
            <option value="">无 (普通 VLESS)</option>
            <option value="xtls-rprx-vision">xtls-rprx-vision</option>
          </select>
        </div>
        <div>
          <label for="srv-enc">解密算法</label>
          <select id="srv-enc" v-model="draft.enc">
            <option value="none">none (标准)</option>
            <option value="xor">xor (对称混淆)</option>
          </select>
        </div>
      </div>
      <label for="srv-pool">反向连接池容量 (Pool)</label>
      <input id="srv-pool" v-model="draft.pool" type="number" min="0" max="64" placeholder="默认 0 (自动/单连接)" />

      <template v-if="draft.transport === 'reality'">
        <p class="field-label" style="margin-top: 12px; font-weight: 600;">REALITY 伪装参数</p>
        <label for="srv-reality-dest">回落目标 (Dest)</label>
        <input id="srv-reality-dest" v-model="draft.realityDest" placeholder="例如 www.apple.com:443" />
        <small class="help">REALITY 握手探测失败时的转发目标地址与端口。</small>
        <label for="srv-reality-priv">X25519 私钥 (Private Key)</label>
        <input id="srv-reality-priv" v-model="draft.realityPrivateKey" type="password" placeholder="留空则保持现有私钥不变" />
        <label for="srv-reality-short-ids">Short IDs</label>
        <input id="srv-reality-short-ids" v-model="draft.realityShortIDs" placeholder="例如 0123456789abcdef (逗号分隔)" />
        <label for="srv-reality-names">伪装域名 (Server Names)</label>
        <input id="srv-reality-names" v-model="draft.realityServerNames" placeholder="例如 www.apple.com,gateway.icloud.com" />
      </template>

      <template v-if="draft.transport === 'hysteria2'">
        <p class="field-label" style="margin-top: 12px; font-weight: 600;">Hysteria2 QUIC 配置</p>
        <label for="srv-hy2-pass">认证密码 (Password)</label>
        <input id="srv-hy2-pass" v-model="draft.hysteria2Password" type="password" placeholder="输入共享认证密码" />
        <small class="help">网关与客户端之间 QUIC 握手的鉴权密码。</small>
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
