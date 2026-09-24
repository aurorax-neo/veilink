<script setup lang="ts">
import { computed, inject, reactive, ref } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { copyText, needsAttention, nodeName, presence, revisionState, seenText, validateNode } from '../format'
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
  role: 'client',
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

const clients = computed(() => {
  const q = query.value.trim().toLowerCase()
  return desk.nodes
    .filter((node) => {
      if (node.role !== 'client') return false
      if (!q) return true
      return [node.name, node.id, node.error].join(' ').toLowerCase().includes(q)
    })
    .sort((a, b) => Number(needsAttention(b)) - Number(needsAttention(a)) || a.name.localeCompare(b.name, 'zh-CN'))
})

function boundServers(clientId: string): string[] {
  return desk.bindings
    .filter((b) => b.client_id === clientId)
    .map((b) => nodeName(desk.nodes, b.server_id))
}

function bindingCount(id: string) {
  return desk.bindings.filter((b) => b.client_id === id).length
}

function openCreate() {
  Object.assign(draft, {
    id: '', name: '', role: 'client', address: '', port: '443', serverName: '',
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
    enc: node.tunnel?.encryption || 'none',
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
  if (draft.enc && draft.enc !== 'none') tunnel.encryption = draft.enc
  if (draft.pool && Number(draft.pool) > 0) tunnel.pool = Number(draft.pool)
  if (draft.transport === 'reality') {
    tunnel.reality = {
      public_key: draft.realityPublicKey.trim(),
      short_ids: draft.realityShortIDs.trim(),
      fingerprint: draft.realityFingerprint.trim() || 'chrome',
    }
  } else if (draft.transport === 'hysteria2') {
    tunnel.hysteria2 = { password: draft.hysteria2Password.trim() }
  }
  await api(draft.id ? `/nodes/${encodeURIComponent(draft.id)}` : '/nodes', draft.id ? 'PUT' : 'POST', {
    name: draft.name.trim(), role: 'client',
    address: '', port: 0, server_name: '',
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
  ask('吊销节点凭据', `确定吊销「${node.name}」？吊销后不能再注册或拉取配置。此操作不可撤销。`, '吊销', async () => {
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
      <input v-model="query" type="search" aria-label="搜索客户端" placeholder="搜索名称或 ID" />
      <button type="button" class="btn primary" @click="openCreate">新建客户端</button>
    </div>

    <EmptyState v-if="!clients.length" title="没有匹配的客户端" text="换一个搜索词，或新建内网节点。" />
    <div v-else class="node-cards">
      <article v-for="node in clients" :key="node.id" class="node-card panel">
        <header>
          <div>
            <strong style="font-size: 16px;">{{ node.name }}</strong>
            <Badge :text="presence(node).text" :tone="presence(node).tone" />
          </div>
          <Badge :text="revisionState(node).text" :tone="revisionState(node).tone" />
        </header>
        <dl class="node-meta">
          <div><dt>绑定服务端</dt><dd>{{ boundServers(node.id).length ? boundServers(node.id).join(', ') : '尚未绑定' }}</dd></div>
          <div><dt>版本同步</dt><dd class="mono">期望 r{{ node.desired_revision }} / 已应用 r{{ node.applied_revision }}</dd></div>
          <div><dt>心跳</dt><dd>{{ seenText(node.last_seen) }}</dd></div>
          <div><dt>传输</dt><dd><Badge :text="transportLabel(node)" :tone="transportTone(node)" /></dd></div>
          <div v-if="node.tunnel?.flow"><dt>流控</dt><dd class="mono">{{ node.tunnel.flow }}</dd></div>
          <div v-if="node.tunnel?.encryption && node.tunnel.encryption !== 'none'"><dt>加密</dt><dd class="mono">{{ node.tunnel.encryption }}</dd></div>
          <div v-if="node.tunnel?.pool"><dt>连接池</dt><dd class="mono">{{ node.tunnel.pool }} 路</dd></div>
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

    <Modal ref="editor" :title="draft.id ? '编辑客户端' : '新建客户端'" :submit="saveNode">
      <label for="cli-name">节点名称</label>
      <input id="cli-name" v-model="draft.name" maxlength="128" required />

      <p class="field-label" style="margin-top: 16px; font-weight: 600;">隧道传输与安全</p>
      <label for="cli-transport">传输方式</label>
      <select id="cli-transport" v-model="draft.transport">
        <option value="tls">标准 TLS (TCP 证书)</option>
        <option value="reality">REALITY 伪装 (无须域名证书)</option>
        <option value="hysteria2">Hysteria2 (QUIC UDP 传输)</option>
      </select>
      <div class="grid-2">
        <div>
          <label for="cli-flow">流控模式 (Flow)</label>
          <select id="cli-flow" v-model="draft.flow">
            <option value="">无 (普通 VLESS)</option>
            <option value="xtls-rprx-vision">xtls-rprx-vision</option>
          </select>
        </div>
        <div>
          <label for="cli-enc">加密算法</label>
          <select id="cli-enc" v-model="draft.enc">
            <option value="none">none (标准)</option>
            <option value="xor">xor (对称混淆)</option>
          </select>
        </div>
      </div>
      <label for="cli-pool">反向连接池容量 (Pool)</label>
      <input id="cli-pool" v-model="draft.pool" type="number" min="0" max="64" placeholder="默认 0 (自动/单连接)" />

      <template v-if="draft.transport === 'reality'">
        <p class="field-label" style="margin-top: 12px; font-weight: 600;">REALITY 客户端参数</p>
        <label for="cli-reality-pub">X25519 公钥 (Public Key)</label>
        <input id="cli-reality-pub" v-model="draft.realityPublicKey" placeholder="留空则自动从网关节点继承" />
        <small class="help">客户端连接使用的网关 REALITY 公钥（可留空继承）。</small>
        <label for="cli-reality-short-id">Short ID</label>
        <input id="cli-reality-short-id" v-model="draft.realityShortIDs" placeholder="留空则自动从网关节点继承" />
        <label for="cli-reality-fp">客户端指纹 (Fingerprint)</label>
        <select id="cli-reality-fp" v-model="draft.realityFingerprint">
          <option value="chrome">chrome</option>
          <option value="firefox">firefox</option>
          <option value="safari">safari</option>
          <option value="ios">ios</option>
          <option value="android">android</option>
          <option value="edge">edge</option>
          <option value="random">random</option>
        </select>
      </template>

      <template v-if="draft.transport === 'hysteria2'">
        <p class="field-label" style="margin-top: 12px; font-weight: 600;">Hysteria2 QUIC 配置</p>
        <label for="cli-hy2-pass">认证密码 (Password)</label>
        <input id="cli-hy2-pass" v-model="draft.hysteria2Password" type="password" placeholder="留空则自动从绑定的网关继承" />
        <small class="help">内网节点连接网关的鉴权密码。若留空则自动继承网关配置。</small>
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
