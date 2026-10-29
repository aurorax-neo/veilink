<script setup lang="ts">
import { computed, onUnmounted, ref } from 'vue'
import { api } from '../api'
import { copyText } from '../format'
import type { Node } from '../types'
import Modal from './Modal.vue'

interface JoinResult { prepare?: string; command: string; expires_at: number; token: string; warning: string }
const modal = ref<InstanceType<typeof Modal> | null>(null)
const revokeModal = ref<InstanceType<typeof Modal> | null>(null)
const resetModal = ref<InstanceType<typeof Modal> | null>(null)
const node = ref<Node | null>(null)
const masterURL = ref(location.origin)
const result = ref<JoinResult | null>(null)
const status = ref('')
const copyError = ref('')
const now = ref(Date.now())
const timer = window.setInterval(() => { now.value = Date.now() }, 1000)
onUnmounted(() => window.clearInterval(timer))
const expired = computed(() => !!result.value && result.value.expires_at * 1000 <= now.value)
function open(value: Node) {
  if (value.embedded) { node.value = null; clear(); return }
  node.value = value
  masterURL.value = location.origin
  clear()
  modal.value?.open()
}
function clear() { result.value = null; status.value = ''; copyError.value = '' }
async function generate() {
  if (node.value?.embedded) throw new Error('内置节点不支持快捷接入。')
  let url: URL
  try { url = new URL(masterURL.value.trim()) } catch { throw new Error('请输入完整的 http:// 或 https:// 地址。') }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash || url.search || (url.pathname !== '/' && url.pathname !== '') || /[\r\n\t ]/.test(masterURL.value)) throw new Error('地址须使用 http:// 或 https://，不能含路径、凭据、查询或片段。')
  if (!node.value) throw new Error('未选择节点。')
  const response = await api<JoinResult>(`/nodes/${encodeURIComponent(node.value.id)}/join`, 'POST', { master_url: masterURL.value.trim() })
  if (!response.command || !response.token || !Number.isFinite(response.expires_at)) throw new Error('接入响应不完整，请重试。')
  result.value = response
  status.value = '命令已生成。'
  return false
}
async function copy(value: string, label: string) {
  copyError.value = ''
  try { await copyText(value); status.value = `${label}已复制。` }
  catch { copyError.value = `${label}复制失败，请手动选择命令。` }
}
async function revoke() {
  if (!node.value) throw new Error('未选择节点。')
  if (node.value.embedded) throw new Error('内置节点不支持快捷接入。')
  await api(`/nodes/${encodeURIComponent(node.value.id)}/enroll`, 'DELETE')
  clear()
  status.value = '接入令牌已撤销。'
  return true
}
async function resetCredential() {
  if (!node.value) throw new Error('未选择节点。')
  if (node.value.embedded) throw new Error('内置节点不支持重置凭据。')
  await api(`/nodes/${encodeURIComponent(node.value.id)}/reset-credential`, 'POST', {})
  clear()
  status.value = '节点凭据已重置，原有凭据已失效。请重新生成接入命令并接入。'
  return true
}
defineExpose({ open })
</script>

<template>
  <Modal ref="modal" :title="`快捷接入 · ${node?.name || ''}`" save-label="生成接入命令" :hide-save="!!result" :submit="generate" @close="clear">
    <label for="join-master">管理地址</label>
    <input id="join-master" v-model="masterURL" type="url" required :disabled="!!result" placeholder="https://master.example.com:8443" />
    <small class="help">填写节点可访问的 Master 地址（含端口）；HTTPS 证书须匹配主机名。</small>
    <p v-if="result?.warning" class="warning" role="note">{{ result.warning }}</p>
    <template v-if="result">
      <div class="command-heading"><label for="join-command">Docker 接入命令</label><button type="button" class="btn small primary" :disabled="expired" @click="copy(result.command, '接入命令')">复制接入命令</button></div>
      <textarea id="join-command" class="command-block secret" :value="result.command" readonly rows="5" spellcheck="false" />
      <div class="token-meta">
        <small class="help" :class="{ bad: expired }">{{ expired ? '令牌已过期' : '令牌到期' }} · {{ new Date(result.expires_at * 1000).toLocaleString('zh-CN', { hour12: false }) }}</small>
        <button v-if="expired" type="button" class="btn small" @click="clear">重新生成</button>
        <button v-else type="button" class="btn small quiet danger revoke-token" style="margin-top: 0;" @click="revokeModal?.open()">撤销此接入令牌</button>
      </div>
    </template>
    <details class="help-details">
      <summary class="help-summary">接入参数与通信说明</summary>
      <div class="help-content">
        <p class="help">命令使用统一镜像 ghcr.io/aurorax-neo/veilink:latest，以 server 或 client 子命令选择角色。接入令牌在有效期内可重复用于此节点，重新生成会替换旧令牌。</p>
        <p class="help">HTTP/h2c 不加密，仅用于可信网络；接入命令只设置管理连接，-control-ca 仅信任 Master HTTPS。客户端不加本地隧道 flags。节点在线仅代表心跳，仍需确认应用修订及映射目标可达。</p>
      </div>
    </details>
    <p v-if="status" class="help" role="status">{{ status }}</p>
    <p v-if="copyError" class="error" role="alert">{{ copyError }}</p>
    <details v-if="!node?.embedded" class="advanced-danger">
      <summary>高危操作：重置节点永久凭据</summary>
      <div class="danger-panel">
        <p class="fine">若节点私钥泄露或需彻底废弃当前节点的长期凭据，可重置凭据。重置后该节点当前所有在线连接将被立即中断，必须使用新生成的接入命令重新启动。</p>
        <button type="button" class="btn small danger" @click="resetModal?.open()">重置节点凭据</button>
      </div>
    </details>
  </Modal>
  <Modal ref="revokeModal" title="撤销接入令牌" save-label="确认撤销" danger size="small" :submit="revoke">
    <p>撤销后当前接入令牌立即失效，无法再用于启动节点；不影响已接入节点的有效凭据。</p>
  </Modal>
  <Modal ref="resetModal" title="重置节点凭据" save-label="确认重置并断开连接" danger size="small" :submit="resetCredential">
    <p>重置后该节点的已有有效凭据将立即失效并被删除，当前正在运行的节点连接会被强制断开。重新运行接入命令后将签发全新凭据。</p>
  </Modal>
</template>
