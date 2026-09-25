<script setup lang="ts">
import { computed, onUnmounted, ref } from 'vue'
import { api } from '../api'
import { copyText } from '../format'
import type { Node } from '../types'
import Modal from './Modal.vue'

interface JoinResult { prepare: string; command: string; expires_at: number; token: string; warning: string }
const modal = ref<InstanceType<typeof Modal> | null>(null)
const revokeModal = ref<InstanceType<typeof Modal> | null>(null)
const node = ref<Node | null>(null)
const masterURL = ref(location.origin)
const ttl = ref(3600)
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
  ttl.value = 3600
  clear()
  modal.value?.open()
}
function clear() { result.value = null; status.value = ''; copyError.value = '' }
async function generate() {
  if (node.value?.embedded) throw new Error('内置节点不支持快捷接入。')
  let url: URL
  try { url = new URL(masterURL.value.trim()) } catch { throw new Error('请输入完整的 https:// 地址。') }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search || (url.pathname !== '/' && url.pathname !== '')) throw new Error('地址须使用 https://，不能含路径、凭据、查询或片段。')
  if (!Number.isInteger(Number(ttl.value)) || Number(ttl.value) <= 0) throw new Error('有效期须为正整数秒。')
  if (!node.value) throw new Error('未选择节点。')
  const response = await api<JoinResult>(`/nodes/${encodeURIComponent(node.value.id)}/join`, 'POST', { master_url: masterURL.value.trim(), ttl_seconds: Number(ttl.value) })
  if (!response.prepare || !response.command || !response.token || !Number.isFinite(response.expires_at)) throw new Error('接入响应不完整，请重试。')
  result.value = response
  status.value = '命令已生成。'
  return false
}
async function copy() {
  copyError.value = ''
  try { await copyText(result.value?.command || ''); status.value = '命令已复制。' }
  catch { copyError.value = '复制失败，请手动选择命令。' }
}
async function revoke() {
  if (!node.value) throw new Error('未选择节点。')
  if (node.value.embedded) throw new Error('内置节点不支持快捷接入。')
  await api(`/nodes/${encodeURIComponent(node.value.id)}/enroll`, 'DELETE')
  clear()
  status.value = '待使用令牌已撤销。'
  return true
}
defineExpose({ open })
</script>

<template>
  <Modal ref="modal" :title="`快捷接入 · ${node?.name || ''}`" save-label="生成命令" :hide-save="!!result" :submit="generate" @close="clear">
    <p class="help">在已安装 Docker 且已准备对应 veilink:server 或 veilink:client 镜像的节点上执行。请先执行目录准备命令，再执行 Docker 接入命令。</p>
    <label for="join-master">管理地址</label>
    <input id="join-master" v-model="masterURL" type="url" required :disabled="!!result" placeholder="https://master.example.com:8443" />
    <small class="help">须含 https://；填写节点可达的管理端 gRPC 地址及端口，证书须匹配主机名。</small>
    <label for="join-ttl">有效期（秒）</label>
    <input id="join-ttl" v-model.number="ttl" type="number" min="1" step="1" required :disabled="!!result" />
    <p v-if="result?.warning" class="warning" role="note">{{ result.warning }}</p>
    <template v-if="result">
      <label for="join-prepare">目录准备命令（需具备目录管理权限）</label>
      <textarea id="join-prepare" :value="result.prepare" readonly rows="2" spellcheck="false" />
      <label for="join-command">Docker 接入命令（含一次性令牌）</label>
      <textarea id="join-command" class="secret" :value="result.command" readonly rows="5" spellcheck="false" />
      <small class="help">{{ expired ? '已过期' : '到期' }} · {{ new Date(result.expires_at * 1000).toLocaleString('zh-CN', { hour12: false }) }}</small>
      <div class="actions"><button type="button" class="btn" :disabled="expired" @click="copy">复制命令</button><button v-if="expired" type="button" class="btn" @click="clear">重新生成</button></div>
    </template>
    <p class="help">接入命令只设置管理连接，-control-ca 仅信任 Master HTTPS。TLS、plain、REALITY、Hysteria2、VLESS Encryption 与 Vision 均在服务端编辑页配置并统一下发；客户端不加本地隧道 flags。节点在线仅代表心跳，仍需确认应用修订及映射目标可达。</p>
    <p v-if="status" class="help" role="status">{{ status }}</p>
    <p v-if="copyError" class="error" role="alert">{{ copyError }}</p>
    <button type="button" class="btn danger revoke-token" @click="revokeModal?.open()">撤销待使用令牌</button>
  </Modal>
  <Modal ref="revokeModal" title="撤销待使用令牌" save-label="撤销" danger :submit="revoke">
    <p>仅撤销尚未使用的接入令牌，不影响已接入节点。</p>
  </Modal>
</template>
