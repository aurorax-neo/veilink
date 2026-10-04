<script setup lang="ts">
import { computed, onUnmounted, ref } from 'vue'
import { api } from '../api'
import { copyText } from '../format'
import type { Node } from '../types'
import Modal from './Modal.vue'

interface JoinResult { prepare?: string; command: string; expires_at: number; token: string; warning: string }
const modal = ref<InstanceType<typeof Modal> | null>(null)
const revokeModal = ref<InstanceType<typeof Modal> | null>(null)
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
defineExpose({ open })
</script>

<template>
  <Modal ref="modal" :title="`快捷接入 · ${node?.name || ''}`" save-label="生成命令" :hide-save="!!result" :submit="generate" @close="clear">
    <p class="help">在已安装 Docker 的节点上执行；命令使用统一镜像 ghcr.io/aurorax-neo/veilink:latest，以 server 或 client 子命令选择角色。容器启动时会自动创建所需目录并设置权限。</p>
    <label for="join-master">管理地址</label>
    <input id="join-master" v-model="masterURL" type="url" required :disabled="!!result" placeholder="https://vl.vekt.cc.cd:8843" />
    <small class="help">填写节点实际可达的管理地址（http:// 或 https://）及端口；HTTP/h2c 不加密，仅用于可信网络，跨主机不能填写 Master 的 127.0.0.1。HTTPS 证书须匹配主机名。</small>
    <p class="help">接入令牌在有效期内可重复用于此节点；重新生成会替换旧令牌，撤销或过期后不能再接入。</p>
    <p v-if="result?.warning" class="warning" role="note">{{ result.warning }}</p>
    <template v-if="result">
      <div class="command-heading"><label for="join-command">Docker 接入命令（含接入令牌）</label><button type="button" class="btn small" :disabled="expired" @click="copy(result.command, '接入命令')">复制接入命令</button></div>
      <textarea id="join-command" class="command-block secret" :value="result.command" readonly rows="5" spellcheck="false" />
      <small class="help">{{ expired ? '已过期' : '到期' }} · {{ new Date(result.expires_at * 1000).toLocaleString('zh-CN', { hour12: false }) }}</small>
      <div v-if="expired" class="actions"><button type="button" class="btn" @click="clear">重新生成</button></div>
    </template>
    <p class="help">接入命令只设置管理连接，-control-ca 仅信任 Master HTTPS。TLS、plain、REALITY、Hysteria2、VLESS Encryption 与 Vision 均在服务端编辑页配置并统一下发；客户端不加本地隧道 flags。节点在线仅代表心跳，仍需确认应用修订及映射目标可达。</p>
    <p v-if="status" class="help" role="status">{{ status }}</p>
    <p v-if="copyError" class="error" role="alert">{{ copyError }}</p>
    <button type="button" class="btn danger revoke-token" @click="revokeModal?.open()">撤销接入令牌</button>
  </Modal>
  <Modal ref="revokeModal" title="撤销接入令牌" save-label="撤销" danger :submit="revoke">
    <p>撤销后此令牌不能再用于接入，包括已使用过的令牌；不影响已接入节点的有效凭据。</p>
  </Modal>
</template>
