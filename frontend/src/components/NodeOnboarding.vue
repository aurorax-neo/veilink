<script setup lang="ts">
import { computed, nextTick, ref } from 'vue'
import { api } from '../api'
import { copyText } from '../format'
import type { Node } from '../types'
import Modal from './Modal.vue'

interface JoinResult {
  prepare?: string
  command: string
  offline_command?: string
  offline_binary_command?: string
  bootstrap_state?: string
  state_json?: string
  expires_at: number
  token: string
  warning: string
}
type CommandTab = 'docker' | 'offline-docker' | 'binary' | 'state'
const modal = ref<InstanceType<typeof Modal> | null>(null)
const commandBox = ref<HTMLTextAreaElement | null>(null)
const node = ref<Node | null>(null)
const masterURL = ref(location.origin)
const generatedMasterURL = ref('')
const result = ref<JoinResult | null>(null)
const generating = ref(false)
const status = ref('')
const copyError = ref('')
const copied = ref(false)
const activeTab = ref<CommandTab>('docker')
const showHelp = ref(false)
let pendingKey = ''
let pendingGenerate: Promise<boolean> | null = null
const hasOffline = computed(() => !!(result.value?.offline_command || result.value?.offline_binary_command || result.value?.state_json))
const activeCommand = computed(() => {
  if (!result.value) return ''
  if (activeTab.value === 'offline-docker') return result.value.offline_command || result.value.command
  if (activeTab.value === 'binary') return result.value.offline_binary_command || ''
  if (activeTab.value === 'state') return result.value.state_json || ''
  return result.value.command
})
const activeCopyLabel = computed(() => {
  if (activeTab.value === 'offline-docker') return '脱机 Docker 命令'
  if (activeTab.value === 'binary') return '脱机二进制命令'
  if (activeTab.value === 'state') return 'state.json 脱机配置'
  return '接入命令'
})
const activeHint = computed(() => {
  if (activeTab.value === 'offline-docker') return '内嵌节点凭据与当前隧道快照，无法连接 Hub 时也可直接启动容器。'
  if (activeTab.value === 'binary') return '单二进制直接携带完整脱机参数运行，网络恢复后自动重连 Hub。'
  if (activeTab.value === 'state') return '将此 JSON 写入节点 /data/state/state.json，即可脱机加载隧道配置。'
  return '启动后连接 Hub 自动拉取并持续同步隧道与端口映射配置。'
})
function selectTab(tab: CommandTab) {
  activeTab.value = tab
  copied.value = false
  void nextTick(() => {
    if (commandBox.value) commandBox.value.scrollTop = 0
  })
}
function open(value: Node) {
  if (value.embedded) { node.value = null; clear(); return }
  node.value = value
  masterURL.value = location.origin
  clear()
  activeTab.value = 'docker'
  showHelp.value = false
  modal.value?.open()
  void generate().catch(() => {})
}
function clear() {
  result.value = null
  generatedMasterURL.value = ''
  status.value = ''
  copyError.value = ''
  copied.value = false
  pendingKey = ''
  pendingGenerate = null
}
async function generate() {
  if (node.value?.embedded) throw new Error('内置节点不支持快捷接入。')
  let url: URL
  const cleanURL = masterURL.value.trim()
  try { url = new URL(cleanURL) } catch { throw new Error('请输入完整的 http:// 或 https:// 地址。') }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.hash || url.search || (url.pathname !== '/' && url.pathname !== '') || /[\r\n\t ]/.test(cleanURL)) throw new Error('地址须使用 http:// 或 https://，不能含路径、凭据、查询或片段。')
  if (!node.value) throw new Error('未选择节点。')
  const reqKey = `${node.value.id}|${cleanURL}`
  if (pendingGenerate && pendingKey === reqKey) return pendingGenerate
  const targetId = node.value.id
  pendingKey = reqKey
  generating.value = true
  const task = (async () => {
    try {
      const response = await api<JoinResult>(`/nodes/${encodeURIComponent(targetId)}/join`, 'POST', { master_url: cleanURL })
      if (!response.command || !response.token || !Number.isFinite(response.expires_at)) throw new Error('接入响应不完整，请重试。')
      result.value = response
      generatedMasterURL.value = cleanURL
      status.value = ''
      void nextTick(() => {
        if (commandBox.value) commandBox.value.scrollTop = 0
      })
      return false
    } finally {
      generating.value = false
      if (pendingKey === reqKey) {
        pendingKey = ''
        pendingGenerate = null
      }
    }
  })()
  pendingGenerate = task
  return task
}
async function copy(value: string, label = activeCopyLabel.value) {
  copyError.value = ''
  try {
    await copyText(value)
    status.value = `${label}已复制。`
    copied.value = true
    globalThis.window?.setTimeout?.(() => { copied.value = false }, 2500)
  }
  catch { copyError.value = `${label}复制失败，请手动选择命令。` }
}
function downloadStateJson() {
  if (!result.value?.state_json) return
  const blob = new Blob([result.value.state_json], { type: 'application/json;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'state.json'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
  status.value = 'state.json 脱机配置已导出。'
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
  <Modal ref="modal" :title="`快捷接入 · ${node?.name || ''}`" save-label="生成接入命令" :hide-save="!!result" :submit="generate" @close="clear">
    <div class="onboarding-field">
      <label for="join-master">管理地址</label>
      <div class="master-input-row">
        <input id="join-master" v-model="masterURL" type="url" required placeholder="https://master.example.com:8443" @keydown.enter.prevent="generate" />
        <button v-if="result" type="button" class="btn small quiet master-refresh-btn" :disabled="generating || masterURL.trim() === generatedMasterURL" @click="generate">
          {{ generating ? '更新中…' : '更新地址' }}
        </button>
      </div>
    </div>
    <template v-if="result">
      <div class="onboarding-command-card">
        <div class="command-heading">
          <div class="command-title-group">
            <label for="join-command">接入命令与参数</label>
            <span class="token-badge">持久有效</span>
          </div>
          <div class="command-actions">
            <button v-if="activeTab === 'state' && result.state_json" type="button" class="btn small quiet" @click="downloadStateJson">导出文件</button>
            <button type="button" class="btn small primary fit" :class="{ 'copy-bounce': copied }" @click="copy(activeCommand, activeCopyLabel)">
              <span class="fit-sizer" aria-hidden="true">✓ 已复制命令</span>
              <span class="fit-sizer" aria-hidden="true">复制接入命令</span>
              <span class="fit-sizer" aria-hidden="true">复制当前内容</span>
              <span class="fit-value">{{ copied ? '✓ 已复制' : (activeTab === 'docker' ? '复制接入命令' : '复制当前内容') }}</span>
            </button>
          </div>
        </div>
        <div v-if="hasOffline" class="seg-pills offline-tabs" role="group" aria-label="接入启动方式">
          <button type="button" :aria-pressed="activeTab === 'docker'" @click="selectTab('docker')">标准容器</button>
          <button type="button" :aria-pressed="activeTab === 'offline-docker'" @click="selectTab('offline-docker')">脱机容器</button>
          <button type="button" :aria-pressed="activeTab === 'binary'" @click="selectTab('binary')">脱机二进制</button>
          <button type="button" :aria-pressed="activeTab === 'state'" @click="selectTab('state')">state.json</button>
        </div>
        <p class="command-mode-hint">{{ activeHint }}</p>
        <textarea id="join-command" ref="commandBox" class="command-block secret" :value="activeCommand" readonly rows="5" spellcheck="false" />
      </div>
    </template>
    <div class="help-details">
      <button type="button" class="help-summary" :aria-expanded="showHelp" @click="showHelp = !showHelp">
        <span>接入参数与通信说明</span>
        <span class="chevron-mark" :class="{ open: showHelp }" aria-hidden="true">▾</span>
      </button>
      <div class="collapsible" :data-open="showHelp ? 'true' : 'false'">
        <div class="help-content">
          <p class="help">填写节点可访问的 Master 地址（含端口）；HTTPS 证书须匹配主机名。当节点无法连接 Hub 时，可使用「脱机运行参数」直接加载完整隧道与端口映射配置启动，待网络恢复后自动同步。</p>
          <p v-if="result?.warning" class="warning" role="note">{{ result.warning }}</p>
          <p class="help">命令使用统一镜像 ghcr.io/aurorax-neo/veilink:latest，以 server 或 client 子命令选择角色。节点接入令牌持久有效，多次生成接入命令不会使原有令牌失效。</p>
          <p class="help">HTTP/h2c 不加密，仅用于可信网络；接入命令只设置管理连接，-control-ca 仅信任 Master HTTPS。客户端不加本地隧道 flags。节点在线仅代表心跳，仍需确认应用修订及映射目标可达。</p>
        </div>
      </div>
    </div>
    <p v-if="status" class="help" role="status">{{ status }}</p>
    <p v-if="copyError" class="error inline-alert" role="alert">{{ copyError }}</p>
  </Modal>
</template>
