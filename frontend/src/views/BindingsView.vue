<script setup lang="ts">
import { computed, inject, ref } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { bindingLabel, nodeName } from '../format'
import Badge from '../components/Badge.vue'
import EmptyState from '../components/EmptyState.vue'
import Modal from '../components/Modal.vue'

const desk = inject(deskKey)!
const editor = ref<InstanceType<typeof Modal> | null>(null)
const confirm = ref<InstanceType<typeof Modal> | null>(null)
const serverId = ref('')
const clientId = ref('')
const pendingId = ref('')
const servers = computed(() => desk.nodes.filter((node) => node.role === 'server' && !node.revoked))
const clients = computed(() => desk.nodes.filter((node) => node.role === 'client' && !node.revoked))
const cards = computed(() =>
  [...desk.bindings].sort((a, b) => bindingLabel(desk.nodes, a).localeCompare(bindingLabel(desk.nodes, b), 'zh-CN')),
)

function mapsOf(id: string) {
  return desk.mappings.filter((mapping) => mapping.binding_id === id)
}

function openCreate() {
  serverId.value = servers.value[0]?.id || ''
  clientId.value = clients.value[0]?.id || ''
  editor.value?.open()
}

async function saveBinding() {
  if (!serverId.value || !clientId.value) throw new Error('请选择未吊销的公网网关和内网节点。')
  if (desk.bindings.some((binding) => binding.server_id === serverId.value && binding.client_id === clientId.value)) {
    throw new Error('这对网关和内网节点已经绑定。')
  }
  await api('/bindings', 'POST', { server_id: serverId.value, client_id: clientId.value })
  await desk.reload()
  desk.notify('绑定已创建。反向域名和身份由管理中心生成，API 不返回 UUID。')
  return true
}

function askRemove(id: string) {
  pendingId.value = id
  confirm.value?.open()
}

async function removeBinding() {
  const binding = desk.bindings.find((item) => item.id === pendingId.value)
  await api(`/bindings/${encodeURIComponent(pendingId.value)}`, 'DELETE')
  await desk.reload()
  desk.notify(binding ? `已删除 ${bindingLabel(desk.nodes, binding)}，其上的映射也已移除。` : '绑定已删除。')
  return true
}
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="正在读取绑定" text="正在从管理中心获取最新列表。" />
  <EmptyState v-else-if="!desk.loaded" title="暂时无法读取绑定" :text="(desk.error || '请求失败') + ' 未显示缓存或演示数据。'" />
  <div v-else class="stack">
    <div class="toolbar">
      <p class="legend inline">绑定创建后不能修改。要换网关或节点，先删除再重建。删除会带走这条绑定上的全部映射。</p>
      <button type="button" class="btn primary" @click="openCreate">新建绑定</button>
    </div>
    <EmptyState v-if="!cards.length" title="还没有绑定" text="先准备一个未吊销的公网网关和一个内网节点。" />
    <div v-else class="cards">
      <article v-for="binding in cards" :key="binding.id" class="bind-card">
        <header>
          <div>
            <p class="kicker">GATEWAY → CLIENT</p>
            <h2>{{ nodeName(desk.nodes, binding.server_id) }}</h2>
            <p class="to">{{ nodeName(desk.nodes, binding.client_id) }}</p>
          </div>
          <Badge :text="`${mapsOf(binding.id).length} 条映射`" />
        </header>
        <dl>
          <div><dt>反向域名</dt><dd><code>{{ binding.domain }}</code></dd></div>
          <div><dt>绑定 ID</dt><dd><code>{{ binding.id }}</code></dd></div>
        </dl>
        <ul v-if="mapsOf(binding.id).length" class="mini-maps">
          <li v-for="mapping in mapsOf(binding.id)" :key="mapping.id">
            <span>{{ mapping.name }}</span>
            <Badge :text="mapping.enabled ? '启用' : '停用'" :tone="mapping.enabled ? 'good' : ''" />
          </li>
        </ul>
        <button type="button" class="btn small danger" @click="askRemove(binding.id)">删除绑定</button>
      </article>
    </div>
    <Modal ref="editor" title="新建网关绑定" save-label="创建绑定" :disabled="!servers.length || !clients.length" :submit="saveBinding">
      <p v-if="!servers.length || !clients.length" class="callout">请先创建至少一个未吊销的公网网关和内网节点。</p>
      <label for="bind-server">公网网关</label>
      <select id="bind-server" v-model="serverId" :disabled="!servers.length">
        <option v-for="node in servers" :key="node.id" :value="node.id">{{ node.name }}</option>
      </select>
      <label for="bind-client">内网节点</label>
      <select id="bind-client" v-model="clientId" :disabled="!clients.length">
        <option v-for="node in clients" :key="node.id" :value="node.id">{{ node.name }}</option>
      </select>
    </Modal>
    <Modal ref="confirm" title="删除绑定" save-label="删除" danger :submit="removeBinding">
      <p class="lead">删除后，这条绑定上的 TCP 映射会一并移除。绑定不能编辑，只能重建。</p>
    </Modal>
  </div>
</template>
