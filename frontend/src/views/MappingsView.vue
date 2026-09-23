<script setup lang="ts">
import { computed, inject, reactive, ref } from 'vue'
import { api } from '../api'
import { deskKey } from '../desk'
import { bindingLabel, endpoint, validateMapping } from '../format'
import type { Mapping } from '../types'
import Badge from '../components/Badge.vue'
import EmptyState from '../components/EmptyState.vue'
import Modal from '../components/Modal.vue'

const desk = inject(deskKey)!
const filter = ref<'all' | 'on' | 'off'>('all')
const query = ref('')
const editor = ref<InstanceType<typeof Modal> | null>(null)
const confirm = ref<InstanceType<typeof Modal> | null>(null)
const confirmTitle = ref('')
const confirmText = ref('')
let confirmRun: () => Promise<void> = async () => {}
const draft = reactive({
  id: '',
  name: '',
  bindingId: '',
  listenHost: '0.0.0.0',
  listenPort: '',
  targetHost: '',
  targetPort: '',
  network: 'tcp',
  enabled: true,
})

const rows = computed(() => {
  const q = query.value.trim().toLowerCase()
  return desk.mappings.filter((mapping) => {
    if (filter.value === 'on' && !mapping.enabled) return false
    if (filter.value === 'off' && mapping.enabled) return false
    if (!q) return true
    const binding = desk.bindings.find((item) => item.id === mapping.binding_id)
    return [mapping.name, mapping.network || 'tcp', mapping.listen_host, mapping.target_host, binding ? bindingLabel(desk.nodes, binding) : ''].join(' ').toLowerCase().includes(q)
  })
})

function bindingOf(id: string) {
  return desk.bindings.find((binding) => binding.id === id)
}

function openCreate() {
  Object.assign(draft, {
    id: '',
    name: '',
    bindingId: desk.bindings[0]?.id || '',
    listenHost: '0.0.0.0',
    listenPort: '',
    targetHost: '',
    targetPort: '',
    network: 'tcp',
    enabled: true,
  })
  editor.value?.open()
}

function openEdit(mapping: Mapping) {
  Object.assign(draft, {
    id: mapping.id,
    name: mapping.name,
    bindingId: mapping.binding_id,
    listenHost: mapping.listen_host,
    listenPort: String(mapping.listen_port),
    targetHost: mapping.target_host,
    targetPort: String(mapping.target_port),
    network: mapping.network || 'tcp',
    enabled: mapping.enabled,
  })
  editor.value?.open()
}

async function saveMapping() {
  const problem = validateMapping(draft, desk.nodes, desk.bindings, desk.mappings, draft.id)
  if (problem) throw new Error(problem)
  const enabled = draft.enabled
  await api(draft.id ? `/mappings/${encodeURIComponent(draft.id)}` : '/mappings', draft.id ? 'PUT' : 'POST', {
    name: draft.name.trim(),
    binding_id: draft.bindingId,
    listen_host: draft.listenHost.trim(),
    listen_port: Number(draft.listenPort),
    target_host: draft.targetHost.trim(),
    target_port: Number(draft.targetPort),
    network: draft.network || 'tcp',
    enabled,
  })
  await desk.reload()
  desk.notify('映射已保存。请到节点页查看期望版本和已应用版本。')
  return true
}

function ask(title: string, text: string, run: () => Promise<void>) {
  confirmTitle.value = title
  confirmText.value = text
  confirmRun = run
  confirm.value?.open()
}

async function runConfirm() {
  await confirmRun()
  return true
}

function toggle(mapping: Mapping) {
  const next = !mapping.enabled
  ask(next ? '启用映射' : '停用映射', `确定${next ? '启用' : '停用'}「${mapping.name}」？变更会下发到两端，可能断开现有连接。`, async () => {
    const problem = next ? validateMapping({
      name: mapping.name,
      bindingId: mapping.binding_id,
      listenHost: mapping.listen_host,
      listenPort: String(mapping.listen_port),
      targetHost: mapping.target_host,
      targetPort: String(mapping.target_port),
      network: mapping.network || 'tcp',
    }, desk.nodes, desk.bindings, desk.mappings, mapping.id) : null
    if (problem) throw new Error(problem)
    await api(`/mappings/${encodeURIComponent(mapping.id)}`, 'PUT', { ...mapping, enabled: next })
    await desk.reload()
    desk.notify(next ? '映射已启用。' : '映射已停用。')
  })
}

function remove(mapping: Mapping) {
  ask('删除映射', `确定删除「${mapping.name}」？此操作不可撤销。`, async () => {
    await api(`/mappings/${encodeURIComponent(mapping.id)}`, 'DELETE')
    await desk.reload()
    desk.notify('映射已删除。')
  })
}
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="正在读取映射" text="正在从管理中心获取最新列表。" />
  <EmptyState v-else-if="!desk.loaded" title="暂时无法读取映射" :text="(desk.error || '请求失败') + ' 未显示缓存或演示数据。'" />
  <div v-else class="stack">
    <div class="toolbar">
      <div class="chips" role="tablist" aria-label="映射筛选">
        <button type="button" :aria-selected="filter === 'all'" @click="filter = 'all'">全部 {{ desk.mappings.length }}</button>
        <button type="button" :aria-selected="filter === 'on'" @click="filter = 'on'">已启用 {{ desk.mappings.filter((mapping) => mapping.enabled).length }}</button>
        <button type="button" :aria-selected="filter === 'off'" @click="filter = 'off'">已停用 {{ desk.mappings.filter((mapping) => !mapping.enabled).length }}</button>
      </div>
      <input v-model="query" type="search" aria-label="搜索映射" placeholder="搜索名称、地址或绑定" />
      <button type="button" class="btn primary" @click="openCreate">新建映射</button>
    </div>
    <section class="panel">
      <header class="panel-head"><h2>端口映射</h2><small>{{ rows.length }} 条</small></header>
      <EmptyState v-if="!rows.length" title="没有匹配的映射" text="先创建网关绑定，再添加从公网 IP 到内网目标的端口转发。" />
      <div v-else class="table-scroll" tabindex="0" role="region" aria-label="映射列表，可横向滚动">
        <table>
          <thead>
            <tr>
              <th scope="col">名称</th>
              <th scope="col">路径</th>
              <th scope="col">状态</th>
              <th scope="col">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="mapping in rows" :key="mapping.id">
              <td>
                <strong>{{ mapping.name }}</strong>
                <small>{{ bindingOf(mapping.binding_id) ? bindingLabel(desk.nodes, bindingOf(mapping.binding_id)!) : mapping.binding_id }}</small>
              </td>
              <td>
                <div class="route">
                  <Badge :text="(mapping.network || 'tcp').toUpperCase()" />
                  <code>{{ endpoint(mapping.listen_host, mapping.listen_port) }}</code>
                  <i aria-hidden="true">→</i>
                  <code>{{ endpoint(mapping.target_host, mapping.target_port) }}</code>
                </div>
              </td>
              <td><Badge :text="mapping.enabled ? '已启用' : '已停用'" :tone="mapping.enabled ? 'good' : ''" /></td>
              <td>
                <div class="actions">
                  <button type="button" class="btn small" @click="openEdit(mapping)">编辑</button>
                  <button type="button" class="btn small" @click="toggle(mapping)">{{ mapping.enabled ? '停用' : '启用' }}</button>
                  <button type="button" class="btn small danger" @click="remove(mapping)">删除</button>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
    <Modal ref="editor" :title="draft.id ? '编辑端口映射' : '新建端口映射'" :disabled="!desk.bindings.length" :submit="saveMapping">
      <p v-if="!desk.bindings.length" class="callout">请先创建网关绑定。</p>
      <div class="grid-2">
        <div>
          <label for="map-name">映射名称</label>
          <input id="map-name" v-model="draft.name" maxlength="128" required />
        </div>
        <div>
          <label for="map-network">协议类型</label>
          <select id="map-network" v-model="draft.network">
            <option value="tcp">TCP</option>
            <option value="udp">UDP (XUDP 封装)</option>
          </select>
        </div>
      </div>
      <label for="map-binding">网关 → 内网节点</label>
      <select id="map-binding" v-model="draft.bindingId">
        <option v-for="binding in desk.bindings" :key="binding.id" :value="binding.id">{{ bindingLabel(desk.nodes, binding) }}</option>
      </select>
      <div class="grid-2">
        <div>
          <label for="map-listen-host">公网监听地址</label>
          <input id="map-listen-host" v-model="draft.listenHost" spellcheck="false" required />
          <small class="help">必须是 IP。0.0.0.0 会暴露到全部 IPv4 接口。</small>
        </div>
        <div>
          <label for="map-listen-port">公网端口</label>
          <input id="map-listen-port" v-model="draft.listenPort" inputmode="numeric" required />
        </div>
      </div>
      <div class="grid-2">
        <div>
          <label for="map-target-host">内网目标地址</label>
          <input id="map-target-host" v-model="draft.targetHost" spellcheck="false" required />
          <small class="help">从内网节点看得到的主机或 IP。</small>
        </div>
        <div>
          <label for="map-target-port">目标端口</label>
          <input id="map-target-port" v-model="draft.targetPort" inputmode="numeric" required />
        </div>
      </div>
      <label class="check" for="map-enabled"><input id="map-enabled" v-model="draft.enabled" type="checkbox" /> 启用这条映射</label>
    </Modal>
    <Modal ref="confirm" :title="confirmTitle" save-label="确认" danger :submit="runConfirm">
      <p class="lead">{{ confirmText }}</p>
    </Modal>
  </div>
</template>
