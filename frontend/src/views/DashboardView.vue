<script setup lang="ts">
import { computed, inject, onMounted, onUnmounted } from 'vue'
import { deskKey, navigateKey } from '../desk'
import { attentionReasons, byNameAndId, heartbeatOnline, presence, revisionState } from '../format'
import { askNodes, nodeBaseline, nodeChanged, registerPageRefresh, waitForReports } from '../pageRefresh'
import Badge from '../components/Badge.vue'
import EmptyState from '../components/EmptyState.vue'

const desk = inject(deskKey)!
const navigate = inject(navigateKey)!
const onlineServers = computed(() => desk.nodes.filter(n => n.role === 'server' && !n.disabled && heartbeatOnline(n)).length)
const onlineClients = computed(() => desk.nodes.filter(n => n.role === 'client' && !n.disabled && heartbeatOnline(n)).length)
const activeMappings = computed(() => desk.mappings.filter(m => m.enabled).length)
const attention = computed(() => desk.nodes.filter(n => attentionReasons(n).length).sort(byNameAndId))
const servers = computed(() => desk.nodes.filter(n => n.role === 'server').sort(byNameAndId))
const totalBindings = computed(() => new Set(desk.mappings.map(m => `${m.server_id}:${m.client_id}`)).size)
function clientCount(id: string) { return new Set(desk.mappings.filter(m => m.server_id === id).map(m => m.client_id)).size }
function mappingCount(id: string) { return desk.mappings.filter(m => m.server_id === id).length }
let active = true
let unregister = () => {}
onMounted(() => {
  unregister = registerPageRefresh(async () => {
    const nodes = desk.nodes.filter(node => !node.revoked)
    const baseline = new Map(nodes.map(node => [node.id, nodeBaseline(node)]))
    const connected = await askNodes(nodes.map(node => node.id))
    const waiting = () => active && connected.some(id => !nodeChanged(desk.nodes.find(node => node.id === id), baseline.get(id)!))
    await waitForReports(() => desk.reload({ silent: true }), waiting)
  })
})
onUnmounted(() => { active = false; unregister() })
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="加载中…" text="" />
  <EmptyState v-else-if="!desk.loaded" title="加载失败" :text="desk.error" />
  <div v-else class="stack">
    <section class="metrics" aria-label="概览">
      <article class="metric"><span>在线服务端</span><strong>{{ onlineServers }}</strong></article>
      <article class="metric"><span>在线客户端</span><strong>{{ onlineClients }}</strong></article>
      <article class="metric"><span>绑定关系</span><strong>{{ totalBindings }}</strong></article>
      <article class="metric"><span>启用映射</span><strong>{{ activeMappings }}</strong></article>
      <article class="metric"><span>待处理节点</span><strong>{{ attention.length }}</strong></article>
    </section>
    <section class="panel">
      <header class="panel-head"><h2>服务端</h2><button type="button" class="btn small" @click="navigate('servers')">管理</button></header>
      <div v-if="servers.length" class="table-scroll" tabindex="0" role="region" aria-label="服务端概览">
        <table><thead><tr><th scope="col">名称</th><th scope="col">状态</th><th scope="col">绑定客户端</th><th scope="col">映射</th><th scope="col">配置</th></tr></thead>
          <tbody><tr v-for="node in servers" :key="node.id"><td>{{ node.name }}</td><td><Badge :text="presence(node).text" :tone="presence(node).tone" /></td><td>{{ clientCount(node.id) }}</td><td>{{ mappingCount(node.id) }}</td><td><Badge :text="revisionState(node).text" :tone="revisionState(node).tone" /></td></tr></tbody>
        </table>
      </div>
      <EmptyState v-else title="暂无服务端" text="" />
    </section>
    <section v-if="attention.length" class="panel">
      <header class="panel-head"><h2>待处理</h2></header>
      <ul class="attention"><li v-for="node in attention" :key="node.id"><button type="button" class="text-btn" @click="navigate(node.role === 'server' ? 'servers' : 'clients')">{{ node.name }}</button><div class="reasons"><Badge v-for="reason in attentionReasons(node)" :key="reason" :text="reason" tone="warn" /></div></li></ul>
    </section>
  </div>
</template>
