<script setup lang="ts">
import { computed, inject } from 'vue'
import { deskKey, navigateKey } from '../desk'
import { attentionReasons, heartbeatOnline, nodeName, presence, revisionState } from '../format'
import Badge from '../components/Badge.vue'
import EmptyState from '../components/EmptyState.vue'

const desk = inject(deskKey)!
const navigate = inject(navigateKey)!
const onlineServers = computed(() => desk.nodes.filter(n => n.role === 'server' && heartbeatOnline(n)).length)
const onlineClients = computed(() => desk.nodes.filter(n => n.role === 'client' && heartbeatOnline(n)).length)
const attention = computed(() => desk.nodes.filter(n => attentionReasons(n).length))
const servers = computed(() => desk.nodes.filter(n => n.role === 'server'))
function clientsOf(id: string) { return [...new Set(desk.mappings.filter(m => m.server_id === id).map(m => nodeName(desk.nodes, m.client_id)))].join('、') || '—' }
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="加载中…" text="" />
  <EmptyState v-else-if="!desk.loaded" title="加载失败" :text="desk.error" />
  <div v-else class="stack">
    <section class="metrics" aria-label="概览">
      <article class="metric"><span>在线服务端</span><strong>{{ onlineServers }}</strong></article>
      <article class="metric"><span>在线客户端</span><strong>{{ onlineClients }}</strong></article>
      <article class="metric"><span>启用映射</span><strong>{{ desk.mappings.filter(m => m.enabled).length }}</strong></article>
      <article class="metric"><span>待处理节点</span><strong>{{ attention.length }}</strong></article>
    </section>
    <section class="panel">
      <header class="panel-head"><h2>服务端</h2><button type="button" class="btn small" @click="navigate('servers')">管理</button></header>
      <div v-if="servers.length" class="table-scroll" tabindex="0" role="region" aria-label="服务端概览">
        <table><thead><tr><th scope="col">名称</th><th scope="col">状态</th><th scope="col">客户端</th><th scope="col">映射</th><th scope="col">配置</th></tr></thead>
          <tbody><tr v-for="node in servers" :key="node.id"><td>{{ node.name }}</td><td><Badge :text="presence(node).text" :tone="presence(node).tone" /></td><td>{{ clientsOf(node.id) }}</td><td>{{ desk.mappings.filter(m => m.server_id === node.id).length }}</td><td><Badge :text="revisionState(node).text" :tone="revisionState(node).tone" /></td></tr></tbody>
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
