<script setup lang="ts">
import { computed, inject } from 'vue'
import { deskKey, navigateKey } from '../desk'
import { actionLabel, attentionReasons, endpoint, heartbeatOnline, nodeName, presence, revisionState } from '../format'
import type { Binding, Node } from '../types'
import Badge from '../components/Badge.vue'
import EmptyState from '../components/EmptyState.vue'

const desk = inject(deskKey)!
const navigate = inject(navigateKey, () => {})
const now = computed(() => Date.now())

const onlineServers = computed(() => desk.nodes.filter((n) => n.role === 'server' && heartbeatOnline(n, now.value)).length)
const onlineClients = computed(() => desk.nodes.filter((n) => n.role === 'client' && heartbeatOnline(n, now.value)).length)
const enabledMaps = computed(() => desk.mappings.filter((m) => m.enabled).length)

const attention = computed(() =>
  desk.nodes
    .map((node) => ({ node, reasons: attentionReasons(node, now.value) }))
    .filter((item) => item.reasons.length)
    .sort((a, b) => a.node.name.localeCompare(b.node.name, 'zh-CN')),
)

const servers = computed(() => desk.nodes.filter((n) => n.role === 'server').sort((a, b) => a.name.localeCompare(b.name, 'zh-CN')))
const recent = computed(() => desk.audit.slice(0, 8))

function bindingsOf(server: Node): Binding[] {
  return desk.bindings.filter((b) => b.server_id === server.id)
}


function mappingsOfBinding(bindingId: string) {
  return desk.mappings.filter((m) => m.binding_id === bindingId)
}

function unboundClients(): Node[] {
  const used = new Set(desk.bindings.map((b) => b.client_id))
  return desk.nodes.filter((n) => n.role === 'client' && !used.has(n.id))
}
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="正在读取配置" text="正在从管理中心获取节点、绑定和映射。" />
  <EmptyState v-else-if="!desk.loaded" title="暂时无法读取配置" :text="(desk.error || '请求失败') + ' 未显示缓存或演示数据。'" />
  <div v-else class="stack">
    <section class="metrics" aria-label="配置摘要">
      <article class="metric"><span>在线服务端</span><strong>{{ onlineServers }}</strong><small>公网网关节点</small></article>
      <article class="metric"><span>在线客户端</span><strong>{{ onlineClients }}</strong><small>内网穿透节点</small></article>
      <article class="metric"><span>活跃映射</span><strong>{{ enabledMaps }}</strong><small>已启用端口转发</small></article>
      <article class="metric"><span>绑定总数</span><strong>{{ desk.bindings.length }}</strong><small>网关与节点配对</small></article>
    </section>

    <div class="split-2">
      <section class="panel">
        <header class="panel-head"><h2>需要处理</h2><small>{{ attention.length }} 个未吊销节点</small></header>
        <ul v-if="attention.length" class="attention">
          <li v-for="item in attention" :key="item.node.id">
            <div>
              <strong>{{ item.node.name }}</strong>
              <small>{{ item.node.role === 'server' ? '公网网关' : '内网节点' }}</small>
            </div>
            <div class="reasons">
              <Badge v-for="reason in item.reasons" :key="reason" :text="reason" :tone="reason === '应用失败' ? 'bad' : 'warn'" />
            </div>
          </li>
        </ul>
        <EmptyState v-else title="没有待处理节点" text="未吊销节点的心跳都在 90 秒内，且期望版本与已应用版本一致。" />
        <div class="panel-foot"><button type="button" class="btn small" @click="navigate('servers')">打开服务端</button></div>
      </section>
      <section class="panel">
        <header class="panel-head"><h2>最近审计</h2><small>最多 8 条</small></header>
        <ol v-if="recent.length" class="timeline compact">
          <li v-for="(item, index) in recent" :key="index">
            <time>{{ new Date(item.at * 1000).toLocaleString('zh-CN', { hour12: false }) }}</time>
            <div>
              <strong>{{ actionLabel(item.action) }}</strong>
              <code>{{ item.object }}</code>
            </div>
          </li>
        </ol>
        <EmptyState v-else title="还没有审计" text="创建节点、绑定或映射后，写操作会出现在这里。" />
        <div class="panel-foot"><button type="button" class="btn small" @click="navigate('audit')">全部审计</button></div>
      </section>
    </div>

    <section class="panel">
      <header class="panel-head"><h2>网络拓扑</h2><small>按公网网关展开</small></header>
      <div v-if="servers.length" class="topo-grid" style="padding: 16px;">
        <article v-for="server in servers" :key="server.id" class="topo-server panel">
          <header>
            <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
              <strong style="font-size: 16px;">{{ server.name }}</strong>
              <Badge :text="presence(server, now).text" :tone="presence(server, now).tone" />
              <Badge :text="revisionState(server).text" :tone="revisionState(server).tone" />
              <code v-if="server.address" style="color: var(--muted);">{{ endpoint(server.address, server.port) }}</code>
            </div>
          </header>
          <p v-if="server.error" class="detail-error">{{ server.error }}</p>
          <div v-if="bindingsOf(server).length" class="topo-clients">
            <div v-for="binding in bindingsOf(server)" :key="binding.id" class="topo-client">
              <div style="display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap;">
                <strong>{{ nodeName(desk.nodes, binding.client_id) }}</strong>
                <code style="color: var(--muted); font-size: 12px;">{{ binding.domain }}</code>
              </div>
              <div v-if="mappingsOfBinding(binding.id).length" class="topo-maps">
                <span v-for="m in mappingsOfBinding(binding.id)" :key="m.id" style="display: inline-flex; gap: 4px; align-items: center;">
                  <Badge :text="(m.network || 'tcp').toUpperCase()" />
                  <code style="font-size: 12px;">{{ endpoint(m.listen_host, m.listen_port) }}</code>
                  <i aria-hidden="true" style="color: var(--muted);">→</i>
                  <code style="font-size: 12px;">{{ endpoint(m.target_host, m.target_port) }}</code>
                  <Badge :text="m.enabled ? '启用' : '停用'" :tone="m.enabled ? 'good' : ''" />
                </span>
              </div>
              <p v-else class="muted" style="margin: 4px 0 0; font-size: 13px;">这条绑定还没有映射。</p>
            </div>
          </div>
          <p v-else class="muted" style="margin: 8px 0 0;">还没有内网节点绑到这个网关。</p>
        </article>
      </div>
      <EmptyState v-else title="还没有公网网关" text="先登记一个 server 节点，再绑定内网节点并添加映射。" />
    </section>

    <section v-if="unboundClients().length" class="panel">
      <header class="panel-head"><h2>尚未绑定的内网节点</h2></header>
      <ul class="plain-list">
        <li v-for="node in unboundClients()" :key="node.id"><strong>{{ node.name }}</strong><code>{{ node.id }}</code></li>
      </ul>
    </section>
  </div>
</template>
