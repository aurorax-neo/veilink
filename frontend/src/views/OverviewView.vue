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
const onlineCount = computed(() => desk.nodes.filter((node) => heartbeatOnline(node, now.value)).length)
const pendingCount = computed(() => desk.nodes.filter((node) => !node.revoked && (node.error || node.applied_revision !== node.desired_revision)).length)
const enabledMaps = computed(() => desk.mappings.filter((mapping) => mapping.enabled).length)
const attention = computed(() =>
  desk.nodes
    .map((node) => ({ node, reasons: attentionReasons(node, now.value) }))
    .filter((item) => item.reasons.length)
    .sort((a, b) => a.node.name.localeCompare(b.node.name, 'zh-CN')),
)
const servers = computed(() => desk.nodes.filter((node) => node.role === 'server').sort((a, b) => a.name.localeCompare(b.name, 'zh-CN')))
const recent = computed(() => desk.audit.slice(0, 6))

function bindingsOf(server: Node): Binding[] {
  return desk.bindings.filter((binding) => binding.server_id === server.id)
}
function unboundClients(): Node[] {
  const used = new Set(desk.bindings.map((binding) => binding.client_id))
  return desk.nodes.filter((node) => node.role === 'client' && !used.has(node.id))
}
</script>

<template>
  <EmptyState v-if="!desk.loaded && desk.loading" title="正在读取配置" text="正在从管理中心获取节点、绑定和映射。" />
  <EmptyState v-else-if="!desk.loaded" title="暂时无法读取配置" :text="(desk.error || '请求失败') + ' 未显示缓存或演示数据。'" />
  <div v-else class="stack">
    <section class="metrics" aria-label="配置摘要">
      <article class="metric"><span>已登记节点</span><strong>{{ desk.nodes.length }}</strong><small>公网网关与内网节点</small></article>
      <article class="metric"><span>近期在线</span><strong>{{ onlineCount }}</strong><small>最近 90 秒有心跳</small></article>
      <article class="metric" :class="{ alert: pendingCount > 0 }"><span>待生效 / 异常</span><strong>{{ pendingCount }}</strong><small>期望版本与应用结果</small></article>
      <article class="metric"><span>已启用映射</span><strong>{{ enabledMaps }}</strong><small>配置状态，不是连通性</small></article>
    </section>
    <p class="callout">配置是最终一致的：相关网关和内网节点都应用到期望版本，才算同步完成。变更会停掉该节点当前隧道，已有连接会被打断。近期在线只比较本机时钟和 last_seen，不探测目标端口。</p>
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
        <div class="panel-foot"><button type="button" class="btn small" @click="navigate('nodes')">打开节点</button></div>
      </section>
      <section class="panel">
        <header class="panel-head"><h2>最近审计</h2><small>最多 6 条</small></header>
        <ol v-if="recent.length" class="timeline compact">
          <li v-for="(item, index) in recent" :key="index">
            <time>{{ new Date(item.at * 1000).toLocaleString('zh-CN', { hour12: false }) }}</time>
            <strong>{{ actionLabel(item.action) }}</strong>
            <code>{{ item.object }}</code>
          </li>
        </ol>
        <EmptyState v-else title="还没有审计" text="创建节点、绑定或映射后，写操作会出现在这里。" />
        <div class="panel-foot"><button type="button" class="btn small" @click="navigate('audit')">全部审计</button></div>
      </section>
    </div>
    <section class="panel">
      <header class="panel-head"><h2>通路</h2><small>按公网网关展开</small></header>
      <div v-if="servers.length" class="lanes">
        <article v-for="server in servers" :key="server.id" class="lane">
          <header>
            <div>
              <strong>{{ server.name }}</strong>
              <code>{{ server.address ? endpoint(server.address, server.port) : '无数据面地址' }}</code>
            </div>
            <Badge :text="presence(server, now).text" :tone="presence(server, now).tone" />
            <Badge :text="revisionState(server).text" :tone="revisionState(server).tone" />
          </header>
          <p v-if="server.error" class="detail-error">{{ server.error }}</p>
          <ul v-if="bindingsOf(server).length">
            <li v-for="binding in bindingsOf(server)" :key="binding.id">
              <div class="pair">
                <strong>{{ nodeName(desk.nodes, binding.client_id) }}</strong>
                <code>{{ binding.domain }}</code>
              </div>
              <ol v-if="desk.mappings.some((mapping) => mapping.binding_id === binding.id)" class="paths">
                <li v-for="mapping in desk.mappings.filter((item) => item.binding_id === binding.id)" :key="mapping.id">
                  <span>{{ mapping.name }}</span>
                  <Badge :text="(mapping.network || 'tcp').toUpperCase()" />
                  <code>{{ endpoint(mapping.listen_host, mapping.listen_port) }}</code>
                  <i aria-hidden="true">→</i>
                  <code>{{ endpoint(mapping.target_host, mapping.target_port) }}</code>
                  <Badge :text="mapping.enabled ? '已启用' : '已停用'" :tone="mapping.enabled ? 'good' : ''" />
                </li>
              </ol>
              <p v-else class="muted tight">这条绑定还没有映射。</p>
            </li>
          </ul>
          <p v-else class="muted tight">还没有内网节点绑到这个网关。</p>
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
    <p class="legend">反向域名只是绑定身份，不是公网 DNS。</p>
  </div>
</template>
