<script setup lang="ts">
import { ref } from 'vue'

defineProps<{ error: string; busy: boolean }>()
const emit = defineEmits<{ submit: [username: string, password: string] }>()
const username = ref('')
const password = ref('')

function onSubmit() {
  emit('submit', username.value, password.value)
}
</script>

<template>
  <div class="login">
    <section class="story">
      <a class="brand" href="#/overview" aria-label="Veilink">
        <svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" /><path d="M7.5 8.5h4.4L16 20.2 20.1 8.5H24.5L17.4 24.5h-2.8L7.5 8.5z" /></svg>
        veilink
        <span>CONTROL</span>
      </a>
      <div>
        <p class="kicker">PRIVATE TCP FABRIC</p>
        <h1>把公网入口接到内网服务。</h1>
        <p class="story-copy">只转发已经登记的 TCP。控制面下发配置，数据面不经过管理中心。</p>
        <ol class="rail" aria-label="数据路径">
          <li><span>01</span><div><strong>访问者</strong><small>公网客户端</small></div></li>
          <li><span>02</span><div><strong>映射端口</strong><small>只接受已登记的 TCP</small></div></li>
          <li><span>03</span><div><strong>公网网关</strong><small>server 上的 VLESS 入口</small></div></li>
          <li><span>04</span><div><strong>内网节点</strong><small>client 主动连出</small></div></li>
          <li><span>05</span><div><strong>目标服务</strong><small>节点自己的网络</small></div></li>
        </ol>
      </div>
      <p class="story-foot">VEILINK / 前端与 master API 分离</p>
    </section>
    <main class="login-main" id="login-main">
      <form class="login-card" @submit.prevent="onSubmit">
        <p class="kicker">管理中心</p>
        <h2>登录</h2>
        <p class="lead">管理节点、绑定和 TCP 映射。账号由初始化命令创建，没有默认密码。</p>
        <label for="username">管理员账号</label>
        <input id="username" v-model="username" name="username" autocomplete="username" required :disabled="busy" />
        <label for="password">密码</label>
        <input id="password" v-model="password" name="password" type="password" autocomplete="current-password" required :disabled="busy" />
        <p v-if="error" class="error" role="alert">{{ error }}</p>
        <button class="btn primary login-submit" type="submit" :disabled="busy">
          {{ busy ? '正在登录…' : '进入控制台' }}
          <span aria-hidden="true">→</span>
        </button>
        <p class="fine">页面运行在独立前端。开发服务器把 /api 转到 master，浏览器仍按同源处理 Cookie 和 CSRF。</p>
      </form>
    </main>
  </div>
</template>
