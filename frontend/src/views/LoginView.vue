<script setup lang="ts">
import { ref } from 'vue'

const props = defineProps<{ error: string; busy: boolean; register?: boolean }>()
const emit = defineEmits<{ submit: [username: string, password: string] }>()
const username = ref('')
const password = ref('')
const confirm = ref('')
const localError = ref('')

function onSubmit() {
  localError.value = ''
  if (props.register && password.value !== confirm.value) { localError.value = '两次密码不一致'; return }
  const size = new TextEncoder().encode(password.value).length
  if (props.register && (size < 12 || size > 72)) { localError.value = '密码须为 12–72 字节'; return }
  emit('submit', username.value, password.value)
}
</script>

<template>
  <div class="login">
    <main class="login-main" id="login-main">
      <form class="login-card" @submit.prevent="onSubmit">
        <h2>veilink · {{ register ? '首次注册' : '登录' }}</h2>
        <p v-if="register">创建唯一管理员。请在可信网络中完成首次注册。</p>
        <label for="username">管理员账号</label>
        <input id="username" v-model="username" name="username" autocomplete="username" maxlength="128" required :disabled="busy" />
        <label for="password">密码</label>
        <input id="password" v-model="password" name="password" type="password" :autocomplete="register ? 'new-password' : 'current-password'" maxlength="72" required :disabled="busy" />
        <template v-if="register">
          <label for="confirm">确认密码</label>
          <input id="confirm" v-model="confirm" type="password" autocomplete="new-password" maxlength="72" required :disabled="busy" />
        </template>
        <p v-if="localError || error" class="error" role="alert">{{ localError || error }}</p>
        <button class="btn primary login-submit" type="submit" :disabled="busy">
          {{ busy ? '正在提交…' : register ? '创建管理员' : '进入控制台' }}
          <span aria-hidden="true">→</span>
        </button>
      </form>
    </main>
  </div>
</template>
