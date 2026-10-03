<script setup lang="ts">
import { ref } from 'vue'

const props = defineProps<{ error: string; busy: boolean }>()
const emit = defineEmits<{ submit: [apiKey: string] }>()
const apiKey = ref('')
const localError = ref('')

function onSubmit() {
  localError.value = ''
  const key = apiKey.value.trim()
  if (!key) { localError.value = '请输入 API Key'; return }
  if (!key.startsWith('vlk_')) { localError.value = 'API Key 格式不正确，应以 vlk_ 开头'; return }
  emit('submit', key)
}
</script>

<template>
  <div class="login">
    <main class="login-main" id="login-main">
      <form class="login-card" @submit.prevent="onSubmit">
        <h2>Veilink</h2>
        <label for="apikey">API Key</label>
        <input
          id="apikey"
          v-model="apiKey"
          name="apikey"
          type="password"
          autocomplete="off"
          spellcheck="false"
          placeholder="vlk_..."
          required
          :disabled="busy"
        />
        <p v-if="localError || error" class="error" role="alert">{{ localError || error }}</p>
        <button class="btn primary login-submit" type="submit" :disabled="busy">
          {{ busy ? '连接中…' : '进入控制台' }}
          <span aria-hidden="true">→</span>
        </button>
      </form>
    </main>
  </div>
</template>
