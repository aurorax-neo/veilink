<script setup lang="ts">
import { ref } from 'vue'

const props = defineProps<{ error: string; busy: boolean }>()
const emit = defineEmits<{ submit: [apiKey: string] }>()
const apiKey = ref('')
const localError = ref('')
const composing = ref(false)
const compositionEndedAt = ref(0)

function onCompositionStart() {
  composing.value = true
}

function onCompositionEnd() {
  composing.value = false
  compositionEndedAt.value = Date.now()
}

function onInputKeydown(event: KeyboardEvent) {
  if (event.key !== 'Enter') return
  if (composing.value || event.isComposing || event.keyCode === 229 || (compositionEndedAt.value > 0 && Date.now() - compositionEndedAt.value < 500)) {
    event.preventDefault()
  }
}

function onSubmit() {
  if (composing.value || (compositionEndedAt.value > 0 && Date.now() - compositionEndedAt.value < 500)) return
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
        <div class="login-field">
          <label for="apikey">API Key</label>
          <input
            id="apikey"
            v-model="apiKey"
            name="apikey"
            type="password"
            autocomplete="off"
            spellcheck="false"
            required
            :disabled="busy"
            @compositionstart="onCompositionStart"
            @compositionend="onCompositionEnd"
            @keydown="onInputKeydown"
          />
        </div>
        <p v-if="localError || error" class="error" role="alert">{{ localError || error }}</p>
        <button class="btn primary login-submit" type="submit" :disabled="busy">
          {{ busy ? '连接中…' : '进入控制台' }}
          <span aria-hidden="true">→</span>
        </button>
      </form>
    </main>
  </div>
</template>

<style scoped>
.login-field {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-top: 14px;
}
</style>
