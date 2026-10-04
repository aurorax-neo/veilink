<script setup lang="ts">
import { computed, ref } from 'vue'
import { clearServerUrl, getDefaultServerUrl, getServerUrl, hasCustomServerUrl, setServerUrl } from '../api'

const props = defineProps<{ error: string; busy: boolean }>()
const emit = defineEmits<{ submit: [apiKey: string] }>()
const apiKey = ref('')
const defaultUrl = getDefaultServerUrl()
const serverUrl = ref(getServerUrl() || defaultUrl)
const isCustom = computed(() => {
  const s = serverUrl.value.trim().replace(/\/+$/, '')
  return s !== '' && s !== defaultUrl
})
const localError = ref('')

function resetServerUrl() {
  clearServerUrl()
  serverUrl.value = getDefaultServerUrl()
}

function onSubmit() {
  localError.value = ''
  let sUrl = serverUrl.value.trim()
  if (sUrl) {
    if (!/^https?:\/\//i.test(sUrl)) {
      sUrl = 'http://' + sUrl
    }
    sUrl = sUrl.replace(/\/+$/, '')
  }
  setServerUrl(sUrl)
  serverUrl.value = sUrl || defaultUrl

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
          <div class="field-head">
            <label for="server-url">服务地址</label>
            <button
              v-if="isCustom"
              type="button"
              class="text-link"
              @click="resetServerUrl"
            >恢复默认</button>
          </div>
          <input
            id="server-url"
            v-model="serverUrl"
            type="text"
            autocomplete="off"
            spellcheck="false"
            :placeholder="defaultUrl || 'http://127.0.0.1:2545'"
            :disabled="busy"
          />
        </div>
        <div class="login-field">
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
.field-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.text-link {
  background: none;
  border: none;
  padding: 0;
  font-size: 12px;
  color: var(--accent);
  cursor: pointer;
  text-decoration: underline;
}
.text-link:hover {
  color: var(--accent-strong);
}
</style>
