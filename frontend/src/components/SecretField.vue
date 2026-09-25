<script setup lang="ts">
import { ref, watch } from 'vue'
import { copyText } from '../format'
const props = defineProps<{ id: string; label: string; modelValue: string; readonly?: boolean; multiline?: boolean; required?: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [value: string] }>()
const revealed = ref(false)
const status = ref('')
let revision = 0
watch(() => props.modelValue, value => { if (!value) revealed.value = false; status.value = ''; revision++ })
async function copy() {
  const current = revision
  try { await copyText(props.modelValue); if (current === revision) status.value = '已复制，请妥善保管剪贴板内容。' }
  catch { if (current === revision) status.value = '复制失败，请显示后手动复制。' }
}
</script>
<template>
  <div class="secret-field">
    <label :for="id">{{ label }}</label>
    <div class="field-actions">
      <textarea v-if="multiline && revealed" :id="id" :value="modelValue" :readonly="readonly" :required="required" rows="3" class="mono" autocomplete="off" :spellcheck="false" @input="emit('update:modelValue', ($event.target as HTMLTextAreaElement).value)" />
      <input v-else :id="id" :value="modelValue" :type="revealed ? 'text' : 'password'" :readonly="readonly || multiline" :required="required" autocomplete="new-password" :spellcheck="false" @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)" />
      <div class="actions">
        <button type="button" class="btn small" :aria-pressed="revealed" :aria-controls="id" @click="revealed = !revealed">{{ revealed ? '隐藏' : '显示' }}</button>
        <button type="button" class="btn small" :disabled="!modelValue" @click="copy">复制</button>
        <slot />
      </div>
    </div>
    <small v-if="multiline && !readonly && !revealed" class="help">显示后可粘贴或编辑私钥。</small>
    <small v-if="status" class="help" role="status">{{ status }}</small>
  </div>
</template>
