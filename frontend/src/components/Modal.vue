<script setup lang="ts">
import { nextTick, ref, useId } from 'vue'

const props = withDefaults(
  defineProps<{
    title: string
    kicker?: string
    saveLabel?: string
    cancelLabel?: string
    hideSave?: boolean
    danger?: boolean
    disabled?: boolean
    submit?: () => Promise<boolean>
  }>(),
  {
    kicker: '',
    saveLabel: '保存',
    cancelLabel: '取消',
    hideSave: false,
    danger: false,
    disabled: false,
  },
)

const emit = defineEmits<{ close: [] }>()
const titleId = useId()
const dlg = ref<HTMLDialogElement | null>(null)
const error = ref('')
const busy = ref(false)

function open() {
  error.value = ''
  busy.value = false
  dlg.value?.showModal()
  nextTick(() => dlg.value?.querySelector<HTMLElement>('input, select, textarea, button')?.focus())
}

function close() {
  if (!busy.value) dlg.value?.close()
}

function onCancel(event: Event) {
  if (busy.value) event.preventDefault()
}

function onClose() {
  busy.value = false
  error.value = ''
  emit('close')
}

async function onSubmit() {
  if (!props.submit || busy.value || props.hideSave || props.disabled) return
  busy.value = true
  error.value = ''
  try {
    const shouldClose = await props.submit()
    if (shouldClose) dlg.value?.close()
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '操作失败'
  } finally {
    busy.value = false
  }
}

defineExpose({ open, close })
</script>

<template>
  <dialog ref="dlg" class="modal" :aria-labelledby="titleId" @cancel="onCancel" @close="onClose">
    <form @submit.prevent="onSubmit">
      <header class="modal-head">
        <div>
          <p v-if="kicker" class="kicker">{{ kicker }}</p>
          <h2 :id="titleId">{{ title }}</h2>
        </div>
        <button type="button" class="icon-btn" aria-label="关闭" :disabled="busy" @click="close">×</button>
      </header>
      <fieldset class="modal-body" :disabled="busy">
        <slot />
      </fieldset>
      <p v-if="error" class="error" role="alert">{{ error }}</p>
      <footer class="modal-foot">
        <button type="button" class="btn" :disabled="busy" @click="close">{{ hideSave ? '关闭' : cancelLabel }}</button>
        <button v-if="!hideSave" class="btn" :class="danger ? 'danger' : 'primary'" type="submit" :disabled="busy || disabled">
          {{ busy ? '正在提交…' : saveLabel }}
        </button>
      </footer>
    </form>
  </dialog>
</template>
