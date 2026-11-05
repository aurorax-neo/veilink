<script setup lang="ts">
import { computed, nextTick, onUnmounted, ref, useId } from 'vue'
import Icon from './Icon.vue'

const props = withDefaults(
  defineProps<{
    title: string
    kicker?: string
    saveLabel?: string
    cancelLabel?: string
    hideSave?: boolean
    danger?: boolean
    disabled?: boolean
    size?: 'small' | 'medium' | 'large'
    variant?: 'modal' | 'drawer'
    submit?: () => Promise<boolean>
  }>(),
  {
    kicker: '',
    saveLabel: '保存',
    cancelLabel: '取消',
    hideSave: false,
    danger: false,
    disabled: false,
    size: 'medium',
    variant: 'modal',
  },
)

const emit = defineEmits<{ close: [] }>()
const titleId = useId()
const panel = ref<HTMLElement | null>(null)
const visible = ref(false)
const error = ref('')
const busy = ref(false)
const sheetSnap = ref<'30' | '60' | '80'>('80')
const dragOffsetY = ref(0)
const draggingSheet = ref(false)
let dragStartY = 0
let composing = false
let compositionEndedAt = 0
const isAlert = computed(() => props.danger)
const isDrawer = computed(() => props.variant === 'drawer' && !props.danger)

function onCompositionStart() {
  composing = true
}

function onCompositionEnd() {
  composing = false
  compositionEndedAt = Date.now()
}

function onFormKeydown(event: KeyboardEvent) {
  if (event.key !== 'Enter') return
  if (composing || event.isComposing || event.keyCode === 229 || (compositionEndedAt > 0 && Date.now() - compositionEndedAt < 500)) {
    event.preventDefault()
  }
}

function onSheetPointerDown(event: PointerEvent) {
  if (!isDrawer.value) return
  draggingSheet.value = true
  dragStartY = event.clientY
  dragOffsetY.value = 0
  ;(event.currentTarget as HTMLElement | null)?.setPointerCapture?.(event.pointerId)
}

function onSheetPointerMove(event: PointerEvent) {
  if (!draggingSheet.value) return
  const delta = event.clientY - dragStartY
  // Damped resistance (Spec 6.8 over-damped drag feel)
  dragOffsetY.value = delta > 0 ? delta * 0.65 : delta * 0.25
}

function onSheetPointerUp() {
  if (!draggingSheet.value) return
  const delta = dragOffsetY.value
  draggingSheet.value = false
  dragOffsetY.value = 0
  const order: Array<'30' | '60' | '80'> = ['30', '60', '80']
  const idx = order.indexOf(sheetSnap.value)
  if (delta > 36 && idx > 0) {
    sheetSnap.value = order[idx - 1]!
  } else if (delta < -36 && idx < order.length - 1) {
    sheetSnap.value = order[idx + 1]!
  }
}

function onKeydown(event: KeyboardEvent) {
  if (!visible.value) return
  if (event.key === 'Escape') {
    if (busy.value || isAlert.value) {
      event.preventDefault()
      return
    }
    event.preventDefault()
    close()
  }
}

function open() {
  error.value = ''
  busy.value = false
  sheetSnap.value = '80'
  visible.value = true
  window.addEventListener('keydown', onKeydown)
  nextTick(() => panel.value?.querySelector<HTMLElement>('input, select, textarea, button')?.focus())
}

function close() {
  if (busy.value) return
  visible.value = false
  busy.value = false
  error.value = ''
  window.removeEventListener('keydown', onKeydown)
  emit('close')
}

function onBackdropClick() {
  // Form overlays and AlertDialogs never close on backdrop click.
  if (isAlert.value || !props.hideSave || busy.value) return
  close()
}

async function onSubmit() {
  if (!props.submit || busy.value || props.hideSave || props.disabled) return
  if (composing || (compositionEndedAt > 0 && Date.now() - compositionEndedAt < 500)) return
  busy.value = true
  error.value = ''
  try {
    const shouldClose = await props.submit()
    if (shouldClose) {
      busy.value = false
      close()
    }
  } catch (reason) {
    error.value = reason instanceof Error ? reason.message : '操作失败'
  } finally {
    busy.value = false
  }
}

onUnmounted(() => {
  window.removeEventListener('keydown', onKeydown)
})

defineExpose({ open, close })
</script>

<template>
  <Teleport to="body">
    <div v-if="visible" class="overlay-root" :class="{ 'is-drawer': isDrawer, 'is-alert': isAlert }" @mousedown.self="onBackdropClick">
      <div
        ref="panel"
        class="modal"
        :class="[
          isDrawer ? 'drawer-panel' : `modal-${size}`,
          isDrawer ? `sheet-snap-${sheetSnap}` : '',
          { 'modal-danger': danger, 'is-sheet-dragging': draggingSheet },
        ]"
        :style="isDrawer && dragOffsetY ? { transform: `translateY(${Math.round(dragOffsetY)}px)` } : undefined"
        :role="isAlert ? 'alertdialog' : 'dialog'"
        aria-modal="true"
        :aria-labelledby="titleId"
      >
        <div
          v-if="isDrawer"
          class="sheet-handle-bar"
          aria-label="面板高度档位"
          @pointerdown="onSheetPointerDown"
          @pointermove="onSheetPointerMove"
          @pointerup="onSheetPointerUp"
          @pointercancel="onSheetPointerUp"
        >
          <span class="sheet-drag-grip" aria-hidden="true"></span>
          <div class="sheet-pill-group">
            <button type="button" class="sheet-pill" :class="{ active: sheetSnap === '30' }" @click="sheetSnap = '30'">30%</button>
            <button type="button" class="sheet-pill" :class="{ active: sheetSnap === '60' }" @click="sheetSnap = '60'">60%</button>
            <button type="button" class="sheet-pill" :class="{ active: sheetSnap === '80' }" @click="sheetSnap = '80'">80%</button>
          </div>
        </div>
        <form @submit.prevent="onSubmit" @compositionstart="onCompositionStart" @compositionend="onCompositionEnd" @keydown="onFormKeydown">
          <header class="modal-head">
            <div class="modal-title-group">
              <p v-if="kicker || isAlert" class="kicker" :class="{ 'kicker-danger': isAlert }">
                {{ kicker || (isAlert ? '不可逆高危确认' : '') }}
              </p>
              <h2 :id="titleId">{{ title }}</h2>
            </div>
            <button v-if="!isAlert" type="button" class="icon-btn" aria-label="关闭" :disabled="busy" @click="close">
              <Icon name="close" :size="16" />
            </button>
          </header>
          <div class="modal-body">
            <fieldset class="modal-fields" :disabled="busy">
              <slot />
            </fieldset>
            <p v-if="error" class="error inline-alert" role="alert">{{ error }}</p>
          </div>
          <footer class="modal-foot" :class="{ 'elastic-actions': !hideSave }">
            <button type="button" class="btn modal-cancel" :disabled="busy" @click="close">
              {{ hideSave ? '关闭' : (isAlert ? '保留当前状态' : cancelLabel) }}
            </button>
            <button v-if="!hideSave" class="btn modal-primary" :class="danger ? 'danger-solid' : 'primary'" type="submit" :disabled="busy || disabled">
              {{ busy ? '正在提交…' : saveLabel }}
            </button>
          </footer>
        </form>
      </div>
    </div>
  </Teleport>
</template>
