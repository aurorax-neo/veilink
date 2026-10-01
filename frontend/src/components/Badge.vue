<script setup lang="ts">
defineProps<{ text: string; tone?: '' | 'good' | 'warn' | 'bad'; reserve?: string }>()
</script>

<template>
  <span class="badge" :class="tone || undefined">
    <span v-if="reserve" class="badge-reserve" aria-hidden="true">{{ reserve }}</span>
    <span class="badge-text">{{ text }}</span>
  </span>
</template>
