<script setup lang="ts">
defineProps<{ text: string; tone?: '' | 'good' | 'warn' | 'bad' }>()
</script>

<template>
  <span class="badge" :class="tone || undefined">{{ text }}</span>
</template>
