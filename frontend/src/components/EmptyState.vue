<script setup lang="ts">
defineProps<{ title: string; text: string }>()
</script>

<template>
  <div class="empty">
    <div class="empty-mark" aria-hidden="true">◇</div>
    <h3>{{ title }}</h3>
    <p>{{ text }}</p>
  </div>
</template>
