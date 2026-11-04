<script setup lang="ts">
withDefaults(defineProps<{ name: string; size?: number }>(), { size: 16 })
</script>

<template>
  <span class="inline-icon" aria-hidden="true">
    <svg :width="size" :height="size" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.85" stroke-linecap="round" stroke-linejoin="round">
      <template v-if="name === 'dashboard'">
        <rect x="3" y="3" width="7" height="9" rx="1.5" />
        <rect x="14" y="3" width="7" height="5" rx="1.5" />
        <rect x="14" y="12" width="7" height="9" rx="1.5" />
        <rect x="3" y="16" width="7" height="5" rx="1.5" />
      </template>
      <template v-else-if="name === 'servers'">
        <rect x="2" y="3" width="20" height="7" rx="2" />
        <rect x="2" y="14" width="20" height="7" rx="2" />
        <path d="M6 6.5h.01M6 17.5h.01M11 6.5h6M11 17.5h6" />
      </template>
      <template v-else-if="name === 'clients'">
        <rect x="3" y="4" width="18" height="12" rx="2" />
        <path d="M8 20h8M12 16v4" />
      </template>
      <template v-else-if="name === 'proxies'">
        <path d="M17 3l4 4-4 4" />
        <path d="M3 7h18" />
        <path d="M7 21l-4-4 4-4" />
        <path d="M21 17H3" />
      </template>
      <template v-else-if="name === 'logs'">
        <path d="M4 6h16M4 12h16M4 18h10" />
      </template>
      <template v-else-if="name === 'audit'">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="m9 12 2 2 4-4" />
      </template>
      <template v-else-if="name === 'settings'">
        <circle cx="12" cy="12" r="3" />
        <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9c.26.6.77 1.02 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
      </template>
      <template v-else-if="name === 'refresh'">
        <path d="M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
        <path d="M3 3v5h5" />
        <path d="M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16" />
        <path d="M16 16h5v5" />
      </template>
      <template v-else-if="name === 'plus'">
        <path d="M12 5v14M5 12h14" />
      </template>
      <template v-else-if="name === 'search'">
        <circle cx="11" cy="11" r="8" />
        <path d="m21 21-4.3-4.3" />
      </template>
      <template v-else-if="name === 'sun'">
        <circle cx="12" cy="12" r="4" />
        <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41" />
      </template>
      <template v-else-if="name === 'moon'">
        <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
      </template>
      <template v-else-if="name === 'logout'">
        <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
        <polyline points="16 17 21 12 16 7" />
        <line x1="21" y1="12" x2="9" y2="12" />
      </template>
      <template v-else-if="name === 'close'">
        <path d="M18 6 6 18M6 6l12 12" />
      </template>
      <template v-else-if="name === 'check'">
        <path d="M20 6 9 17l-5-5" />
      </template>
      <template v-else-if="name === 'alert'">
        <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z" />
        <path d="M12 9v4M12 17h.01" />
      </template>
      <template v-else-if="name === 'chevron-down'">
        <path d="m6 9 6 6 6-6" />
      </template>
      <template v-else-if="name === 'copy'">
        <rect x="9" y="9" width="13" height="13" rx="2" />
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
      </template>
      <template v-else-if="name === 'key'">
        <circle cx="7.5" cy="15.5" r="5.5" />
        <path d="m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3" />
      </template>
      <template v-else>
        <circle cx="12" cy="12" r="9" />
      </template>
    </svg>
  </span>
</template>
