<template>
  <!-- Route changes left the old page under the new URL for seconds with no sign
       anything was happening; the bar says so. Ink, not a brand colour (§8). -->
  <NuxtLoadingIndicator color="currentColor" :height="2" />
  <NuxtLayout>
    <NuxtPage />
  </NuxtLayout>
</template>
