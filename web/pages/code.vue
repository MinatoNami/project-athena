<script setup lang="ts">
useHead({ title: 'Secrets & config' })
const { data: me } = await useMe()
if (!me.value) await navigateTo('/login')
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">
        <h1>Secrets &amp; configuration</h1>
        <p>
          Credentials committed to repositories (Gitleaks) and misconfigured
          Dockerfiles, Kubernetes, Terraform and Compose files (Trivy). Both run with no
          network, inside the scanner sandbox, over the same checkout as the SBOM.
        </p>
      </div>
    </div>
    <CodeFindingsPanel />
  </div>
</template>
