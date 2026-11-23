<script setup lang="ts">
/**
 * Secrets and misconfigurations across every repository Athena patrols.
 *
 * A separate surface from findings on purpose. A leaked credential is not a
 * vulnerability with a CVE and a fixed version: its remedy is rotation, its clock
 * started when it was committed, and the person who handles it is often not the one
 * who upgrades packages.
 */
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
