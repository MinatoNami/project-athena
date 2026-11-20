<script setup lang="ts">
/**
 * What every chart is wrapped in.
 *
 * The table toggle is not a nicety: it is the accessibility fallback and the CSV
 * source (§9), and it is the only way a reader can get the exact figure out of a
 * picture. Empty and loading are distinct states here for the same reason the rest
 * of the product distinguishes them — a chart with no bars and a chart that has not
 * loaded look identical, and mean opposite things.
 */
const props = defineProps<{
  title: string
  note?: string
  pending?: boolean
  empty?: boolean
  /** Said when there is nothing to plot — never left to an empty frame. */
  emptyText?: string
  table: { columns: string[]; rows: (string | number)[][] }
}>()

const showing = ref<'chart' | 'table'>('chart')

function csv() {
  const escape = (c: string | number) => {
    const s = String(c)
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s
  }
  const body = [props.table.columns, ...props.table.rows]
    .map(row => row.map(escape).join(','))
    .join('\n')
  const url = URL.createObjectURL(new Blob([body], { type: 'text/csv' }))
  const a = document.createElement('a')
  a.href = url
  a.download = `${props.title.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.csv`
  a.click()
  URL.revokeObjectURL(url)
}
</script>

<template>
  <figure class="frame">
    <figcaption>
      <span class="lbl">{{ title }}</span>
      <span v-if="note" class="note">{{ note }}</span>
      <span class="sp" />
      <div class="seg">
        <button :class="{ on: showing === 'chart' }" :aria-pressed="showing === 'chart'" @click="showing = 'chart'">Chart</button>
        <button :class="{ on: showing === 'table' }" :aria-pressed="showing === 'table'" @click="showing = 'table'">Table</button>
      </div>
      <button class="btn tiny" :aria-label="`Download ${title} as CSV`" @click="csv">CSV</button>
    </figcaption>

    <div v-if="pending" class="skeleton block" />
    <p v-else-if="empty" class="muted empty">{{ emptyText || 'Nothing to plot yet.' }}</p>

    <template v-else>
      <div v-show="showing === 'chart'"><slot /></div>
      <table v-if="showing === 'table'">
        <thead>
          <tr><th v-for="c in table.columns" :key="c">{{ c }}</th></tr>
        </thead>
        <tbody>
          <tr v-for="(row, i) in table.rows" :key="i">
            <td v-for="(cell, j) in row" :key="j" :class="{ mono: j > 0 }">{{ cell }}</td>
          </tr>
        </tbody>
      </table>
    </template>
  </figure>
</template>

<style scoped>
.frame { margin: 0; border: 1px solid var(--rule); border-radius: 9px;
         background: var(--surface); padding: .7rem .85rem .75rem; }
figcaption { display: flex; align-items: center; gap: .5rem; margin-bottom: .6rem; flex-wrap: wrap; }
/* The note wraps rather than pushing the controls onto a line of their own. */
.note { font-size: .72rem; color: var(--ink-muted); flex: 1 1 10rem; min-width: 0; }
.sp { flex-grow: 1; }
.seg button { font-size: .68rem; padding: .18rem .45rem; }
.btn.tiny { font-size: .68rem; padding: .18rem .45rem; }
.block { height: 120px; }
.empty { margin: .4rem 0 .2rem; }
table { font-size: .78rem; }
th { padding: .25rem .4rem; }
td { padding: .3rem .4rem; }
</style>
