import { api } from './api'
import type { Node } from './types'

const refreshers = new Set<() => Promise<void>>()

export function registerPageRefresh(refresh: () => Promise<void>) {
  refreshers.add(refresh)
  return () => { refreshers.delete(refresh) }
}

export async function runPageRefresh() {
  await Promise.all([...refreshers].map(async refresh => {
    try { await refresh() } catch { /* The page keeps its own error. */ }
  }))
}

export function nodeBaseline(node: Node) {
  return { seen: node.last_seen, revision: node.applied_revision, error: node.error || '' }
}

export function nodeChanged(node: Node | undefined, baseline: { seen: number; revision: number; error: string }) {
  return !!node && (node.last_seen !== baseline.seen || node.applied_revision !== baseline.revision || (node.error || '') !== baseline.error)
}

export async function askNodes(ids: string[]) {
  const connected: string[] = []
  await Promise.all(ids.map(async id => {
    try {
      const result = await api<{ connected?: unknown }>(`/nodes/${encodeURIComponent(id)}/refresh`, 'POST', {})
      if (result?.connected === true) connected.push(id)
    } catch { /* One node failing to wake does not block the page. */ }
  }))
  return connected
}

function sleep(ms: number) {
  return new Promise(resolve => { setTimeout(resolve, ms) })
}

export async function waitForReports(load: () => Promise<void>, pending: () => boolean, deadline = Date.now() + 15000) {
  while (pending() && Date.now() <= deadline) {
    await sleep(1000)
    if (!pending()) return
    await load()
  }
}
