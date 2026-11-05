import { api } from './api'
import type { Node } from './types'

const refreshers = new Set<() => Promise<void>>()
const freshlyReported = new Set<string>()
const reloadedAfterReport = new Set<string>()

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
  freshlyReported.delete(node.id)
  reloadedAfterReport.delete(node.id)
  return { seen: node.last_seen, revision: node.applied_revision, error: node.error || '' }
}

export function nodeChanged(node: Node | undefined, baseline: { seen: number; revision: number; error: string }) {
  return !!node && (reloadedAfterReport.has(node.id) || node.last_seen !== baseline.seen || node.applied_revision !== baseline.revision || (node.error || '') !== baseline.error)
}

export async function askNodes(ids: string[]) {
  const connected: string[] = []
  await Promise.all(ids.map(async id => {
    try {
      const result = await api<{ connected?: unknown; reported?: unknown }>(`/nodes/${encodeURIComponent(id)}/refresh`, 'POST', {})
      if (result?.connected === true) {
        connected.push(id)
        if (result?.reported === true) freshlyReported.add(id)
      }
    } catch { /* One node failing to wake does not block the page. */ }
  }))
  return connected
}

function waitEventOrSleep(ms: number) {
  return new Promise<void>(resolve => {
    const bus = (globalThis as Record<string, unknown>).__veilinkStream as { on?: (type: string, fn: (data?: { node_id?: string }) => void) => () => void } | undefined
    let offNode: (() => void) | undefined
    let offTunnel: (() => void) | undefined
    const done = () => {
      offNode?.()
      offTunnel?.()
      clearTimeout(timer)
      resolve()
    }
    const timer = setTimeout(done, ms)
    offNode = bus?.on?.('node', (data) => {
      if (data?.node_id) freshlyReported.add(data.node_id)
      done()
    })
    offTunnel = bus?.on?.('tunnel', (data) => {
      if (data?.node_id) freshlyReported.add(data.node_id)
      done()
    })
  })
}

export async function waitForReports(load: () => Promise<void>, pending: () => boolean, deadline = Date.now() + 15000) {
  while (pending() && Date.now() <= deadline) {
    if (freshlyReported.size > 0) {
      const batch = [...freshlyReported]
      freshlyReported.clear()
      await load()
      for (const id of batch) reloadedAfterReport.add(id)
      if (!pending()) return
    }
    await waitEventOrSleep(200)
    if (!pending()) return
    await load()
  }
}
