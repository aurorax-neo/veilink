import type { InjectionKey } from 'vue'
import type { Audit, Mapping, Node, PageId, TrafficRow } from './types'

export interface Desk {
  nodes: Node[]
  mappings: Mapping[]
  audit: Audit[]
  traffic: TrafficRow[]
  trafficLoaded: boolean
  trafficError: string
  loading: boolean
  loaded: boolean
  error: string
  notice: string
  noticeBad: boolean
  reload: (options?: { silent?: boolean }) => Promise<void>
  notify: (text: string, bad?: boolean) => void
}

export const deskKey: InjectionKey<Desk> = Symbol('desk')
export const navigateKey: InjectionKey<(page: PageId) => void> = Symbol('navigate')
