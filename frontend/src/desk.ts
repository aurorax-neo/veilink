import type { InjectionKey } from 'vue'
import type { Audit, Mapping, Node, PageId, TrafficRow } from './types'

export interface NoticeUndo {
  label?: string
  run: () => void | Promise<void>
}

export interface Desk {
  nodes: Node[]
  mappings: Mapping[]
  audit: Audit[]
  traffic: TrafficRow[]
  trafficLoaded: boolean
  trafficError: string
  loading: boolean
  refreshing: boolean
  loaded: boolean
  error: string
  notice: string
  noticeBad: boolean
  noticeUndo?: NoticeUndo | null
  reloadNodes: (id: string) => Promise<void>
  reload: (options?: { silent?: boolean }) => Promise<void>
  notify: (text: string, bad?: boolean, undo?: NoticeUndo | null) => void
  dismissNotice: () => void
}

export const deskKey: InjectionKey<Desk> = Symbol('desk')
export const navigateKey: InjectionKey<(page: PageId) => void> = Symbol('navigate')
