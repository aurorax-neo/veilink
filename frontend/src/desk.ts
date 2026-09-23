import type { InjectionKey } from 'vue'
import type { Audit, Binding, Mapping, Node, PageId } from './types'

export interface Desk {
  nodes: Node[]
  bindings: Binding[]
  mappings: Mapping[]
  audit: Audit[]
  loading: boolean
  loaded: boolean
  error: string
  notice: string
  noticeBad: boolean
  reload: () => Promise<void>
  notify: (text: string, bad?: boolean) => void
}

export const deskKey: InjectionKey<Desk> = Symbol('desk')
export const navigateKey: InjectionKey<(page: PageId) => void> = Symbol('navigate')
