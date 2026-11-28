import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { Search } from 'lucide-react'

export interface CommandEntry {
  id: string
  group: string
  label: string
  hint?: string
  icon?: ReactNode
  onSelect: () => void
}

export function CommandPalette({
  open,
  onClose,
  commands,
  placeholder = '输入页面、节点、映射或命令…',
}: {
  open: boolean
  onClose: () => void
  commands: CommandEntry[]
  placeholder?: string
}) {
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  useEffect(() => {
    if (!open) {
      setQuery('')
      setActiveIndex(0)
    }
  }, [open])

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return commands
    return commands.filter((c) => `${c.group} ${c.label} ${c.hint || ''}`.toLowerCase().includes(q))
  }, [commands, query])

  useEffect(() => {
    setActiveIndex(0)
  }, [query])

  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onCloseRef.current()
      } else if (e.key === 'ArrowDown') {
        e.preventDefault()
        setActiveIndex((i) => (filtered.length ? (i + 1) % filtered.length : 0))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setActiveIndex((i) => (filtered.length ? (i - 1 + filtered.length) % filtered.length : 0))
      } else if (e.key === 'Enter' && filtered[activeIndex] && !e.isComposing) {
        e.preventDefault()
        filtered[activeIndex].onSelect()
        onCloseRef.current()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, filtered, activeIndex])

  if (!open) return null

  return createPortal(
    <div
      className="overlay-backdrop"
      style={{ alignItems: 'flex-start', paddingTop: '12vh' }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="cmdk-box" role="dialog" aria-modal="true" aria-label="快速命令面板">
        <div className="cmdk-input-wrap">
          <Search size={17} style={{ color: 'var(--text-muted)', flexShrink: 0 }} />
          <input
            type="search"
            className="cmdk-input"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={placeholder}
            autoFocus
          />
          <span className="cmdk-kbd">ESC</span>
        </div>
        <div className="cmdk-results" role="listbox">
          {filtered.length === 0 ? (
            <div style={{ padding: '24px 12px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
              没有找到匹配的页面或对象
            </div>
          ) : (
            filtered.map((cmd, idx) => (
              <button
                key={cmd.id}
                type="button"
                role="option"
                aria-selected={idx === activeIndex}
                className="select-option"
                style={{
                  background: idx === activeIndex ? 'var(--surface-3)' : undefined,
                  padding: '8px 12px',
                }}
                onMouseEnter={() => setActiveIndex(idx)}
                onClick={() => {
                  cmd.onSelect()
                  onClose()
                }}
              >
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
                  <span style={{ color: 'var(--text-muted)' }}>{cmd.icon}</span>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cmd.label}</span>
                </span>
                <span style={{ fontSize: 11.5, color: 'var(--text-muted)', flexShrink: 0 }}>
                  {cmd.hint || cmd.group}
                </span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>,
    document.body,
  )
}
