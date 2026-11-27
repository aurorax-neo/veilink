import { useEffect, useId, useRef, useState, type PointerEvent, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { Check, ChevronDown, Copy, Eye, EyeOff, PanelRightOpen, Search } from 'lucide-react'
import { copyText, triggerHaptic } from '../../format'

/* ============================================================================
   Segmented Control (2–4 options — Spec 3.2: never dropdown for 2 options)
   ============================================================================ */
export interface OptionItem<T extends string = string> {
  value: T
  label: string
  disabled?: boolean
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  ariaLabel,
  disabled = false,
}: {
  value: T
  options: readonly OptionItem<T>[]
  onChange: (next: T) => void
  ariaLabel: string
  disabled?: boolean
}) {
  return (
    <div className="segmented" role="group" aria-label={ariaLabel}>
      {options.map((opt) => (
        <button
          key={opt.value}
          type="button"
          className="segmented-btn"
          aria-pressed={value === opt.value}
          disabled={disabled || opt.disabled}
          onClick={() => {
            triggerHaptic(8)
            onChange(opt.value)
          }}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}

/* ============================================================================
   Switch (boolean 2-state option — Spec 3.2)
   ============================================================================ */
export function Switch({
  checked,
  onChange,
  label,
  disabled = false,
}: {
  checked: boolean
  onChange: (next: boolean) => void
  label: string
  disabled?: boolean
}) {
  return (
    <label className="switch-row" style={{ opacity: disabled ? 0.5 : 1 }}>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        disabled={disabled}
        className="switch-track"
        data-checked={checked ? 'true' : 'false'}
        style={{ border: 0, padding: 0, cursor: disabled ? 'not-allowed' : 'pointer' }}
        onClick={() => {
          triggerHaptic(10)
          onChange(!checked)
        }}
      >
        <span className="switch-thumb" />
      </button>
      <span style={{ fontSize: 13.5, color: 'var(--text-primary)' }}>{label}</span>
    </label>
  )
}

/* ============================================================================
   Select (Spec 3.1 & 3.2):
   - Always has visible input border (distinguished from Dropdown)
   - >10 options automatically enables search input
   - Popover list max-height 264px, auto-flips upward near viewport bottom
   ============================================================================ */
export function Select<T extends string>({
  id,
  value,
  options,
  onChange,
  placeholder = '请选择',
  searchPlaceholder = '搜索选项…',
  disabled = false,
  searchable,
  ariaLabel,
}: {
  id?: string
  value: T
  options: readonly OptionItem<T>[]
  onChange: (next: T) => void
  placeholder?: string
  searchPlaceholder?: string
  disabled?: boolean
  searchable?: boolean
  ariaLabel?: string
}) {
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState<{ top: number; left: number; width: number; openUp: boolean } | null>(null)
  const [query, setQuery] = useState('')
  const rootRef = useRef<HTMLDivElement>(null)
  const popRef = useRef<HTMLDivElement>(null)
  const autoSearch = searchable ?? options.length > 10

  useEffect(() => {
    if (!open) {
      setQuery('')
      setPos(null)
      return
    }
    const updatePos = () => {
      const rect = rootRef.current?.getBoundingClientRect()
      if (!rect) return
      const popWidth = Math.min(Math.max(rect.width, 200), Math.min(360, window.innerWidth - 24))
      const openUp = window.innerHeight - rect.bottom < 300
      const top = openUp ? rect.top - 6 : rect.bottom + 6
      const left = Math.min(window.innerWidth - popWidth - 12, Math.max(12, rect.left))
      setPos({ top, left, width: popWidth, openUp })
    }
    updatePos()
    const onDocDown = (e: MouseEvent) => {
      const target = e.target as Node
      if (rootRef.current?.contains(target) || popRef.current?.contains(target)) return
      setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDocDown)
    window.addEventListener('keydown', onKey)
    window.addEventListener('resize', updatePos)
    window.addEventListener('scroll', updatePos, true)
    return () => {
      document.removeEventListener('mousedown', onDocDown)
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('resize', updatePos)
      window.removeEventListener('scroll', updatePos, true)
    }
  }, [open])

  const selected = options.find((opt) => opt.value === value)
  const filtered = query.trim()
    ? options.filter((opt) => opt.label.toLowerCase().includes(query.trim().toLowerCase()))
    : options

  return (
    <div ref={rootRef} className="select-root">
      <button
        id={id}
        type="button"
        className="select-trigger"
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-label={ariaLabel}
        onClick={() => setOpen((v) => !v)}
      >
        <span className="select-trigger-text" style={{ color: selected ? 'var(--text-primary)' : 'var(--text-muted)' }}>
          {selected ? selected.label : placeholder}
        </span>
        <ChevronDown size={15} style={{ flexShrink: 0, color: 'var(--text-muted)' }} />
      </button>

      {open &&
        pos &&
        createPortal(
          <div
            ref={popRef}
            className="select-popover"
            style={{
              position: 'fixed',
              inset: 'auto',
              top: pos.top,
              left: pos.left,
              width: pos.width,
              minWidth: pos.width,
              transform: pos.openUp ? 'translateY(-100%)' : undefined,
            }}
          >
            {autoSearch && (
              <div style={{ position: 'relative' }}>
                <Search
                  size={13}
                  style={{ position: 'absolute', insetInlineStart: 10, insetBlockStart: 10, color: 'var(--text-muted)', pointerEvents: 'none' }}
                />
                <input
                  type="search"
                  className="select-search"
                  style={{ paddingInlineStart: 30 }}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder={searchPlaceholder}
                  autoFocus
                />
              </div>
            )}
            <div className="select-list" role="listbox" aria-label={ariaLabel || placeholder}>
              {filtered.length === 0 ? (
                <div style={{ padding: '12px 10px', fontSize: 12.5, color: 'var(--text-muted)', textAlign: 'center' }}>
                  无匹配项
                </div>
              ) : (
                filtered.map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    role="option"
                    className="select-option"
                    disabled={opt.disabled}
                    aria-selected={opt.value === value}
                    onClick={() => {
                      onChange(opt.value)
                      setOpen(false)
                    }}
                  >
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{opt.label}</span>
                    {opt.value === value && <Check size={14} style={{ flexShrink: 0 }} />}
                  </button>
                ))
              )}
            </div>
          </div>,
          document.body,
        )}
    </div>
  )
}

/* ============================================================================
   Dropdown (Spec 3.1 & 3.3):
   - Portal-rendered so table overflow-x containers NEVER clip menu items!
   - Command collection (no input border), executes immediately, never writes back value
   - Auto-flips upward when triggered near bottom of viewport
   ============================================================================ */
export interface DropdownItem {
  id: string
  label: string
  icon?: ReactNode
  danger?: boolean
  disabled?: boolean
  separatorBefore?: boolean
  onSelect: () => void
}

export function Dropdown({
  trigger,
  items,
  align = 'end',
  menuLabel = '操作菜单',
}: {
  trigger: (open: boolean, toggle: () => void) => ReactNode
  items: DropdownItem[]
  align?: 'start' | 'end'
  menuLabel?: string
}) {
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState<{ top: number; left: number; openUp: boolean } | null>(null)
  const rootRef = useRef<HTMLDivElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) {
      setPos(null)
      return
    }
    const updatePos = () => {
      const rect = rootRef.current?.getBoundingClientRect()
      if (!rect) return
      const estW = 210
      const isRtl = document.documentElement.dir === 'rtl'
      const alignRight = isRtl ? align === 'start' : align === 'end'
      const openUp = window.innerHeight - rect.bottom < 220
      const top = openUp ? rect.top - 6 : rect.bottom + 6
      const rawLeft = alignRight ? rect.right - estW : rect.left
      const left = Math.min(window.innerWidth - estW - 12, Math.max(12, rawLeft))
      setPos({ top, left, openUp })
    }
    updatePos()
    const onDocDown = (e: MouseEvent) => {
      const target = e.target as Node
      if (rootRef.current?.contains(target) || menuRef.current?.contains(target)) return
      setOpen(false)
    }
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDocDown)
    window.addEventListener('keydown', onKey)
    window.addEventListener('resize', updatePos)
    window.addEventListener('scroll', updatePos, true)
    return () => {
      document.removeEventListener('mousedown', onDocDown)
      window.removeEventListener('keydown', onKey)
      window.removeEventListener('resize', updatePos)
      window.removeEventListener('scroll', updatePos, true)
    }
  }, [open, align])

  return (
    <div ref={rootRef} className="dropdown-root">
      {trigger(open, () => setOpen((v) => !v))}
      {open &&
        pos &&
        createPortal(
          <div
            ref={menuRef}
            className="dropdown-menu"
            style={{
              position: 'fixed',
              inset: 'auto',
              top: pos.top,
              left: pos.left,
              width: 210,
              transform: pos.openUp ? 'translateY(-100%)' : undefined,
            }}
            role="menu"
            aria-label={menuLabel}
          >
            {items.map((item) => (
              <div key={item.id}>
                {item.separatorBefore && <div className="dropdown-sep" role="separator" />}
                <button
                  type="button"
                  role="menuitem"
                  className={`dropdown-item ${item.danger ? 'is-danger' : ''}`}
                  disabled={item.disabled}
                  onClick={() => {
                    triggerHaptic(10)
                    setOpen(false)
                    item.onSelect()
                  }}
                >
                  {item.icon}
                  <span>{item.label}</span>
                </button>
              </div>
            ))}
          </div>,
          document.body,
        )}
    </div>
  )
}

/* ============================================================================
   Collapsible — Spec 6.7 pure CSS Grid 0fr -> 1fr (zero JS height calculation)
   ============================================================================ */
export function Collapsible({
  title,
  badge,
  defaultOpen = false,
  children,
}: {
  title: string
  badge?: ReactNode
  defaultOpen?: boolean
  children: ReactNode
}) {
  const [open, setOpen] = useState(defaultOpen)
  return (
    <div className="collapsible-card">
      <button
        type="button"
        className="collapsible-trigger"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
      >
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
          <span>{title}</span>
          {badge}
        </span>
        <ChevronDown size={16} className="collapsible-chevron" data-open={open ? 'true' : 'false'} />
      </button>
      <div className="collapsible" data-open={open ? 'true' : 'false'}>
        <div className="collapsible-inner">
          <div className="collapsible-content">{children}</div>
        </div>
      </div>
    </div>
  )
}

/* ============================================================================
   SecretField — Masked input/textarea + Spec 6.8 bounce copy (2.5s auto-fade)
   ============================================================================ */
export function SecretField({
  id,
  label,
  value,
  onChange,
  multiline = false,
  required = false,
  readonly = false,
  actions,
}: {
  id?: string
  label: string
  value: string
  onChange: (next: string) => void
  multiline?: boolean
  required?: boolean
  readonly?: boolean
  actions?: ReactNode
}) {
  const autoId = useId()
  const fieldId = id || autoId
  const [revealed, setRevealed] = useState(false)
  const [copied, setCopied] = useState(false)
  const [copyMsg, setCopyMsg] = useState('')
  const timerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  useEffect(() => {
    if (!value) setRevealed(false)
  }, [value])

  useEffect(() => () => { if (timerRef.current) clearTimeout(timerRef.current) }, [])

  const doCopy = async () => {
    try {
      await copyText(value)
      triggerHaptic(12)
      setCopied(true)
      setCopyMsg('已复制，请妥善保管剪贴板内容。')
      if (timerRef.current) clearTimeout(timerRef.current)
      // Spec 6.8: copy checkmark auto-fades after 2.5s
      timerRef.current = setTimeout(() => {
        setCopied(false)
        setCopyMsg('')
      }, 2500)
    } catch {
      setCopyMsg('复制失败，请显示后手动复制。')
    }
  }

  return (
    <div className="field">
      <div className="field-label">
        <label htmlFor={fieldId}>{label}</label>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          {actions}
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            aria-pressed={revealed}
            onClick={() => setRevealed((v) => !v)}
          >
            {revealed ? <EyeOff size={14} /> : <Eye size={14} />}
            <span>{revealed ? '隐藏' : '显示'}</span>
          </button>
          <button
            type="button"
            className={`btn btn-sm btn-ghost ${copied ? 'copy-bounce' : ''}`}
            disabled={!value}
            onClick={doCopy}
          >
            {copied ? <Check size={14} style={{ color: 'var(--good)' }} /> : <Copy size={14} />}
            <span>{copied ? '已复制' : '复制'}</span>
          </button>
        </div>
      </div>

      {multiline && revealed ? (
        <textarea
          id={fieldId}
          className="mono ltr-force"
          rows={3}
          value={value}
          readOnly={readonly}
          required={required}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => onChange(e.target.value)}
        />
      ) : (
        <input
          id={fieldId}
          className="mono ltr-force"
          type={revealed ? 'text' : 'password'}
          value={value}
          readOnly={readonly || multiline}
          required={required}
          spellCheck={false}
          autoComplete="off"
          onChange={(e) => onChange(e.target.value)}
        />
      )}
      {multiline && !readonly && !revealed && (
        <span className="field-help">点击「显示」后可直接粘贴或编辑私钥 PEM。</span>
      )}
      {copyMsg && (
        <span className="field-help" role="status">
          {copyMsg}
        </span>
      )}
    </div>
  )
}

/* ============================================================================
   SplitPane — Spec 7.5 exact mechanics:
   - Transparent drag shield prevents inner content from stealing pointer
   - Esc restores pre-drag ratio
   - Double-click divider resets to 50% / 50%
   - Dragging either side past 80% auto-collapses the opposite side
   ============================================================================ */
export function SplitPane({
  start,
  end,
  defaultRatio = 62,
  showEnd = true,
  restoreEndLabel = '展开详情面板',
}: {
  start: ReactNode
  end: ReactNode
  defaultRatio?: number
  showEnd?: boolean
  restoreEndLabel?: string
}) {
  const [ratio, setRatio] = useState(defaultRatio)
  const [collapsed, setCollapsed] = useState<'none' | 'start' | 'end'>('none')
  const [dragging, setDragging] = useState(false)
  const preDragRatioRef = useRef(defaultRatio)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!dragging) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        setRatio(preDragRatioRef.current)
        setCollapsed('none')
        setDragging(false)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [dragging])

  const onDividerDown = (e: PointerEvent<HTMLDivElement>) => {
    e.preventDefault()
    preDragRatioRef.current = ratio
    setDragging(true)
    e.currentTarget.setPointerCapture?.(e.pointerId)
  }

  const onDividerMove = (e: PointerEvent<HTMLDivElement>) => {
    if (!dragging || !containerRef.current) return
    const rect = containerRef.current.getBoundingClientRect()
    const isRtl = document.documentElement.dir === 'rtl'
    const rawPct = isRtl
      ? ((rect.right - e.clientX) / rect.width) * 100
      : ((e.clientX - rect.left) / rect.width) * 100
    if (rawPct > 80) {
      setCollapsed('end')
      return
    }
    if (rawPct < 20) {
      setCollapsed('start')
      return
    }
    setCollapsed('none')
    setRatio(Math.min(80, Math.max(20, rawPct)))
  }

  const onDividerUp = () => {
    if (dragging) setDragging(false)
  }

  if (!showEnd) {
    return <div className="panel">{start}</div>
  }

  return (
    <div ref={containerRef} className="split-pane">
      {dragging && <div className="split-drag-shield" aria-hidden="true" />}

      {collapsed !== 'start' && (
        <div
          className="split-pane-start"
          style={{ width: collapsed === 'end' ? '100%' : `${ratio}%` }}
        >
          {collapsed === 'end' && (
            <div style={{ padding: '8px 14px', display: 'flex', justifyContent: 'flex-end', borderBlockEnd: 'var(--hairline-width) solid var(--line-hairline)' }}>
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                onClick={() => {
                  setCollapsed('none')
                  setRatio(defaultRatio)
                }}
              >
                <PanelRightOpen size={14} />
                <span>{restoreEndLabel}</span>
              </button>
            </div>
          )}
          {start}
        </div>
      )}

      {collapsed === 'none' && (
        <div
          className={`split-divider ${dragging ? 'is-dragging' : ''}`}
          role="separator"
          aria-orientation="vertical"
          aria-label="拖动调整分栏比例（双击重置 50/50，拖动中按 Esc 取消）"
          title="拖动调整宽度 · 双击 50/50 · 按 Esc 恢复 · 拖过 80% 自动收起"
          onPointerDown={onDividerDown}
          onPointerMove={onDividerMove}
          onPointerUp={onDividerUp}
          onPointerCancel={onDividerUp}
          onDoubleClick={() => {
            setRatio(50)
            setCollapsed('none')
          }}
        />
      )}

      {collapsed !== 'end' && (
        <div
          className="split-pane-end"
          style={{ width: collapsed === 'start' ? '100%' : `${100 - ratio}%` }}
        >
          {collapsed === 'start' && (
            <div style={{ padding: '8px 14px', display: 'flex', justifyContent: 'flex-start', borderBlockEnd: 'var(--hairline-width) solid var(--line-hairline)' }}>
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                onClick={() => {
                  setCollapsed('none')
                  setRatio(defaultRatio)
                }}
              >
                <span>恢复列表视图</span>
              </button>
            </div>
          )}
          {end}
        </div>
      )}
    </div>
  )
}
