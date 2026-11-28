import { useEffect, useId, useRef, useState, type FormEvent, type KeyboardEvent, type PointerEvent, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { AlertTriangle, X } from 'lucide-react'
import { isImeComposingEnter, triggerHaptic } from '../../format'
import { InlineAlert } from './Badge'

/* ============================================================================
   1. Modal — Spec 2.3 exact 400 / 520 / 720px widths; form modals block backdrop close
   ============================================================================ */
export function Modal({
  open,
  onClose,
  title,
  kicker,
  size = 'md',
  isForm = false,
  danger = false,
  saveLabel = '保存',
  cancelLabel = '取消',
  hideFooter = false,
  hideSave = false,
  disabled = false,
  onSubmit,
  children,
}: {
  open: boolean
  onClose: () => void
  title: string
  kicker?: string
  size?: 'sm' | 'md' | 'lg'
  isForm?: boolean
  danger?: boolean
  saveLabel?: string
  cancelLabel?: string
  hideFooter?: boolean
  hideSave?: boolean
  disabled?: boolean
  onSubmit?: () => Promise<boolean> | boolean
  children: ReactNode
}) {
  const titleId = useId()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const composingRef = useRef(false)
  const compEndRef = useRef(0)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  useEffect(() => {
    if (!open) {
      setError('')
      setBusy(false)
      return
    }
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) {
        e.preventDefault()
        onCloseRef.current()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, busy])

  if (!open) return null

  const handleFormSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!onSubmit || busy || disabled || hideSave) return
    if (composingRef.current || (compEndRef.current > 0 && Date.now() - compEndRef.current < 500)) return
    setBusy(true)
    setError('')
    try {
      const shouldClose = await onSubmit()
      if (shouldClose) {
        setBusy(false)
        onClose()
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : '操作失败')
    } finally {
      setBusy(false)
    }
  }

  const handleKeyDown = (e: KeyboardEvent) => {
    if (composingRef.current || isImeComposingEnter(e.nativeEvent, compEndRef.current)) {
      e.preventDefault()
    }
  }

  return createPortal(
    <div
      className="overlay-backdrop"
      onMouseDown={(e) => {
        // Spec 2.5: Form modals NEVER close on backdrop click
        if (e.target === e.currentTarget && !isForm && !busy) onClose()
      }}
    >
      <div
        className={`modal-panel modal-${size}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <form
          onSubmit={handleFormSubmit}
          onCompositionStart={() => { composingRef.current = true }}
          onCompositionEnd={() => {
            composingRef.current = false
            compEndRef.current = Date.now()
          }}
          onKeyDown={handleKeyDown}
          style={{ display: 'flex', flexDirection: 'column', flex: '1 1 auto', minHeight: 0, width: '100%', overflow: 'hidden' }}
        >
          <header className="overlay-head">
            <div>
              {kicker && <p className="overlay-kicker">{kicker}</p>}
              <h2 id={titleId} style={{ fontSize: 16.5 }}>{title}</h2>
            </div>
            <button type="button" className="icon-btn" aria-label="关闭" disabled={busy} onClick={onClose}>
              <X size={16} />
            </button>
          </header>

          <div className="overlay-body">
            <fieldset disabled={busy} style={{ border: 0, margin: 0, padding: 0, display: 'flex', flexDirection: 'column', flexShrink: 0, gap: 16, minWidth: 0 }}>
              {children}
            </fieldset>
            <InlineAlert message={error} />
          </div>

          {!hideFooter && (
            <footer className={`overlay-foot ${hideSave ? 'single-action' : 'elastic-bar'}`}>
              <button
                type="button"
                className={`btn ${hideSave ? 'primary-action' : 'aux-action'}`}
                disabled={busy}
                onClick={onClose}
              >
                {hideSave ? '关闭' : cancelLabel}
              </button>
              {!hideSave && (
                <button
                  type="submit"
                  className={`btn ${danger ? 'btn-danger-solid' : 'btn-primary'} primary-action`}
                  disabled={busy || disabled}
                >
                  {busy ? '处理中…' : saveLabel}
                </button>
              )}
            </footer>
          )}
        </form>
      </div>
    </div>,
    document.body,
  )
}

/* ============================================================================
   2. Drawer (Desktop) + BottomSheet (Mobile 30% / 60% / 80% dvh) — Spec 2.3 & 2.6
   ============================================================================ */
export function Drawer({
  open,
  onClose,
  title,
  kicker,
  wide = false,
  saveLabel = '保存更改',
  cancelLabel = '取消',
  hideSave = false,
  disabled = false,
  onSubmit,
  children,
}: {
  open: boolean
  onClose: () => void
  title: string
  kicker?: string
  wide?: boolean
  saveLabel?: string
  cancelLabel?: string
  hideSave?: boolean
  disabled?: boolean
  onSubmit?: () => Promise<boolean> | boolean
  children: ReactNode
}) {
  const titleId = useId()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [snap, setSnap] = useState<'30' | '60' | '80'>('80')
  const [dragY, setDragY] = useState(0)
  const [dragging, setDragging] = useState(false)
  const dragStartRef = useRef(0)
  const composingRef = useRef(false)
  const compEndRef = useRef(0)
  const onCloseRef = useRef(onClose)
  onCloseRef.current = onClose

  useEffect(() => {
    if (!open) {
      setError('')
      setBusy(false)
      setSnap('80')
      setDragY(0)
      setDragging(false)
      return
    }
    const onKey = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape' && !busy) {
        e.preventDefault()
        onCloseRef.current()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, busy])

  if (!open) return null

  const onPointerDown = (e: PointerEvent<HTMLDivElement>) => {
    // Allow snap pill buttons inside the handle bar to receive normal click events.
    if ((e.target as HTMLElement | null)?.closest('button')) return
    setDragging(true)
    dragStartRef.current = e.clientY
    setDragY(0)
    e.currentTarget.setPointerCapture?.(e.pointerId)
  }
  const onPointerMove = (e: PointerEvent<HTMLDivElement>) => {
    if (!dragging) return
    const delta = e.clientY - dragStartRef.current
    // Spec 6.8 over-damped drag resistance
    setDragY(delta > 0 ? delta * 0.65 : delta * 0.25)
  }
  const onPointerUp = () => {
    if (!dragging) return
    const delta = dragY
    setDragging(false)
    setDragY(0)
    const order: Array<'30' | '60' | '80'> = ['30', '60', '80']
    const idx = order.indexOf(snap)
    if (delta > 40 && idx > 0) {
      setSnap(order[idx - 1])
      triggerHaptic(10)
    } else if (delta < -40 && idx < order.length - 1) {
      setSnap(order[idx + 1])
      triggerHaptic(10)
    }
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!onSubmit || busy || disabled || hideSave) return
    if (composingRef.current || (compEndRef.current > 0 && Date.now() - compEndRef.current < 500)) return
    setBusy(true)
    setError('')
    try {
      const ok = await onSubmit()
      if (ok) {
        setBusy(false)
        onClose()
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : '操作失败')
    } finally {
      setBusy(false)
    }
  }

  return createPortal(
    <div
      className="overlay-backdrop is-drawer"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && hideSave && !busy) onClose()
      }}
    >
      <div
        className={`drawer-panel ${wide ? 'drawer-wide' : ''} snap-${snap} ${dragging ? 'sheet-dragging' : ''}`}
        style={dragY ? { transform: `translateY(${Math.round(dragY)}px)` } : undefined}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <div
          className="sheet-handle"
          aria-label="面板高度档位"
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={onPointerUp}
          onPointerCancel={onPointerUp}
        >
          <span className="sheet-grip" aria-hidden="true" />
          <div className="sheet-snap-pills">
            {(['30', '60', '80'] as const).map((level) => (
              <button
                key={level}
                type="button"
                className="sheet-snap-pill tabular"
                aria-pressed={snap === level}
                onClick={() => setSnap(level)}
              >
                {level}%
              </button>
            ))}
          </div>
        </div>

        <form
          onSubmit={handleSubmit}
          onCompositionStart={() => { composingRef.current = true }}
          onCompositionEnd={() => {
            composingRef.current = false
            compEndRef.current = Date.now()
          }}
          onKeyDown={(e) => {
            if (composingRef.current || isImeComposingEnter(e.nativeEvent, compEndRef.current)) e.preventDefault()
          }}
          style={{ display: 'flex', flexDirection: 'column', flex: 1, minHeight: 0 }}
        >
          <header className="overlay-head">
            <div>
              {kicker && <p className="overlay-kicker">{kicker}</p>}
              <h2 id={titleId} style={{ fontSize: 17 }}>{title}</h2>
            </div>
            <button type="button" className="icon-btn" aria-label="关闭" disabled={busy} onClick={onClose}>
              <X size={16} />
            </button>
          </header>

          <div className="overlay-body">
            <fieldset disabled={busy} style={{ border: 0, margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 18, minWidth: 0 }}>
              {children}
            </fieldset>
            <InlineAlert message={error} />
          </div>

          <footer className={`overlay-foot ${hideSave ? 'single-action' : 'elastic-bar'}`}>
            <button
              type="button"
              className={`btn ${hideSave ? 'primary-action' : 'aux-action'}`}
              disabled={busy}
              onClick={onClose}
            >
              {hideSave ? '关闭' : cancelLabel}
            </button>
            {!hideSave && (
              <button
                type="submit"
                className="btn btn-primary primary-action"
                disabled={busy || disabled}
              >
                {busy ? '正在保存…' : saveLabel}
              </button>
            )}
          </footer>
        </form>
      </div>
    </div>,
    document.body,
  )
}

/* ============================================================================
   3. AlertDialog — Spec 2.4 irreversible destructive ops:
      - Shows concrete quantified loss
      - Blocks backdrop click
      - Disables Esc key
      - Explicit consequence button copy (NEVER "是/否")
   ============================================================================ */
export function AlertDialog({
  open,
  onClose,
  title,
  lossSummary,
  description,
  confirmLabel,
  cancelLabel = '保留当前状态',
  onConfirm,
}: {
  open: boolean
  onClose: () => void
  title: string
  lossSummary: string
  description?: string
  confirmLabel: string
  cancelLabel?: string
  onConfirm: () => Promise<void> | void
}) {
  const titleId = useId()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!open) {
      setBusy(false)
      setError('')
      return
    }
    // Spec 2.4: Explicitly intercept & disable Escape key for irreversible AlertDialog
    const blockEsc = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        e.stopPropagation()
      }
    }
    window.addEventListener('keydown', blockEsc, true)
    return () => window.removeEventListener('keydown', blockEsc, true)
  }, [open])

  if (!open) return null

  const handleConfirm = async () => {
    if (busy) return
    triggerHaptic(18)
    setBusy(true)
    setError('')
    try {
      await onConfirm()
      setBusy(false)
      onClose()
    } catch (err) {
      setError(err instanceof Error ? err.message : '操作失败')
      setBusy(false)
    }
  }

  return createPortal(
    <div className="overlay-backdrop">
      <div
        className="modal-panel modal-sm"
        role="alertdialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <header className="overlay-head">
          <div>
            <p className="overlay-kicker is-danger">
              <span className="inline-icon" style={{ marginInlineEnd: 4 }}>
                <AlertTriangle size={12} />
              </span>
              不可逆高危操作
            </p>
            <h2 id={titleId} style={{ fontSize: 16.5 }}>{title}</h2>
          </div>
        </header>

        <div className="overlay-body">
          <div className="page-banner-alert tone-bad" style={{ padding: '10px 12px' }}>
            <span style={{ fontWeight: 'var(--fw-medium)' }}>{lossSummary}</span>
          </div>
          {description && <p style={{ fontSize: 13.5, color: 'var(--text-secondary)' }}>{description}</p>}
          <InlineAlert message={error} />
        </div>

        <footer className="overlay-foot elastic-bar">
          <button type="button" className="btn aux-action" disabled={busy} onClick={onClose}>
            {cancelLabel}
          </button>
          <button type="button" className="btn btn-danger-solid primary-action" disabled={busy} onClick={handleConfirm}>
            {busy ? '正在执行…' : confirmLabel}
          </button>
        </footer>
      </div>
    </div>,
    document.body,
  )
}

/* ============================================================================
   4. Popconfirm — Spec 2.2 anchored to trigger button with explicit action verbs
   ============================================================================ */
export function Popconfirm({
  title,
  confirmLabel,
  cancelLabel = '保留当前',
  danger = false,
  onConfirm,
  children,
}: {
  title: string
  confirmLabel: string
  cancelLabel?: string
  danger?: boolean
  onConfirm: () => Promise<void> | void
  children: (toggle: () => void, open: boolean) => ReactNode
}) {
  const [open, setOpen] = useState(false)
  const [pos, setPos] = useState<{ top: number; left: number; openUp: boolean } | null>(null)
  const [busy, setBusy] = useState(false)
  const wrapRef = useRef<HTMLDivElement>(null)
  const cardRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) {
      setPos(null)
      return
    }
    const updatePos = () => {
      const rect = wrapRef.current?.getBoundingClientRect()
      if (!rect) return
      const width = 268
      const openUp = window.innerHeight - rect.bottom < 160
      const top = openUp ? rect.top - 8 : rect.bottom + 8
      const left = Math.min(window.innerWidth - width - 12, Math.max(12, rect.right - width))
      setPos({ top, left, openUp })
    }
    updatePos()
    const onDocDown = (e: MouseEvent) => {
      const target = e.target as Node
      if (wrapRef.current?.contains(target) || cardRef.current?.contains(target)) return
      setOpen(false)
    }
    const onKey = (e: globalThis.KeyboardEvent) => {
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

  const run = async () => {
    if (busy) return
    setBusy(true)
    try {
      await onConfirm()
      setOpen(false)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div ref={wrapRef} className="popconfirm-wrap">
      {children(() => setOpen((v) => !v), open)}
      {open &&
        pos &&
        createPortal(
          <div
            ref={cardRef}
            className="popconfirm-card"
            style={{
              position: 'fixed',
              inset: 'auto',
              top: pos.top,
              left: pos.left,
              transform: pos.openUp ? 'translateY(-100%)' : undefined,
            }}
            role="dialog"
            aria-label={title}
          >
            <p style={{ fontSize: 13, fontWeight: 'var(--fw-medium)' }}>{title}</p>
            <div className="popconfirm-actions">
              <button type="button" className="btn btn-sm btn-ghost" disabled={busy} onClick={() => setOpen(false)}>
                {cancelLabel}
              </button>
              <button
                type="button"
                className={`btn btn-sm ${danger ? 'btn-danger-solid' : 'btn-primary'}`}
                disabled={busy}
                onClick={run}
              >
                {busy ? '处理中…' : confirmLabel}
              </button>
            </div>
          </div>,
          document.body,
        )}
    </div>
  )
}

/* ============================================================================
   5. ActionSheet (Mobile) — Spec 2.6 separated Cancel + red danger options
   ============================================================================ */
export interface ActionSheetOption {
  label: string
  icon?: ReactNode
  danger?: boolean
  disabled?: boolean
  onSelect: () => void
}

export function ActionSheet({
  open,
  title,
  options,
  cancelLabel = '取消',
  onClose,
}: {
  open: boolean
  title?: string
  options: ActionSheetOption[]
  cancelLabel?: string
  onClose: () => void
}) {
  if (!open) return null
  return createPortal(
    <div
      className="overlay-backdrop is-action-sheet"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className="action-sheet" role="dialog" aria-modal="true" aria-label={title || '操作菜单'}>
        <div className="action-sheet-group">
          {title && <div className="action-sheet-title">{title}</div>}
          {options.map((opt) => (
            <button
              key={opt.label}
              type="button"
              className={`action-sheet-btn ${opt.danger ? 'is-danger' : ''}`}
              disabled={opt.disabled}
              onClick={() => {
                triggerHaptic(12)
                onClose()
                opt.onSelect()
              }}
            >
              {opt.icon}
              <span>{opt.label}</span>
            </button>
          ))}
        </div>
        <div className="action-sheet-group">
          <button type="button" className="action-sheet-btn" onClick={onClose}>
            {cancelLabel}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}
