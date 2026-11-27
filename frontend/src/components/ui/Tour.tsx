import { useEffect, useState } from 'react'
import { createPortal } from 'react-dom'
import { ArrowLeft, ArrowRight, Check } from 'lucide-react'

export interface TourStep {
  selector: string
  title: string
  description: string
}

export function Tour({
  open,
  steps,
  onClose,
}: {
  open: boolean
  steps: TourStep[]
  onClose: () => void
}) {
  const [index, setIndex] = useState(0)
  const [rect, setRect] = useState<DOMRect | null>(null)

  useEffect(() => {
    if (!open) {
      setIndex(0)
      return
    }
    const update = () => {
      const step = steps[index]
      if (!step) return
      const el = document.querySelector(step.selector)
      if (el) {
        setRect(el.getBoundingClientRect())
      } else {
        setRect(null)
      }
    }
    update()
    window.addEventListener('resize', update)
    window.addEventListener('scroll', update, true)
    return () => {
      window.removeEventListener('resize', update)
      window.removeEventListener('scroll', update, true)
    }
  }, [open, index, steps])

  if (!open || !steps[index]) return null
  const current = steps[index]
  const isLast = index === steps.length - 1

  const cardTop = rect
    ? Math.min(window.innerHeight - 210, Math.max(16, rect.bottom + 14 > window.innerHeight - 200 ? rect.top - 190 : rect.bottom + 14))
    : window.innerHeight / 2 - 90
  const cardLeft = rect
    ? Math.min(window.innerWidth - 356, Math.max(12, rect.left))
    : window.innerWidth / 2 - 170

  return createPortal(
    <div className="tour-spotlight-layer" role="dialog" aria-modal="true" aria-label={current.title}>
      {rect && (
        <div
          className="tour-highlight-ring"
          style={{
            top: rect.top - 4,
            left: rect.left - 4,
            width: rect.width + 8,
            height: rect.height + 8,
          }}
        />
      )}
      <div className="tour-card" style={{ top: cardTop, left: cardLeft }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span className="badge badge-accent tabular">
            {index + 1} / {steps.length}
          </span>
          <button type="button" className="btn btn-sm btn-ghost" onClick={onClose}>
            跳过
          </button>
        </div>
        <h3 style={{ fontSize: 15.5 }}>{current.title}</h3>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)' }}>{current.description}</p>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBlockStart: 6, gap: 8 }}>
          <button
            type="button"
            className="btn btn-sm btn-ghost"
            disabled={index === 0}
            onClick={() => setIndex((i) => Math.max(0, i - 1))}
          >
            <ArrowLeft size={14} className="rtl-flip" />
            <span>上一步</span>
          </button>
          <button
            type="button"
            className="btn btn-sm btn-primary"
            onClick={() => {
              if (isLast) onClose()
              else setIndex((i) => i + 1)
            }}
          >
            <span>{isLast ? '完成导览' : '下一步'}</span>
            {isLast ? <Check size={14} /> : <ArrowRight size={14} className="rtl-flip" />}
          </button>
        </div>
      </div>
    </div>,
    document.body,
  )
}
