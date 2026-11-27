import { Check, AlertCircle, Undo2, X } from 'lucide-react'
import { triggerHaptic } from '../../format'

export interface ToastItem {
  id: number
  text: string
  bad?: boolean
}

export interface SnackbarItem {
  id: number
  text: string
  undoLabel?: string
  onUndo: () => void | Promise<void>
}

export function ToastRegion({
  toasts,
  snackbar,
  onDismissToast,
  onDismissSnackbar,
}: {
  toasts: ToastItem[]
  snackbar: SnackbarItem | null
  onDismissToast: (id: number) => void
  onDismissSnackbar: () => void
}) {
  return (
    <>
      <div className="toast-stack" aria-live="polite" aria-atomic="true">
        {toasts.map((item) => (
          <div
            key={item.id}
            className={`toast-pill ${item.bad ? 'is-bad' : ''}`}
            role={item.bad ? 'alert' : 'status'}
          >
            <span
              className="inline-icon"
              aria-hidden="true"
              style={{ color: item.bad ? 'var(--bad)' : 'var(--good)' }}
            >
              {item.bad ? <AlertCircle size={16} /> : <Check size={16} />}
            </span>
            <span style={{ flex: 1 }}>{item.text}</span>
            <button
              type="button"
              className="icon-btn icon-btn-compact"
              aria-label="关闭提示"
              onClick={() => onDismissToast(item.id)}
            >
              <X size={14} />
            </button>
          </div>
        ))}
      </div>

      {snackbar && (
        <div className="snackbar-host" role="status" aria-live="polite">
          <div key={snackbar.id} className="snackbar-bar">
            <span>{snackbar.text}</span>
            <button
              type="button"
              className="btn btn-sm btn-soft"
              onClick={() => {
                triggerHaptic(14)
                const run = snackbar.onUndo
                onDismissSnackbar()
                void Promise.resolve(run()).catch(() => {})
              }}
            >
              <Undo2 size={14} />
              <span>{snackbar.undoLabel || '撤销'}</span>
            </button>
            <button
              type="button"
              className="icon-btn icon-btn-compact"
              aria-label="关闭"
              onClick={onDismissSnackbar}
            >
              <X size={14} />
            </button>
          </div>
        </div>
      )}
    </>
  )
}
