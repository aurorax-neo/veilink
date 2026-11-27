import type { ReactNode } from 'react'
import { AlertCircle, AlertTriangle, Info } from 'lucide-react'
import type { Tone } from '../../format'

export function Badge({
  text,
  tone = 'neutral',
  dot = false,
  pulse = false,
  title,
  className = '',
}: {
  text: string
  tone?: Tone
  dot?: boolean
  pulse?: boolean
  title?: string
  className?: string
}) {
  return (
    <span className={`badge badge-${tone} ${className}`.trim()} title={title}>
      {dot && <span className={`badge-dot ${pulse ? 'badge-dot-pulse' : ''}`.trim()} aria-hidden="true" />}
      <span>{text}</span>
    </span>
  )
}

export function Tooltip({ content, children }: { content: string; children: ReactNode }) {
  return (
    <span className="tooltip-wrap">
      {children}
      <span className="tooltip-bubble" role="tooltip">
        {content}
      </span>
    </span>
  )
}

export function Alert({
  tone = 'warn',
  children,
  action,
}: {
  tone?: 'warn' | 'bad' | 'info'
  children: ReactNode
  action?: ReactNode
}) {
  const Icon = tone === 'bad' ? AlertCircle : tone === 'warn' ? AlertTriangle : Info
  return (
    <div className={`page-banner-alert tone-${tone}`} role={tone === 'bad' ? 'alert' : 'status'}>
      <span className="inline-icon" aria-hidden="true" style={{ marginBlockStart: 2 }}>
        <Icon size={16} />
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>{children}</div>
      {action}
    </div>
  )
}

export function InlineAlert({
  message,
  tone = 'bad',
  id,
}: {
  message?: string | null
  tone?: 'bad' | 'warn'
  id?: string
}) {
  if (!message) return null
  const Icon = tone === 'warn' ? AlertTriangle : AlertCircle
  return (
    <p id={id} className={`inline-alert tone-${tone}`} role="alert">
      <span className="inline-icon" aria-hidden="true" style={{ marginBlockStart: 1 }}>
        <Icon size={14} />
      </span>
      <span>{message}</span>
    </p>
  )
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: ReactNode
  title: string
  description?: string
  action?: ReactNode
}) {
  return (
    <div className="empty-state">
      {icon && <div className="empty-state-icon" aria-hidden="true">{icon}</div>}
      <h3>{title}</h3>
      {description && <p style={{ maxWidth: 440, fontSize: 13 }}>{description}</p>}
      {action && <div style={{ marginBlockStart: 8 }}>{action}</div>}
    </div>
  )
}
