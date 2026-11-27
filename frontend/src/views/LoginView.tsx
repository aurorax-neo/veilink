import { useRef, useState, type FormEvent, type KeyboardEvent } from 'react'
import { ArrowRight, Check, Copy, Eye, EyeOff, Globe, Lock, Mail, Moon, Radio, ShieldCheck, Sun, Waypoints } from 'lucide-react'
import { useConsole } from '../context/ConsoleContext'
import { copyText, isImeComposingEnter, triggerHaptic, validateEmailAddress } from '../format'
import { LOCALES } from '../i18n'
import { Alert, Badge, InlineAlert } from '../components/ui/Badge'
import { Collapsible, Dropdown } from '../components/ui/Controls'

export function LoginView() {
  const { authError, authBusy, submitLogin, theme, toggleTheme, locale, setLocale, dict, versionWarning } = useConsole()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [revealed, setRevealed] = useState(false)
  const [localError, setLocalError] = useState('')
  const [copiedReset, setCopiedReset] = useState(false)
  const composingRef = useRef(false)
  const compEndRef = useRef(0)

  const resetCmd = 'veilink admin reset-password'

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (composingRef.current || isImeComposingEnter(e.nativeEvent, compEndRef.current)) {
      e.preventDefault()
    }
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (composingRef.current || (compEndRef.current > 0 && Date.now() - compEndRef.current < 500)) return
    setLocalError('')
    const emailErr = validateEmailAddress(email)
    if (emailErr) {
      setLocalError(emailErr)
      return
    }
    if (!password) {
      setLocalError('请输入管理员登录密码。')
      return
    }
    triggerHaptic(12)
    void submitLogin(email.trim(), password)
  }

  const copyResetCmd = async () => {
    try {
      await copyText(resetCmd)
      triggerHaptic(10)
      setCopiedReset(true)
      window.setTimeout(() => setCopiedReset(false), 2500)
    } catch { /* ignore */ }
  }

  return (
    <div className="login-page">
      <section className="login-showcase" aria-label="Veilink 架构特性">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div className="brand-logo" aria-hidden="true">
            <svg viewBox="0 0 32 32" width={20} height={20} fill="currentColor">
              <path d="M7.5 8.5h4.4L16 20.2 20.1 8.5H24.5L17.4 24.5h-2.8L7.5 8.5z" />
            </svg>
          </div>
          <div>
            <strong style={{ fontSize: 16 }}>Veilink</strong>
            <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>{dict.login.badge}</div>
          </div>
        </div>

        <div style={{ display: 'grid', gap: 22, marginBlock: 28 }}>
          <div style={{ maxWidth: 480, display: 'grid', gap: 10 }}>
            <h1 style={{ fontSize: 32, lineHeight: 1.22, letterSpacing: '-0.025em' }}>
              {dict.login.headline}
            </h1>
            <p style={{ fontSize: 14.5, color: 'var(--text-secondary)' }}>
              {dict.login.description}
            </p>
          </div>

          <div className="login-features">
            <div className="login-feature">
              <div className="login-feature-icon"><ShieldCheck size={17} /></div>
              <div>
                <div style={{ fontWeight: 'var(--fw-semibold)', fontSize: 13.5 }}>{dict.login.feature1Title}</div>
                <p style={{ fontSize: 12.5, color: 'var(--text-muted)', marginBlockStart: 2 }}>{dict.login.feature1Desc}</p>
              </div>
            </div>
            <div className="login-feature">
              <div className="login-feature-icon"><Waypoints size={17} /></div>
              <div>
                <div style={{ fontWeight: 'var(--fw-semibold)', fontSize: 13.5 }}>{dict.login.feature2Title}</div>
                <p style={{ fontSize: 12.5, color: 'var(--text-muted)', marginBlockStart: 2 }}>{dict.login.feature2Desc}</p>
              </div>
            </div>
            <div className="login-feature">
              <div className="login-feature-icon"><Radio size={17} /></div>
              <div>
                <div style={{ fontWeight: 'var(--fw-semibold)', fontSize: 13.5 }}>{dict.login.feature3Title}</div>
                <p style={{ fontSize: 12.5, color: 'var(--text-muted)', marginBlockStart: 2 }}>{dict.login.feature3Desc}</p>
              </div>
            </div>
          </div>
        </div>

        <div style={{ fontSize: 12, color: 'var(--text-muted)', display: 'flex', gap: 14, flexWrap: 'wrap' }}>
          <span className="ltr-force">VLESS · REALITY · ML-KEM-768</span>
          <span>·</span>
          <span className="ltr-force">XHTTP H1/H2/H3</span>
          <span>·</span>
          <span className="ltr-force">Hysteria2 QUIC</span>
        </div>
      </section>

      <main id="login-main" className="login-auth-pane">
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
          <Dropdown
            menuLabel="界面语言"
            trigger={(_open, toggle) => (
              <button type="button" className="btn btn-sm btn-ghost" onClick={toggle}>
                <Globe size={15} />
                <span>{LOCALES.find((l) => l.code === locale)?.native || locale}</span>
              </button>
            )}
            items={LOCALES.map((item) => ({
              id: item.code,
              label: `${item.native}${item.dir === 'rtl' ? ' · RTL' : ''}`,
              onSelect: () => setLocale(item.code),
            }))}
          />
          <button
            type="button"
            className="icon-btn"
            aria-label={theme === 'dark' ? dict.common.themeLight : dict.common.themeDark}
            onClick={toggleTheme}
          >
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          </button>
        </div>

        <form className="login-card" onSubmit={handleSubmit}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div className="brand-logo" aria-hidden="true">
                <Lock size={16} />
              </div>
              <div>
                <h2 style={{ fontSize: 18 }}>{dict.appName}</h2>
                <p style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>{dict.controlPlane}</p>
              </div>
            </div>
            <Badge text="单管理员锁" tone="good" dot />
          </div>

          {versionWarning && <Alert tone="warn">{versionWarning}</Alert>}

          <div className="field">
            <label className="field-label" htmlFor="login-email">
              <span className="inline-icon" style={{ gap: 5 }}>
                <Mail size={13} />
                <span>{dict.login.emailLabel}</span>
              </span>
            </label>
            <input
              id="login-email"
              name="email"
              className="ltr-force"
              type="email"
              value={email}
              placeholder={dict.login.emailPlaceholder}
              autoComplete="username"
              spellCheck={false}
              disabled={authBusy}
              autoFocus
              onChange={(e) => {
                setEmail(e.target.value)
                if (localError) setLocalError('')
              }}
              onCompositionStart={() => { composingRef.current = true }}
              onCompositionEnd={() => {
                composingRef.current = false
                compEndRef.current = Date.now()
              }}
              onKeyDown={handleKeyDown}
            />
          </div>

          <div className="field">
            <div className="field-label">
              <label htmlFor="login-password" className="inline-icon" style={{ gap: 5 }}>
                <Lock size={13} />
                <span>{dict.login.passwordLabel}</span>
              </label>
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                style={{ minHeight: 28, padding: '0 8px' }}
                aria-pressed={revealed}
                onClick={() => setRevealed((v) => !v)}
              >
                {revealed ? <EyeOff size={13} /> : <Eye size={13} />}
                <span>{revealed ? '隐藏' : '显示'}</span>
              </button>
            </div>
            <input
              id="login-password"
              name="password"
              type={revealed ? 'text' : 'password'}
              value={password}
              placeholder={dict.login.passwordPlaceholder}
              autoComplete="current-password"
              disabled={authBusy}
              onChange={(e) => {
                setPassword(e.target.value)
                if (localError) setLocalError('')
              }}
              onCompositionStart={() => { composingRef.current = true }}
              onCompositionEnd={() => {
                composingRef.current = false
                compEndRef.current = Date.now()
              }}
              onKeyDown={handleKeyDown}
            />
            <InlineAlert message={localError || authError} />
          </div>

          <button type="submit" className="btn btn-primary" disabled={authBusy} style={{ width: '100%' }}>
            <span>{authBusy ? dict.login.submitting : dict.login.submit}</span>
            <ArrowRight size={15} className="rtl-flip" />
          </button>

          <p className="field-help" style={{ textAlign: 'center' }}>
            {dict.login.lockedNotice}
          </p>

          <Collapsible title={dict.login.forgotTitle}>
            <p className="field-help">{dict.login.forgotDesc}</p>
            <div className="setup-cmd-row">
              <code className="mono ltr-force" style={{ fontSize: 12 }}>{resetCmd}</code>
              <button
                type="button"
                className={`btn btn-sm btn-ghost ${copiedReset ? 'copy-bounce' : ''}`}
                style={{ minHeight: 28, padding: '0 8px' }}
                onClick={() => void copyResetCmd()}
              >
                {copiedReset ? <Check size={13} style={{ color: 'var(--good)' }} /> : <Copy size={13} />}
                <span>{copiedReset ? dict.common.copied : dict.common.copy}</span>
              </button>
            </div>
          </Collapsible>
        </form>

        <div style={{ textAlign: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
          HttpOnly Session · PBKDF2-HMAC-SHA256 · Same-Origin API v1
        </div>
      </main>
    </div>
  )
}
