import { useRef, useState, type FormEvent, type KeyboardEvent } from 'react'
import { Eye, EyeOff, Globe, Moon, Sun } from 'lucide-react'
import { useConsole } from '../context/ConsoleContext'
import { isImeComposingEnter, triggerHaptic, validateEmailAddress } from '../format'
import { LOCALES } from '../i18n'
import { InlineAlert } from '../components/ui/Badge'
import { Dropdown } from '../components/ui/Controls'

export function LoginView() {
  const { authError, authBusy, submitLogin, theme, toggleTheme, locale, setLocale, dict } = useConsole()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [revealed, setRevealed] = useState(false)
  const [localError, setLocalError] = useState('')
  const composingRef = useRef(false)
  const compEndRef = useRef(0)

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
      setLocalError('请输入密码。')
      return
    }
    triggerHaptic(12)
    void submitLogin(email.trim(), password)
  }

  return (
    <main id="login-main" className="auth-screen">
      <div className="auth-topbar">
        <Dropdown
          menuLabel="语言"
          trigger={(_open, toggle) => (
            <button type="button" className="icon-btn" aria-label="切换语言" onClick={toggle}>
              <Globe size={16} />
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
        <div className="auth-brand">
          <div className="brand-logo" aria-hidden="true">
            <svg viewBox="0 0 32 32" width={18} height={18} fill="currentColor">
              <path d="M7.5 8.5h4.4L16 20.2 20.1 8.5H24.5L17.4 24.5h-2.8L7.5 8.5z" />
            </svg>
          </div>
          <h1 style={{ fontSize: 18, fontWeight: 'var(--fw-semibold)' }}>{dict.login.submit}</h1>
        </div>

        <div className="field">
          <label className="field-label" htmlFor="login-email">
            {dict.login.emailLabel}
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
            <label htmlFor="login-password">{dict.login.passwordLabel}</label>
            <button
              type="button"
              className="btn btn-sm btn-ghost"
              style={{ minHeight: 24, padding: '0 6px' }}
              aria-label={revealed ? '隐藏密码' : '显示密码'}
              aria-pressed={revealed}
              onClick={() => setRevealed((v) => !v)}
            >
              {revealed ? <EyeOff size={13} /> : <Eye size={13} />}
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

        <button type="submit" className="btn btn-primary" disabled={authBusy} style={{ width: '100%', marginBlockStart: 2 }}>
          <span>{authBusy ? dict.login.submitting : dict.login.submit}</span>
        </button>
      </form>
    </main>
  )
}
