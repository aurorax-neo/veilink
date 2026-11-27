import { useRef, useState, type FormEvent, type KeyboardEvent } from 'react'
import { Check, Copy, Eye, EyeOff, Globe, Moon, Sun } from 'lucide-react'
import { useConsole } from '../context/ConsoleContext'
import { copyText, evaluatePasswordStrength, isImeComposingEnter, triggerHaptic, validateEmailAddress } from '../format'
import { LOCALES } from '../i18n'
import { InlineAlert } from '../components/ui/Badge'
import { Dropdown } from '../components/ui/Controls'

export function SetupView() {
  const { authError, authBusy, secretFileHint, completeSetup, theme, toggleTheme, locale, setLocale, dict } = useConsole()

  const [installSecret, setInstallSecret] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [localError, setLocalError] = useState('')
  const [copied, setCopied] = useState(false)

  const composingRef = useRef(false)
  const compEndRef = useRef(0)

  const strength = evaluatePasswordStrength(password)
  const emailProblem = email ? validateEmailAddress(email) : null
  const mismatch = confirmPassword.length > 0 && confirmPassword !== password
  const catCmd = `cat ${secretFileHint || '/data/.install_secret'}`

  const handleCopyCmd = async () => {
    try {
      await copyText(catCmd)
      triggerHaptic(10)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } catch { /* ignore */ }
  }

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (composingRef.current || isImeComposingEnter(e.nativeEvent, compEndRef.current)) {
      e.preventDefault()
    }
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (composingRef.current || (compEndRef.current > 0 && Date.now() - compEndRef.current < 500)) return
    setLocalError('')

    if (!installSecret.trim()) {
      setLocalError('请输入安装令牌。')
      return
    }
    const emailErr = validateEmailAddress(email)
    if (emailErr) {
      setLocalError(emailErr)
      return
    }
    if (!strength.valid) {
      setLocalError('密码至少 8 位。')
      return
    }
    if (password !== confirmPassword) {
      setLocalError('两次输入的密码不一致。')
      return
    }

    triggerHaptic(14)
    void completeSetup(installSecret.trim(), email.trim(), password)
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

      <form className="login-card setup-card" onSubmit={handleSubmit}>
        <div className="auth-brand">
          <div className="brand-logo" aria-hidden="true">
            <svg viewBox="0 0 32 32" width={18} height={18} fill="currentColor">
              <path d="M7.5 8.5h4.4L16 20.2 20.1 8.5H24.5L17.4 24.5h-2.8L7.5 8.5z" />
            </svg>
          </div>
          <h1 style={{ fontSize: 18, fontWeight: 'var(--fw-semibold)' }}>{dict.setup.title}</h1>
        </div>

        <div className="field">
          <label className="field-label" htmlFor="setup-secret">
            {dict.setup.secretLabel}
          </label>
          <input
            id="setup-secret"
            name="install_secret"
            className="mono ltr-force"
            type="text"
            value={installSecret}
            placeholder={dict.setup.secretPlaceholder}
            autoComplete="off"
            spellCheck={false}
            disabled={authBusy}
            autoFocus
            onChange={(e) => {
              setInstallSecret(e.target.value)
              if (localError) setLocalError('')
            }}
            onCompositionStart={() => { composingRef.current = true }}
            onCompositionEnd={() => {
              composingRef.current = false
              compEndRef.current = Date.now()
            }}
            onKeyDown={handleKeyDown}
          />
          <div className="setup-cmd-row">
            <code className="mono ltr-force" style={{ fontSize: 11.5 }}>{catCmd}</code>
            <button
              type="button"
              className={`btn btn-sm btn-ghost ${copied ? 'copy-bounce' : ''}`}
              style={{ minWidth: 34, minHeight: 34, padding: '0 8px' }}
              aria-label={dict.common.copy}
              onClick={() => void handleCopyCmd()}
            >
              {copied ? <Check size={12} style={{ color: 'var(--good)' }} /> : <Copy size={12} />}
            </button>
          </div>
        </div>

        <div className="field">
          <label className="field-label" htmlFor="setup-email">
            {dict.setup.emailLabel}
          </label>
          <input
            id="setup-email"
            name="email"
            className="ltr-force"
            type="email"
            value={email}
            placeholder="admin@example.com"
            autoComplete="username"
            spellCheck={false}
            disabled={authBusy}
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
          <InlineAlert message={emailProblem} />
        </div>

        <div className="field">
          <div className="field-label">
            <label htmlFor="setup-password">{dict.setup.passwordLabel}</label>
            <button
              type="button"
              className="btn btn-sm btn-ghost"
              style={{ minHeight: 24, padding: '0 6px' }}
              aria-label={showPassword ? '隐藏密码' : '显示密码'}
              aria-pressed={showPassword}
              onClick={() => setShowPassword((v) => !v)}
            >
              {showPassword ? <EyeOff size={13} /> : <Eye size={13} />}
            </button>
          </div>
          <input
            id="setup-password"
            name="password"
            type={showPassword ? 'text' : 'password'}
            value={password}
            placeholder="至少 8 位"
            autoComplete="new-password"
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
          {password.length > 0 && (
            <div className="strength-bars ltr-force" aria-label={`密码强度：${strength.label}`}>
              {[1, 2, 3, 4].map((lvl) => (
                <span key={lvl} className="strength-seg" data-active={strength.score >= lvl ? strength.tone : 'off'} />
              ))}
            </div>
          )}
        </div>

        <div className="field">
          <label className="field-label" htmlFor="setup-confirm">
            {dict.setup.confirmPasswordLabel}
          </label>
          <input
            id="setup-confirm"
            name="confirm_password"
            type={showPassword ? 'text' : 'password'}
            value={confirmPassword}
            placeholder="再次输入密码"
            autoComplete="new-password"
            disabled={authBusy}
            onChange={(e) => {
              setConfirmPassword(e.target.value)
              if (localError) setLocalError('')
            }}
            onCompositionStart={() => { composingRef.current = true }}
            onCompositionEnd={() => {
              composingRef.current = false
              compEndRef.current = Date.now()
            }}
            onKeyDown={handleKeyDown}
          />
          <InlineAlert message={mismatch ? '两次输入的密码不一致。' : null} />
        </div>

        <InlineAlert message={localError || authError} />

        <button type="submit" className="btn btn-primary" disabled={authBusy} style={{ width: '100%', marginBlockStart: 2 }}>
          <span>{authBusy ? dict.setup.submitting : dict.setup.submit}</span>
        </button>
      </form>
    </main>
  )
}
