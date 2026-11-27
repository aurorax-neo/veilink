import { useRef, useState, type FormEvent, type KeyboardEvent } from 'react'
import { ArrowRight, Check, Copy, Eye, EyeOff, Globe, Lock, Mail, Moon, ShieldAlert, ShieldCheck, Sun, Terminal } from 'lucide-react'
import { useConsole } from '../context/ConsoleContext'
import { copyText, evaluatePasswordStrength, isImeComposingEnter, triggerHaptic, validateEmailAddress } from '../format'
import { LOCALES } from '../i18n'
import { Alert, Badge, InlineAlert } from '../components/ui/Badge'
import { Dropdown } from '../components/ui/Controls'

export function SetupView() {
  const { authError, authBusy, secretFileHint, completeSetup, theme, toggleTheme, locale, setLocale, dict, versionWarning } = useConsole()

  const [installSecret, setInstallSecret] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [localError, setLocalError] = useState('')
  const [copiedCmd, setCopiedCmd] = useState('')

  const composingRef = useRef(false)
  const compEndRef = useRef(0)

  const strength = evaluatePasswordStrength(password)
  const emailProblem = email ? validateEmailAddress(email) : null
  const mismatch = confirmPassword.length > 0 && confirmPassword !== password

  const secretReady = installSecret.trim().length >= 8
  const accountReady = !emailProblem && email.trim().length > 0 && strength.valid && confirmPassword === password && password.length >= 8
  const activeStep = !secretReady ? 1 : !accountReady ? 2 : 3

  const catCmd = `cat ${secretFileHint || '/data/.install_secret'}`

  const handleCopyCmd = async (cmd: string) => {
    try {
      await copyText(cmd)
      triggerHaptic(10)
      setCopiedCmd(cmd)
      window.setTimeout(() => setCopiedCmd((c) => (c === cmd ? '' : c)), 2500)
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
      setLocalError('请输入服务器生成的初始化安全令牌（Install Secret）。')
      return
    }
    const emailErr = validateEmailAddress(email)
    if (emailErr) {
      setLocalError(emailErr)
      return
    }
    if (!strength.valid) {
      setLocalError('管理员密码至少需要 8 位字符。')
      return
    }
    if (password !== confirmPassword) {
      setLocalError('两次输入的密码不一致，请核对后重试。')
      return
    }

    triggerHaptic(14)
    void completeSetup(installSecret.trim(), email.trim(), password)
  }

  return (
    <div className="login-page setup-page">
      {/* Left Architectural Setup Guide (inspired by nginx-ui install flow) */}
      <section className="login-showcase" aria-label="首次安装安全引导">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div className="brand-logo" aria-hidden="true">
            <svg viewBox="0 0 32 32" width={20} height={20} fill="currentColor">
              <path d="M7.5 8.5h4.4L16 20.2 20.1 8.5H24.5L17.4 24.5h-2.8L7.5 8.5z" />
            </svg>
          </div>
          <div>
            <strong style={{ fontSize: 16 }}>Veilink</strong>
            <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>{dict.setup.badge}</div>
          </div>
        </div>

        <div style={{ display: 'grid', gap: 22, marginBlock: 24 }}>
          <div style={{ maxWidth: 480, display: 'grid', gap: 8 }}>
            <Badge text="Install Lock · 防访客抢注" tone="accent" dot pulse />
            <h1 style={{ fontSize: 28, lineHeight: 1.25, letterSpacing: '-0.02em' }}>{dict.setup.title}</h1>
            <p style={{ fontSize: 14, color: 'var(--text-secondary)' }}>{dict.setup.subtitle}</p>
          </div>

          {/* 3-Step Visual Progress Guide */}
          <ol className="setup-stepper" aria-label="初始化步骤">
            {[
              { step: 1, title: dict.setup.step1, done: secretReady },
              { step: 2, title: dict.setup.step2, done: accountReady },
              { step: 3, title: dict.setup.step3, done: false },
            ].map((item) => (
              <li
                key={item.step}
                className={`setup-step ${activeStep === item.step ? 'is-active' : ''} ${item.done ? 'is-done' : ''}`}
              >
                <span className="setup-step-num tabular">
                  {item.done ? <Check size={13} /> : item.step}
                </span>
                <span>{item.title}</span>
              </li>
            ))}
          </ol>

          {/* How to retrieve .install_secret from host */}
          <div className="login-feature" style={{ flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Terminal size={15} style={{ color: 'var(--accent-strong)' }} />
              <strong style={{ fontSize: 13 }}>{dict.setup.guardTitle}</strong>
            </div>
            <p style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>{dict.setup.guardDesc}</p>
            <div className="setup-cmd-row">
              <code className="mono ltr-force" style={{ fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {catCmd}
              </code>
              <button
                type="button"
                className={`btn btn-sm btn-ghost ${copiedCmd === catCmd ? 'copy-bounce' : ''}`}
                style={{ minHeight: 30, padding: '0 8px' }}
                onClick={() => void handleCopyCmd(catCmd)}
              >
                {copiedCmd === catCmd ? <Check size={13} style={{ color: 'var(--good)' }} /> : <Copy size={13} />}
                <span>{copiedCmd === catCmd ? dict.common.copied : dict.common.copy}</span>
              </button>
            </div>
          </div>
        </div>

        <div style={{ fontSize: 12, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <ShieldCheck size={14} style={{ color: 'var(--good)', flexShrink: 0 }} />
          <span>{dict.setup.singleAdminNote}</span>
        </div>
      </section>

      {/* Right Setup Form Pane */}
      <main id="login-main" className="login-auth-pane">
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 6 }}>
          <Dropdown
            menuLabel="切换语言"
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

        <form className="login-card setup-card" onSubmit={handleSubmit}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div className="brand-logo" aria-hidden="true">
              <ShieldAlert size={16} />
            </div>
            <div>
              <h2 style={{ fontSize: 18 }}>{dict.setup.title}</h2>
              <p style={{ fontSize: 12.5, color: 'var(--text-muted)' }}>仅限部署者首次手工初始化</p>
            </div>
          </div>

          {/* Mobile compact hint (when left showcase is hidden on <= 1024px) */}
          <div className="setup-mobile-hint">
            <Alert tone="info">
              <div style={{ display: 'grid', gap: 6 }}>
                <strong>{dict.setup.guardTitle}</strong>
                <span style={{ fontSize: 12 }}>请在服务器终端查看启动日志或执行：</span>
                <code className="mono ltr-force" style={{ fontSize: 11.5, wordBreak: 'break-all' }}>{catCmd}</code>
              </div>
            </Alert>
          </div>

          {versionWarning && <Alert tone="warn">{versionWarning}</Alert>}

          {/* 1. Install Secret */}
          <div className="field">
            <label className="field-label" htmlFor="setup-secret">
              <span>{dict.setup.secretLabel}</span>
              <Badge text="一次性验证" tone="warn" />
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
          </div>

          {/* 2. Administrator Email */}
          <div className="field">
            <label className="field-label" htmlFor="setup-email">
              <span className="inline-icon" style={{ gap: 5 }}>
                <Mail size={13} />
                <span>{dict.setup.emailLabel}</span>
              </span>
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

          {/* 3. Password + Strength Bar */}
          <div className="field">
            <div className="field-label">
              <label htmlFor="setup-password" className="inline-icon" style={{ gap: 5 }}>
                <Lock size={13} />
                <span>{dict.setup.passwordLabel}</span>
              </label>
              <button
                type="button"
                className="btn btn-sm btn-ghost"
                style={{ minHeight: 28, padding: '0 8px' }}
                aria-pressed={showPassword}
                onClick={() => setShowPassword((v) => !v)}
              >
                {showPassword ? <EyeOff size={13} /> : <Eye size={13} />}
                <span>{showPassword ? '隐藏' : '显示'}</span>
              </button>
            </div>
            <input
              id="setup-password"
              name="password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              placeholder="建议混合大小写字母、数字与符号"
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
              <div style={{ display: 'grid', gap: 4, marginBlockStart: 2 }}>
                <div className="strength-bars ltr-force" aria-label={`密码强度：${strength.label}`}>
                  {[1, 2, 3, 4].map((lvl) => (
                    <span
                      key={lvl}
                      className="strength-seg"
                      data-active={strength.score >= lvl ? strength.tone : 'off'}
                    />
                  ))}
                </div>
                <span className="cell-sub">密码强度：{strength.label}</span>
              </div>
            )}
          </div>

          {/* 4. Confirm Password */}
          <div className="field">
            <label className="field-label" htmlFor="setup-confirm">
              {dict.setup.confirmPasswordLabel}
            </label>
            <input
              id="setup-confirm"
              name="confirm_password"
              type={showPassword ? 'text' : 'password'}
              value={confirmPassword}
              placeholder="再次输入登录密码"
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

          <button type="submit" className="btn btn-primary" disabled={authBusy} style={{ width: '100%' }}>
            <span>{authBusy ? dict.setup.submitting : dict.setup.submit}</span>
            <ArrowRight size={15} className="rtl-flip" />
          </button>

          <p className="field-help" style={{ textAlign: 'center' }}>
            {dict.setup.singleAdminNote}
          </p>
        </form>

        <div style={{ textAlign: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
          PBKDF2-HMAC-SHA256 · Single Admin Lock · Same-Origin API v1
        </div>
      </main>
    </div>
  )
}
