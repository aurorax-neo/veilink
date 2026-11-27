import { useEffect, useState, type FormEvent } from 'react'
import { Compass, Lock, LogOut, Mail, Save, Server, ShieldCheck } from 'lucide-react'
import { api, ApiError } from '../api'
import { useConsole } from '../context/ConsoleContext'
import { evaluatePasswordStrength, formatTime, validateEmailAddress } from '../format'
import { LOCALES } from '../i18n'
import type { LocaleCode, MasterServiceConfig, WebStatus } from '../types'
import { Alert, Badge, EmptyState, InlineAlert } from '../components/ui/Badge'
import { Segmented, Select, Switch } from '../components/ui/Controls'
import { Popconfirm } from '../components/ui/Overlays'

export function SettingsView() {
  const { currentUser, refreshAccount, logout, theme, toggleTheme, locale, setLocale, setTourOpen, toast, dict } = useConsole()

  const [status, setStatus] = useState<WebStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')

  const [service, setService] = useState<MasterServiceConfig>({ listen_addr: '', scheme: 'http', cert_file: '', key_file: '' })
  const [serviceLoaded, setServiceLoaded] = useState(false)
  const [savingService, setSavingService] = useState(false)
  const [serviceNotice, setServiceNotice] = useState<{ text: string; bad: boolean } | null>(null)

  // Email change state
  const [emailCurrentPw, setEmailCurrentPw] = useState('')
  const [newEmail, setNewEmail] = useState('')
  const [savingEmail, setSavingEmail] = useState(false)
  const [emailErr, setEmailErr] = useState('')

  // Password change state
  const [pwCurrent, setPwCurrent] = useState('')
  const [pwNext, setPwNext] = useState('')
  const [pwConfirm, setPwConfirm] = useState('')
  const [revokeOthersOnPw, setRevokeOthersOnPw] = useState(true)
  const [savingPw, setSavingPw] = useState(false)
  const [pwErr, setPwErr] = useState('')

  useEffect(() => {
    void (async () => {
      setLoading(true)
      setLoadError('')
      try {
        const res = await api<WebStatus>('/web/config')
        setStatus(res)
      } catch (e) {
        setLoadError(e instanceof ApiError ? e.message : '加载失败')
      } finally {
        setLoading(false)
      }
    })()

    void (async () => {
      try {
        const cfg = await api<MasterServiceConfig>('/master/config')
        setService(cfg)
        setServiceLoaded(true)
      } catch (e) {
        setServiceNotice({ text: e instanceof ApiError ? e.message : '服务配置加载失败', bad: true })
      }
    })()

    void refreshAccount()
  }, [refreshAccount])

  const saveService = async () => {
    setSavingService(true)
    setServiceNotice(null)
    try {
      const res = await api<{ ok: boolean; need_restart?: string[] }>('/master/config', 'POST', service)
      const text = res.need_restart?.length ? '监听配置已保存，重启 Master 后生效。' : '监听配置已保存。'
      setServiceNotice({ text, bad: false })
      toast(text)
    } catch (e) {
      setServiceNotice({ text: e instanceof ApiError ? e.message : '保存失败', bad: true })
    } finally {
      setSavingService(false)
    }
  }

  const handleChangeEmail = async (e: FormEvent) => {
    e.preventDefault()
    setEmailErr('')
    const problem = validateEmailAddress(newEmail)
    if (problem) {
      setEmailErr(problem)
      return
    }
    if (!emailCurrentPw) {
      setEmailErr('请输入当前管理员密码以验证身份。')
      return
    }
    setSavingEmail(true)
    try {
      await api('/auth/email', 'POST', { current_password: emailCurrentPw, new_email: newEmail.trim() })
      setEmailCurrentPw('')
      setNewEmail('')
      await refreshAccount()
      toast('管理员邮箱已更新。')
    } catch (err) {
      setEmailErr(err instanceof Error ? err.message : '修改邮箱失败')
    } finally {
      setSavingEmail(false)
    }
  }

  const pwStrength = evaluatePasswordStrength(pwNext)

  const handleChangePassword = async (e: FormEvent) => {
    e.preventDefault()
    setPwErr('')
    if (!pwCurrent) {
      setPwErr('请输入当前密码。')
      return
    }
    if (!pwStrength.valid) {
      setPwErr('新密码长度至少需要 8 位。')
      return
    }
    if (pwNext !== pwConfirm) {
      setPwErr('两次输入的新密码不一致。')
      return
    }
    setSavingPw(true)
    try {
      const res = await api<{ ok: boolean; revoked_sessions?: number }>('/auth/password', 'POST', {
        current_password: pwCurrent,
        new_password: pwNext,
        revoke_other_sessions: revokeOthersOnPw,
      })
      setPwCurrent('')
      setPwNext('')
      setPwConfirm('')
      await refreshAccount()
      toast(
        res.revoked_sessions
          ? `密码已更新，并已注销 ${res.revoked_sessions} 个其它会话。`
          : '管理员登录密码已更新。',
      )
    } catch (err) {
      setPwErr(err instanceof Error ? err.message : '修改密码失败')
    } finally {
      setSavingPw(false)
    }
  }

  const handleRevokeOthers = async () => {
    try {
      const res = await api<{ ok: boolean; revoked_sessions: number }>('/auth/sessions/revoke-others', 'POST', {})
      await refreshAccount()
      toast(`已注销 ${res.revoked_sessions || 0} 个其它设备的会话。`)
    } catch (err) {
      toast(err instanceof Error ? err.message : '操作失败', true)
    }
  }

  if (loading) return <div className="panel"><EmptyState title="正在加载系统设置…" /></div>
  if (loadError) return <div className="panel"><EmptyState title="加载失败" description={loadError} /></div>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Runtime Status */}
      {status && (
        <section className="panel">
          <header className="panel-head">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <Server size={16} style={{ color: 'var(--accent-strong)' }} />
              <h2>{dict.settings.runtimeTitle}</h2>
            </div>
            <Badge text={status.serving ? '控制面运行正常' : '不可用'} tone={status.serving ? 'good' : 'bad'} dot pulse={status.serving} />
          </header>
          <div className="panel-body">
            <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))' }}>
              <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--surface-1)' }}>
                <div className="cell-sub">运行版本</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBlockStart: 4, flexWrap: 'wrap' }}>
                  <code className="tabular ltr-force" style={{ fontWeight: 'var(--fw-semibold)' }}>{status.active_version}</code>
                  <Badge text="React 19 Embedded" tone="accent" />
                </div>
              </div>
              <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--surface-1)' }}>
                <div className="cell-sub">当前监听端点</div>
                <code className="tabular ltr-force" style={{ display: 'block', marginBlockStart: 6, fontWeight: 'var(--fw-medium)' }}>
                  {serviceLoaded && service.listen_addr ? `${service.scheme}://${service.listen_addr}` : '加载中…'}
                </code>
              </div>
              <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--surface-1)' }}>
                <div className="cell-sub">安全注册状态</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBlockStart: 4, flexWrap: 'wrap' }}>
                  <Badge text="公开注册已永久锁定" tone="good" dot />
                  <span className="cell-sub tabular">活跃会话 {currentUser?.active_sessions ?? 1}</span>
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Sole Administrator Account & Security */}
      <section className="panel">
        <header className="panel-head">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <ShieldCheck size={16} style={{ color: 'var(--accent-strong)' }} />
            <h2>{dict.settings.accountTitle}</h2>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <Popconfirm
              title="注销除当前设备外的所有已登录会话？"
              confirmLabel="确认注销其它会话"
              onConfirm={handleRevokeOthers}
            >
              {(toggle) => (
                <button type="button" className="btn btn-sm" onClick={toggle}>
                  注销其它会话
                </button>
              )}
            </Popconfirm>
            <button type="button" className="btn btn-sm btn-danger-ghost" onClick={() => void logout()}>
              <LogOut size={14} />
              <span>{dict.common.signOut}</span>
            </button>
          </div>
        </header>

        <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div style={{ padding: 14, borderRadius: 'var(--radius-md)', background: 'var(--surface-1)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
            <div style={{ display: 'grid', gap: 4 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <strong className="ltr-force" style={{ fontSize: 15 }}>{currentUser?.email || '—'}</strong>
                <Badge text="唯一管理员" tone="accent" />
              </div>
              <div className="cell-sub tabular">
                {currentUser?.created_at ? `创建于 ${formatTime(currentUser.created_at)}` : ''}
                {currentUser?.last_login ? ` · 最近登录 ${formatTime(currentUser.last_login)}` : ''}
              </div>
            </div>
            <Badge text="PBKDF2-HMAC-SHA256" tone="good" />
          </div>

          <div className="bento-2">
            {/* Change Email Form */}
            <form
              onSubmit={handleChangeEmail}
              style={{ padding: 16, borderRadius: 'var(--radius-md)', background: 'var(--surface-1)', display: 'flex', flexDirection: 'column', gap: 12 }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontWeight: 'var(--fw-semibold)', fontSize: 14 }}>
                <Mail size={15} style={{ color: 'var(--accent-strong)' }} />
                <span>修改管理员邮箱</span>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="chg-email-new">新邮箱地址</label>
                <input
                  id="chg-email-new"
                  className="ltr-force"
                  type="email"
                  placeholder="new-admin@example.com"
                  value={newEmail}
                  onChange={(e) => {
                    setNewEmail(e.target.value)
                    if (emailErr) setEmailErr('')
                  }}
                />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="chg-email-pw">当前登录密码</label>
                <input
                  id="chg-email-pw"
                  type="password"
                  autoComplete="current-password"
                  value={emailCurrentPw}
                  onChange={(e) => {
                    setEmailCurrentPw(e.target.value)
                    if (emailErr) setEmailErr('')
                  }}
                />
              </div>
              <InlineAlert message={emailErr} />
              <div style={{ marginBlockStart: 'auto', paddingBlockStart: 4 }}>
                <button type="submit" className="btn btn-sm btn-primary" disabled={savingEmail}>
                  <Save size={14} />
                  <span>{savingEmail ? '正在更新…' : '保存新邮箱'}</span>
                </button>
              </div>
            </form>

            {/* Change Password Form */}
            <form
              onSubmit={handleChangePassword}
              style={{ padding: 16, borderRadius: 'var(--radius-md)', background: 'var(--surface-1)', display: 'flex', flexDirection: 'column', gap: 12 }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, fontWeight: 'var(--fw-semibold)', fontSize: 14 }}>
                <Lock size={15} style={{ color: 'var(--accent-strong)' }} />
                <span>修改登录密码</span>
              </div>
              <div className="field">
                <label className="field-label" htmlFor="chg-pw-cur">当前密码</label>
                <input
                  id="chg-pw-cur"
                  type="password"
                  autoComplete="current-password"
                  value={pwCurrent}
                  onChange={(e) => {
                    setPwCurrent(e.target.value)
                    if (pwErr) setPwErr('')
                  }}
                />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="chg-pw-new">新密码（至少 8 位）</label>
                <input
                  id="chg-pw-new"
                  type="password"
                  autoComplete="new-password"
                  value={pwNext}
                  onChange={(e) => {
                    setPwNext(e.target.value)
                    if (pwErr) setPwErr('')
                  }}
                />
                {pwNext.length > 0 && (
                  <div className="strength-bars ltr-force">
                    {[1, 2, 3, 4].map((lvl) => (
                      <span key={lvl} className="strength-seg" data-active={pwStrength.score >= lvl ? pwStrength.tone : 'off'} />
                    ))}
                  </div>
                )}
              </div>
              <div className="field">
                <label className="field-label" htmlFor="chg-pw-confirm">确认新密码</label>
                <input
                  id="chg-pw-confirm"
                  type="password"
                  autoComplete="new-password"
                  value={pwConfirm}
                  onChange={(e) => {
                    setPwConfirm(e.target.value)
                    if (pwErr) setPwErr('')
                  }}
                />
              </div>
              <Switch checked={revokeOthersOnPw} label="修改密码后同时注销其它设备会话" onChange={setRevokeOthersOnPw} />
              <InlineAlert message={pwErr} />
              <div>
                <button type="submit" className="btn btn-sm btn-primary" disabled={savingPw}>
                  <Save size={14} />
                  <span>{savingPw ? '正在更新…' : '更新登录密码'}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      </section>

      {/* Appearance, Internationalization & Guided Tour */}
      <section className="panel">
        <header className="panel-head">
          <h2>{dict.settings.appearanceTitle}</h2>
          <button type="button" className="btn btn-sm btn-soft" onClick={() => setTourOpen(true)}>
            <Compass size={14} />
            <span>{dict.settings.restartTour}</span>
          </button>
        </header>
        <div className="panel-body">
          <div className="form-grid-2">
            <div className="field">
              <span className="field-label">界面外观主题</span>
              <Segmented<'dark' | 'light'>
                ariaLabel="主题切换"
                value={theme}
                onChange={(next) => { if (next !== theme) toggleTheme() }}
                options={[
                  { value: 'dark', label: '深色碳墨（Dark）' },
                  { value: 'light', label: '浅色纸感（Light）' },
                ]}
              />
            </div>
            <div className="field">
              <span className="field-label">控制台语言（支持 RTL 阿拉伯语与多语言排版）</span>
              <Select<LocaleCode>
                ariaLabel="控制台语言"
                value={locale}
                onChange={setLocale}
                options={LOCALES.map((item) => ({
                  value: item.code,
                  label: `${item.native} · ${item.label}${item.dir === 'rtl' ? ' (RTL)' : ''}`,
                }))}
              />
            </div>
          </div>
        </div>
      </section>

      {/* Master Service Configuration */}
      <section className="panel">
        <header className="panel-head">
          <h2>{dict.settings.serviceTitle}</h2>
          <button type="button" className="btn btn-sm btn-primary" disabled={savingService || !serviceLoaded} onClick={() => void saveService()}>
            <Save size={14} />
            <span>{savingService ? dict.common.saving : dict.settings.saveConfig}</span>
          </button>
        </header>
        <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div className="form-grid-2">
            <div className="field">
              <label className="field-label" htmlFor="svc-listen">监听地址（IP:Port）</label>
              <input
                id="svc-listen"
                className="mono ltr-force"
                type="text"
                disabled={!serviceLoaded}
                placeholder="127.0.0.1:2545"
                value={service.listen_addr}
                onChange={(e) => setService((p) => ({ ...p, listen_addr: e.target.value }))}
              />
            </div>
            <div className="field">
              <span className="field-label">管理面协议</span>
              <Segmented<'http' | 'https'>
                ariaLabel="管理协议"
                value={service.scheme}
                disabled={!serviceLoaded}
                onChange={(scheme) => setService((p) => ({ ...p, scheme }))}
                options={[
                  { value: 'http', label: 'HTTP' },
                  { value: 'https', label: 'HTTPS' },
                ]}
              />
            </div>
            {service.scheme === 'https' && (
              <>
                <div className="field">
                  <label className="field-label" htmlFor="svc-cert">TLS 证书文件路径</label>
                  <input
                    id="svc-cert"
                    className="mono ltr-force"
                    type="text"
                    placeholder="/data/cert.pem"
                    value={service.cert_file}
                    onChange={(e) => setService((p) => ({ ...p, cert_file: e.target.value }))}
                  />
                </div>
                <div className="field">
                  <label className="field-label" htmlFor="svc-key">TLS 私钥文件路径</label>
                  <input
                    id="svc-key"
                    className="mono ltr-force"
                    type="text"
                    placeholder="/data/key.pem"
                    value={service.key_file}
                    onChange={(e) => setService((p) => ({ ...p, key_file: e.target.value }))}
                  />
                </div>
              </>
            )}
          </div>
          {serviceNotice && (
            <Alert tone={serviceNotice.bad ? 'bad' : 'info'}>{serviceNotice.text}</Alert>
          )}
        </div>
      </section>
    </div>
  )
}
