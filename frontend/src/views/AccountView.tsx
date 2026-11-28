import { useEffect, useState, type FormEvent } from 'react'
import { Lock, LogOut, Mail, Save, ShieldCheck } from 'lucide-react'
import { api } from '../api'
import { useConsole } from '../context/ConsoleContext'
import { evaluatePasswordStrength, formatTime, validateEmailAddress } from '../format'
import { registerPageRefresh } from '../pageRefresh'
import { Badge, InlineAlert } from '../components/ui/Badge'
import { Switch } from '../components/ui/Controls'
import { Popconfirm } from '../components/ui/Overlays'

export function AccountView() {
  const { currentUser, refreshAccount, requestLogout, toast, dict } = useConsole()

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
    void refreshAccount()
    return registerPageRefresh(() => refreshAccount())
  }, [refreshAccount])

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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
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
            <button type="button" className="btn btn-sm btn-danger-ghost" onClick={requestLogout}>
              <LogOut size={14} />
              <span>{dict.common.signOut}</span>
            </button>
          </div>
        </header>

        <div className="panel-body" style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div className="kpi-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))' }}>
            <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--surface-1)' }}>
              <div className="cell-sub">管理员邮箱</div>
              <div style={{ marginBlockStart: 6, display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                <strong className="ltr-force" style={{ fontSize: 14 }}>{currentUser?.email || '—'}</strong>
                <Badge text="唯一管理员" tone="accent" />
              </div>
            </div>
            <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--surface-1)' }}>
              <div className="cell-sub">活跃会话</div>
              <div className="tabular" style={{ marginBlockStart: 6, fontWeight: 'var(--fw-semibold)', fontSize: 15 }}>
                {currentUser?.active_sessions ?? 1}
              </div>
            </div>
            <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--surface-1)' }}>
              <div className="cell-sub">最近登录</div>
              <div className="tabular" style={{ marginBlockStart: 6, fontWeight: 'var(--fw-medium)', fontSize: 13.5 }}>
                {currentUser?.last_login ? formatTime(currentUser.last_login) : '—'}
              </div>
            </div>
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
    </div>
  )
}
