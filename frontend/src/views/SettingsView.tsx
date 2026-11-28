import { useCallback, useEffect, useState } from 'react'
import { Compass, Save, Server } from 'lucide-react'
import { api, ApiError } from '../api'
import { useConsole } from '../context/ConsoleContext'
import { LOCALES } from '../i18n'
import { registerPageRefresh } from '../pageRefresh'
import type { LocaleCode, MasterServiceConfig, WebStatus } from '../types'
import { Alert, Badge, EmptyState } from '../components/ui/Badge'
import { Segmented, Select } from '../components/ui/Controls'

export function SettingsView() {
  const { theme, toggleTheme, locale, setLocale, setTourOpen, toast, dict } = useConsole()

  const [status, setStatus] = useState<WebStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState('')

  const [service, setService] = useState<MasterServiceConfig>({ listen_addr: '', scheme: 'http', cert_file: '', key_file: '' })
  const [serviceLoaded, setServiceLoaded] = useState(false)
  const [savingService, setSavingService] = useState(false)
  const [serviceNotice, setServiceNotice] = useState<{ text: string; bad: boolean } | null>(null)

  const loadAll = useCallback(async (silent = false) => {
    if (!silent) {
      setLoading(true)
      setLoadError('')
    }
    try {
      const res = await api<WebStatus>('/web/config')
      setStatus(res)
    } catch (e) {
      if (!silent) setLoadError(e instanceof ApiError ? e.message : '加载失败')
    } finally {
      if (!silent) setLoading(false)
    }

    try {
      const cfg = await api<MasterServiceConfig>('/master/config')
      setService(cfg)
      setServiceLoaded(true)
    } catch (e) {
      setServiceNotice({ text: e instanceof ApiError ? e.message : '服务配置加载失败', bad: true })
    }
  }, [])

  useEffect(() => {
    void loadAll(false)
    return registerPageRefresh(() => loadAll(true))
  }, [loadAll])

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
                <code className="tabular ltr-force" style={{ display: 'block', marginBlockStart: 6, fontWeight: 'var(--fw-semibold)' }}>
                  {status.active_version}
                </code>
              </div>
              <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--surface-1)' }}>
                <div className="cell-sub">监听端点</div>
                <code className="tabular ltr-force" style={{ display: 'block', marginBlockStart: 6, fontWeight: 'var(--fw-medium)' }}>
                  {serviceLoaded && service.listen_addr ? `${service.scheme}://${service.listen_addr}` : '—'}
                </code>
              </div>
              <div style={{ padding: 12, borderRadius: 'var(--radius-md)', background: 'var(--surface-1)' }}>
                <div className="cell-sub">前端资源模式</div>
                <div style={{ marginBlockStart: 6, fontWeight: 'var(--fw-medium)' }}>
                  {status.prebundled ? '内嵌发布包' : status.mode || '标准模式'}
                </div>
              </div>
            </div>
          </div>
        </section>
      )}

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
              <span className="field-label">外观</span>
              <Segmented<'dark' | 'light'>
                ariaLabel="主题切换"
                value={theme}
                onChange={(next) => { if (next !== theme) toggleTheme() }}
                options={[
                  { value: 'dark', label: '深色' },
                  { value: 'light', label: '浅色' },
                ]}
              />
            </div>
            <div className="field">
              <span className="field-label">语言</span>
              <Select<LocaleCode>
                ariaLabel="控制台语言"
                value={locale}
                onChange={setLocale}
                options={LOCALES.map((item) => ({
                  value: item.code,
                  label: `${item.native}${item.dir === 'rtl' ? ' · RTL' : ''}`,
                }))}
              />
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}
