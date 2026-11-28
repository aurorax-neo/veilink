import { useEffect, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { Plus, Sparkles, Trash2, Upload } from 'lucide-react'
import { api } from '../api'
import { PEM_MAX_BYTES, truncateFileName, validatePEM } from '../format'
import { buildNodeSavePayload, effectiveXhttpMode, isFlowAllowed, nodeToDraft, parseXHTTPHeaders, type MetaPlacement, type NodeDraft, type NodeGenOptions, type PaddingPlacement, type XhttpMode } from '../lib/nodePayload'
import type { ConnectEndpoint, Node, TunnelConfig } from '../types'
import { Badge, InlineAlert } from './ui/Badge'
import { Collapsible, SecretField, Segmented, Select, Switch } from './ui/Controls'
import { Modal } from './ui/Overlays'

type PEMField = 'cert' | 'key' | 'ca'
type GenerateKind = 'reality' | 'short_id' | 'mldsa65' | 'vless' | 'hysteria2' | 'certificate'

const NODE_DRAFT_KEY = 'veilink_react_node_draft_v1'

export function NodeEditorDrawer({
  open,
  role,
  node,
  defaultName,
  onClose,
  onSaved,
}: {
  open: boolean
  role: 'server' | 'client'
  node: Node | null
  defaultName: string
  onClose: () => void
  onSaved: (saved: Node) => Promise<void>
}) {
  const isServer = role === 'server'
  const init = useMemo(() => nodeToDraft(node || undefined, defaultName), [node, defaultName])

  const [draft, setDraft] = useState<NodeDraft>(init.draft)
  const [endpoints, setEndpoints] = useState<ConnectEndpoint[]>(init.endpoints)
  const [options, setOptions] = useState<NodeGenOptions>(init.options)
  const [originalTunnel, setOriginalTunnel] = useState<TunnelConfig>(init.originalTunnel)

  const [hasSavedDraft, setHasSavedDraft] = useState(false)
  const [genBusy, setGenBusy] = useState<GenerateKind | ''>('')
  const [genStatus, setGenStatus] = useState('')
  const [genError, setGenError] = useState('')
  const [headersError, setHeadersError] = useState('')
  const [uploads, setUploads] = useState<Record<PEMField, { busy: boolean; error: string; status: string; fileName: string }>>({
    cert: { busy: false, error: '', status: '', fileName: '' },
    key: { busy: false, error: '', status: '', fileName: '' },
    ca: { busy: false, error: '', status: '', fileName: '' },
  })
  const endpointAutoPortRef = useRef(!node)
  const genRevRef = useRef(0)
  const nodeRef = useRef(node)
  nodeRef.current = node
  const defaultNameRef = useRef(defaultName)
  defaultNameRef.current = defaultName
  const sessionKey = open ? `${isServer ? 'server' : 'client'}:${node?.id || '__new__'}` : ''

  useEffect(() => {
    if (!sessionKey) return
    const targetNode = nodeRef.current
    const fresh = nodeToDraft(targetNode || undefined, defaultNameRef.current)
    setDraft(fresh.draft)
    setEndpoints(fresh.endpoints)
    setOptions(fresh.options)
    setOriginalTunnel(fresh.originalTunnel)
    endpointAutoPortRef.current = !targetNode
    setGenBusy('')
    setGenStatus('')
    setGenError('')
    setHeadersError('')
    setUploads({
      cert: { busy: false, error: '', status: '', fileName: '' },
      key: { busy: false, error: '', status: '', fileName: '' },
      ca: { busy: false, error: '', status: '', fileName: '' },
    })
    if (!targetNode && isServer) {
      try {
        setHasSavedDraft(!!globalThis.sessionStorage?.getItem(NODE_DRAFT_KEY))
      } catch {
        setHasSavedDraft(false)
      }
    } else {
      setHasSavedDraft(false)
    }
  }, [sessionKey, isServer])

  // Spec 2.5: Auto-save draft for unsaved new Server nodes so accidental close preserves work
  useEffect(() => {
    if (!open || node || !isServer) return
    if (!draft.name && !draft.cert && !draft.privateKey && !draft.password) return
    try {
      globalThis.sessionStorage?.setItem(NODE_DRAFT_KEY, JSON.stringify({ draft, endpoints, options }))
    } catch { /* ignore */ }
  }, [open, node, isServer, draft, endpoints, options])

  const restoreDraft = () => {
    try {
      const raw = globalThis.sessionStorage?.getItem(NODE_DRAFT_KEY)
      if (!raw) return
      const parsed = JSON.parse(raw)
      if (parsed?.draft) setDraft(parsed.draft)
      if (Array.isArray(parsed?.endpoints) && parsed.endpoints.length) setEndpoints(parsed.endpoints)
      if (parsed?.options) setOptions(parsed.options)
      setHasSavedDraft(false)
    } catch { /* ignore */ }
  }

  const discardDraft = () => {
    setHasSavedDraft(false)
    try { globalThis.sessionStorage?.removeItem(NODE_DRAFT_KEY) } catch { /* ignore */ }
  }

  const updateDraft = <K extends keyof NodeDraft>(key: K, value: NodeDraft[K]) => {
    setDraft((prev) => {
      const next = { ...prev, [key]: value }
      if (key === 'protocol') {
        if (value === 'hysteria2') {
          next.transport = 'quic'
          next.security = 'tls'
        } else if (next.transport === 'quic') {
          next.transport = 'tcp'
        }
      }
      if (key === 'security' && value === 'reality' && next.transport === 'xhttp') {
        next.xhttpTLS = false
      }
      if (key === 'transport' && value === 'xhttp' && next.security === 'reality') {
        next.xhttpTLS = false
      }
      if (!isFlowAllowed(next)) next.flow = ''
      return next
    })
  }

  const effXhttpMode = effectiveXhttpMode(draft)
  const flowAllowed = isFlowAllowed(draft)
  const pemFields: PEMField[] = !isServer
    ? []
    : draft.protocol === 'hysteria2' || draft.security === 'tls'
      ? ['cert', 'key', 'ca']
      : draft.transport === 'xhttp' && draft.xhttpTLS
        ? ['ca']
        : []

  const readingPem = Object.values(uploads).some((u) => u.busy)
  const uploadErr = pemFields.map((f) => uploads[f].error).find(Boolean)

  const handleUploadPem = async (e: ChangeEvent<HTMLInputElement>, field: PEMField) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    if (file.size > PEM_MAX_BYTES) {
      setUploads((prev) => ({ ...prev, [field]: { busy: false, error: '文件不能超过 64 KiB。', status: '', fileName: '' } }))
      return
    }
    setUploads((prev) => ({ ...prev, [field]: { busy: true, error: '', status: '', fileName: '' } }))
    try {
      const text = await file.text()
      const problem = validatePEM(text, field) || (!text.trim() ? '文件为空，请选择 PEM 文件。' : '')
      if (problem) {
        setUploads((prev) => ({ ...prev, [field]: { busy: false, error: problem, status: '', fileName: '' } }))
        return
      }
      updateDraft(field, text.trim())
      setUploads((prev) => ({
        ...prev,
        [field]: {
          busy: false,
          error: '',
          status: '已载入，保存后生效。',
          fileName: truncateFileName(file.name, 16), // Spec 7.6
        },
      }))
    } catch {
      setUploads((prev) => ({ ...prev, [field]: { busy: false, error: '读取失败，请重试或粘贴 PEM。', status: '', fileName: '' } }))
    }
  }

  const handleGenerate = async (kind: GenerateKind) => {
    if (!isServer || genBusy || readingPem) return
    if (kind === 'certificate' && (!Number.isInteger(Number(options.ttl)) || Number(options.ttl) < 1 || Number(options.ttl) > 365)) {
      setGenError('证书有效期须为 1 到 365 天的整数。')
      return
    }
    const primary = endpoints.find((ep) => ep.enabled) || endpoints[0]
    const rev = ++genRevRef.current
    setGenBusy(kind)
    setGenError('')
    setGenStatus('')
    try {
      const res = await api<Record<string, string>>('/nodes/generate', 'POST', {
        role: 'server',
        kind,
        ...(kind === 'certificate' ? { host: primary?.host.trim() || '', ttl_days: Number(options.ttl) } : {}),
        ...(kind === 'vless' ? { mode: options.mode, authentication: options.authentication } : {}),
      })
      if (rev !== genRevRef.current) return
      if (kind === 'reality') {
        setDraft((p) => ({ ...p, privateKey: res.private_key || '', shortIDs: res.short_id || '' }))
      } else if (kind === 'short_id') {
        setDraft((p) => ({ ...p, shortIDs: res.short_id || '' }))
      } else if (kind === 'mldsa65') {
        setDraft((p) => ({ ...p, mldsa65Verify: res.public_key || '', mldsa65Seed: res.private_key || '' }))
      } else if (kind === 'vless') {
        setDraft((p) => ({ ...p, enc: res.decryption || '' }))
      } else if (kind === 'hysteria2') {
        setDraft((p) => ({ ...p, password: res.password || '' }))
      } else if (kind === 'certificate') {
        setDraft((p) => ({ ...p, cert: res.cert_pem || '', key: res.key_pem || '', ca: res.ca_pem || '' }))
        setUploads({
          cert: { busy: false, error: '', status: '', fileName: '' },
          key: { busy: false, error: '', status: '', fileName: '' },
          ca: { busy: false, error: '', status: '', fileName: '' },
        })
      }
      setGenStatus('已生成服务端参数，保存后自动派生客户端配置。')
    } catch {
      if (rev === genRevRef.current) setGenError('生成失败，请检查登录状态及生成接口后重试。')
    } finally {
      if (rev === genRevRef.current) setGenBusy('')
    }
  }

  const handleSave = async (): Promise<boolean> => {
    if (readingPem) throw new Error('请等待 PEM 文件读取完成。')
    if (genBusy) throw new Error('请等待密钥生成完成。')
    if (uploadErr) throw new Error(uploadErr)
    if (isServer && draft.protocol === 'vless' && draft.transport === 'xhttp' && draft.xhttpHeaders.trim()) {
      try {
        parseXHTTPHeaders(draft.xhttpHeaders)
        setHeadersError('')
      } catch (e) {
        const msg = e instanceof Error ? e.message : '请求头格式错误'
        setHeadersError(msg)
        throw e
      }
    }
    const payload = buildNodeSavePayload(role, node?.embedded ? { ...draft, mode: 'online' } : draft, endpoints, originalTunnel)
    const saved = await api<Node>(draft.id ? `/nodes/${encodeURIComponent(draft.id)}` : '/nodes', draft.id ? 'PUT' : 'POST', payload)
    if (!node && isServer) discardDraft()
    await onSaved(saved)
    return true
  }

  const enabledDownloadEndpoints = endpoints.filter((ep) => ep.enabled)
  const sessionTableKind = ['', 'hex', 'base62'].includes(draft.xhttpSessionTable) ? draft.xhttpSessionTable : 'custom'

  return (
    <Modal
      open={open}
      onClose={onClose}
      isForm
      size={isServer ? 'lg' : 'md'}
      title={`${draft.id ? '编辑' : '新建'}${isServer ? '公网网关' : '内网节点'}`}
      saveLabel={draft.id ? '保存' : '创建'}
      disabled={readingPem || !!uploadErr || !!genBusy}
      onSubmit={handleSave}
    >
      {hasSavedDraft && !node && (
        <div className="draft-banner" role="status">
          <span>检测到未提交的网关草稿，是否继续编辑？</span>
          <div style={{ display: 'flex', gap: 6 }}>
            <button type="button" className="btn btn-sm btn-primary" onClick={restoreDraft}>恢复草稿</button>
            <button type="button" className="btn btn-sm btn-ghost" onClick={discardDraft}>丢弃</button>
          </div>
        </div>
      )}

      {/* Section 1: Basic Identity & Node Operating Mode */}
      <div className="form-section">
        <div className="field">
          <label className="field-label" htmlFor="node-name">节点名称</label>
          <input
            id="node-name"
            type="text"
            maxLength={128}
            required
            value={draft.name}
            onChange={(e) => updateDraft('name', e.target.value)}
          />
        </div>

        <div className="field">
          <div className="field-label">
            <span>节点模式</span>
            {node?.embedded && <Badge text="内置网关固定在线" tone="accent" />}
          </div>
          {node?.embedded ? (
            <Segmented<'online'>
              ariaLabel="节点模式"
              value="online"
              disabled
              onChange={() => {}}
              options={[{ value: 'online', label: '在线受控' }]}
            />
          ) : (
            <Segmented<'online' | 'offline'>
              ariaLabel="节点模式"
              value={draft.mode}
              onChange={(mode) => updateDraft('mode', mode)}
              options={[
                { value: 'online', label: '在线受控' },
                { value: 'offline', label: '脱机独立' },
              ]}
            />
          )}
          <span className="field-help">
            {draft.mode === 'offline' && !node?.embedded
              ? '脱机独立：节点不连接 Hub 控制面、不轮询心跳；保存后导出脱机配置直接启动。'
              : '在线受控：节点通过接入令牌连接 Hub，实时同步修订并上报心跳与链路状态。'}
          </span>
        </div>
      </div>

      {isServer && (
        <>
          {/* Section 2: Local Bind & Connect Endpoints */}
          <div className="form-section">
            <span className="form-section-title">本地监听与客户端连接入口</span>
            <div className="form-grid-2">
              <div className="field">
                <label className="field-label" htmlFor="node-listen-host">本地监听 IP</label>
                <input
                  id="node-listen-host"
                  className="mono ltr-force"
                  type="text"
                  value={draft.listen}
                  placeholder="0.0.0.0"
                  onChange={(e) => updateDraft('listen', e.target.value)}
                />
              </div>
              <div className="field">
                <label className="field-label" htmlFor="node-listen-port">本地监听端口</label>
                <input
                  id="node-listen-port"
                  className="mono tabular ltr-force"
                  type="number"
                  min={1}
                  max={65535}
                  required
                  value={draft.listenPort}
                  onChange={(e) => {
                    const v = e.target.value
                    updateDraft('listenPort', v)
                    if (endpointAutoPortRef.current && /^\d+$/.test(v) && endpoints[0]) {
                      setEndpoints((prev) => prev.map((ep, i) => (i === 0 ? { ...ep, port: Number(v) } : ep)))
                    }
                  }}
                />
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              <div className="field-label">
                <span>连接地址</span>
                <button
                  type="button"
                  className="btn btn-sm btn-soft"
                  onClick={() =>
                    setEndpoints((prev) => [
                      ...prev,
                      {
                        id: `endpoint-${Date.now()}-${prev.length}`,
                        name: prev.length ? `备用地址 ${prev.length}` : '首选地址',
                        host: '127.0.0.1',
                        port: Number(draft.listenPort) || 443,
                        enabled: true,
                      },
                    ])
                  }
                >
                  <Plus size={14} />
                  <span>添加入口</span>
                </button>
              </div>
              {endpoints.map((ep, idx) => (
                <div
                  key={ep.id}
                  className="subpanel-card"
                  style={{
                    padding: 12,
                    display: 'grid',
                    gap: 10,
                  }}
                >
                  <div className="form-grid-2">
                    <div className="field">
                      <label className="field-label">入口名称</label>
                      <input
                        type="text"
                        value={ep.name}
                        onChange={(e) => setEndpoints((prev) => prev.map((item, i) => (i === idx ? { ...item, name: e.target.value } : item)))}
                      />
                    </div>
                    <div className="field">
                      <label className="field-label">连接端口</label>
                      <input
                        className="mono tabular ltr-force"
                        type="number"
                        min={1}
                        max={65535}
                        value={ep.port}
                        onChange={(e) => {
                          if (idx === 0) endpointAutoPortRef.current = false
                          setEndpoints((prev) => prev.map((item, i) => (i === idx ? { ...item, port: Number(e.target.value) } : item)))
                        }}
                      />
                    </div>
                  </div>
                  <div className="field">
                    <label className="field-label">可达主机 / 域名</label>
                    <input
                      className="mono ltr-force"
                      type="text"
                      value={ep.host}
                      placeholder="gateway.example.com"
                      onChange={(e) => setEndpoints((prev) => prev.map((item, i) => (i === idx ? { ...item, host: e.target.value } : item)))}
                    />
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <Switch
                      checked={ep.enabled}
                      label="启用此入口"
                      onChange={(checked) => setEndpoints((prev) => prev.map((item, i) => (i === idx ? { ...item, enabled: checked } : item)))}
                    />
                    <button
                      type="button"
                      className="btn btn-sm btn-danger-ghost"
                      disabled={endpoints.length === 1}
                      onClick={() => setEndpoints((prev) => prev.filter((_, i) => i !== idx))}
                    >
                      <Trash2 size={14} />
                      <span>移除</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section 3: Protocol & Security Stack */}
          <div className="form-section">
            <span className="form-section-title">隧道协议与安全层</span>

            <div className="protocol-cards" role="group" aria-label="隧道协议">
              <button
                type="button"
                className="protocol-card"
                aria-pressed={draft.protocol === 'vless'}
                onClick={() => updateDraft('protocol', 'vless')}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <strong>VLESS</strong>
                  <Badge text="TCP / XHTTP" tone="accent" />
                </div>
              </button>
              <button
                type="button"
                className="protocol-card"
                aria-pressed={draft.protocol === 'hysteria2'}
                onClick={() => updateDraft('protocol', 'hysteria2')}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <strong>Hysteria2</strong>
                  <Badge text="UDP / QUIC" tone="purple" />
                </div>
              </button>
            </div>

            <div className="form-grid-2">
              <div className="field">
                <span className="field-label">传输层</span>
                {draft.protocol === 'vless' ? (
                  <Segmented<'tcp' | 'xhttp'>
                    ariaLabel="传输层"
                    value={draft.transport === 'xhttp' ? 'xhttp' : 'tcp'}
                    onChange={(v) => updateDraft('transport', v)}
                    options={[
                      { value: 'tcp', label: 'TCP' },
                      { value: 'xhttp', label: 'XHTTP' },
                    ]}
                  />
                ) : (
                  <Segmented<'quic'> ariaLabel="传输层" value="quic" disabled onChange={() => {}} options={[{ value: 'quic', label: 'QUIC (UDP)' }]} />
                )}
              </div>

              <div className="field">
                <span className="field-label">
                  {draft.protocol === 'vless' && draft.transport === 'xhttp' ? '回源监听安全' : '外层安全模式'}
                </span>
                {draft.protocol === 'vless' ? (
                  <Segmented<'tls' | 'reality' | 'encryption'>
                    ariaLabel="安全模式"
                    value={draft.security}
                    onChange={(v) => updateDraft('security', v)}
                    options={[
                      { value: 'tls', label: 'TLS' },
                      { value: 'reality', label: 'REALITY' },
                      { value: 'encryption', label: 'Encryption' },
                    ]}
                  />
                ) : (
                  <Segmented<'tls'> ariaLabel="安全模式" value="tls" disabled onChange={() => {}} options={[{ value: 'tls', label: 'TLS 1.3' }]} />
                )}
              </div>
            </div>

            {genStatus && <span className="field-help" style={{ color: 'var(--good)' }} role="status">{genStatus}</span>}
            <InlineAlert message={genError} />

            {/* Hysteria2 Auth */}
            {draft.protocol === 'hysteria2' && (
              <SecretField
                label="Hysteria2 鉴权密码"
                value={draft.password}
                required
                onChange={(v) => updateDraft('password', v)}
                actions={
                  <button type="button" className="btn btn-sm btn-soft" disabled={!!genBusy} onClick={() => void handleGenerate('hysteria2')}>
                    <Sparkles size={13} />
                    <span>生成密码</span>
                  </button>
                }
              />
            )}

            {/* TLS / CA PEM Uploads */}
            {pemFields.length > 0 && (
              <div className="subpanel-card" style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: 14 }}>
                {pemFields.includes('cert') && (
                  <div style={{ display: 'flex', alignItems: 'flex-end', gap: 10, flexWrap: 'wrap' }}>
                    <div className="field" style={{ flex: '0 1 160px' }}>
                      <label className="field-label" htmlFor="cert-ttl">自签有效天数</label>
                      <input
                        id="cert-ttl"
                        className="tabular"
                        type="number"
                        min={1}
                        max={365}
                        value={options.ttl}
                        onChange={(e) => setOptions((p) => ({ ...p, ttl: Number(e.target.value) }))}
                      />
                    </div>
                    <button type="button" className="btn btn-soft" disabled={!!genBusy || readingPem} onClick={() => void handleGenerate('certificate')}>
                      <Sparkles size={14} />
                      <span>{genBusy === 'certificate' ? '正在签发…' : '一键生成自签证书 + CA'}</span>
                    </button>
                  </div>
                )}

                {pemFields.map((field) => {
                  const title = { cert: '证书 PEM', key: '私钥 PEM', ca: 'CA 证书 PEM（可选）' }[field]
                  const uState = uploads[field]
                  return (
                    <div key={field} className="field">
                      {field === 'key' ? (
                        <SecretField
                          label={title}
                          value={draft.key}
                          multiline
                          required
                          onChange={(v) => updateDraft('key', v)}
                          actions={
                            <label className="btn btn-sm btn-ghost" style={{ cursor: 'pointer' }}>
                              <Upload size={13} />
                              <span>{uState.fileName || '上传文件'}</span>
                              <input type="file" className="sr-only" accept=".pem,.crt,.key" onChange={(e) => void handleUploadPem(e, 'key')} />
                            </label>
                          }
                        />
                      ) : (
                        <>
                          <div className="field-label">
                            <label htmlFor={`pem-${field}`}>{title}</label>
                            <label className="btn btn-sm btn-ghost" style={{ cursor: 'pointer' }}>
                              <Upload size={13} />
                              <span>{uState.fileName || '上传 PEM 文件'}</span>
                              <input type="file" className="sr-only" accept=".pem,.crt,.key" onChange={(e) => void handleUploadPem(e, field)} />
                            </label>
                          </div>
                          <textarea
                            id={`pem-${field}`}
                            className="mono ltr-force"
                            rows={3}
                            required={field === 'cert'}
                            spellCheck={false}
                            value={draft[field]}
                            onChange={(e) => updateDraft(field, e.target.value)}
                          />
                        </>
                      )}
                      <InlineAlert message={uState.error} />
                      {uState.status && <span className="field-help" style={{ color: 'var(--good)' }}>{uState.status}</span>}
                    </div>
                  )
                })}
              </div>
            )}

            {/* REALITY Parameters */}
            {draft.protocol === 'vless' && draft.security === 'reality' && (
              <div className="subpanel-card" style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: 14 }}>
                <div className="form-grid-2">
                  <div className="field">
                    <label className="field-label" htmlFor="reality-dest">回落目标（Dest）</label>
                    <input
                      id="reality-dest"
                      className="mono ltr-force"
                      type="text"
                      placeholder="www.microsoft.com:443"
                      value={draft.dest}
                      onChange={(e) => updateDraft('dest', e.target.value)}
                    />
                  </div>
                  <div className="field">
                    <label className="field-label" htmlFor="reality-sni">伪装域名（Server Names）</label>
                    <input
                      id="reality-sni"
                      className="mono ltr-force"
                      type="text"
                      placeholder="逗号分隔"
                      value={draft.names}
                      onChange={(e) => updateDraft('names', e.target.value)}
                    />
                  </div>
                </div>

                <SecretField
                  label="REALITY X25519 私钥"
                  value={draft.privateKey}
                  onChange={(v) => updateDraft('privateKey', v)}
                  actions={
                    <button type="button" className="btn btn-sm btn-soft" disabled={!!genBusy} onClick={() => void handleGenerate('reality')}>
                      <Sparkles size={13} />
                      <span>生成密钥对</span>
                    </button>
                  }
                />

                <div className="field">
                  <div className="field-label">
                    <label htmlFor="reality-short">Short IDs</label>
                    <button type="button" className="btn btn-sm btn-ghost" disabled={!!genBusy} onClick={() => void handleGenerate('short_id')}>
                      <Sparkles size={13} />
                      <span>随机生成</span>
                    </button>
                  </div>
                  <input
                    id="reality-short"
                    className="mono ltr-force"
                    type="text"
                    placeholder="逗号分隔十六进制"
                    value={draft.shortIDs}
                    onChange={(e) => updateDraft('shortIDs', e.target.value)}
                  />
                </div>

                <Collapsible title="REALITY 后量子签名（ML-DSA-65）与爬取参数">
                  <div className="form-grid-2">
                    <div className="field">
                      <label className="field-label">SpiderX 起点</label>
                      <input className="mono ltr-force" type="text" placeholder="留空随机" value={draft.spiderX} onChange={(e) => updateDraft('spiderX', e.target.value)} />
                    </div>
                    <div className="field">
                      <label className="field-label">SpiderY 参数</label>
                      <input className="mono ltr-force" type="text" placeholder="10 个逗号分隔整数" value={draft.spiderY} onChange={(e) => updateDraft('spiderY', e.target.value)} />
                    </div>
                  </div>
                  <div className="field">
                    <div className="field-label">
                      <label>ML-DSA-65 验证公钥</label>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button type="button" className="btn btn-sm btn-soft" disabled={!!genBusy} onClick={() => void handleGenerate('mldsa65')}>
                          <Sparkles size={13} />
                          <span>生成 ML-DSA-65</span>
                        </button>
                        {(draft.mldsa65Seed || draft.mldsa65Verify) && (
                          <button type="button" className="btn btn-sm btn-ghost" onClick={() => setDraft((p) => ({ ...p, mldsa65Seed: '', mldsa65Verify: '' }))}>
                            关闭
                          </button>
                        )}
                      </div>
                    </div>
                    <input className="mono ltr-force" type="text" placeholder="可选后量子额外验证" value={draft.mldsa65Verify} onChange={(e) => updateDraft('mldsa65Verify', e.target.value)} />
                  </div>
                  <SecretField label="ML-DSA-65 服务端种子" value={draft.mldsa65Seed} onChange={(v) => updateDraft('mldsa65Seed', v)} />
                </Collapsible>
              </div>
            )}

            {/* VLESS Encryption & Vision Flow */}
            {draft.protocol === 'vless' && (
              <Collapsible
                title="VLESS Encryption 与 Flow 控制（Vision）"
                badge={
                  draft.enc ? <Badge text="已启用 Encryption" tone="purple" /> : draft.flow ? <Badge text="Vision" tone="accent" /> : undefined
                }
                defaultOpen={draft.security === 'encryption' || !!draft.enc || !!draft.flow}
              >
                <div className="form-grid-2">
                  <div className="field">
                    <span className="field-label">生成模式</span>
                    <Segmented<'native' | 'xorpub' | 'random'>
                      ariaLabel="生成模式"
                      value={options.mode}
                      onChange={(mode) => setOptions((p) => ({ ...p, mode }))}
                      options={[
                        { value: 'native', label: 'native' },
                        { value: 'xorpub', label: 'xorpub' },
                        { value: 'random', label: 'random' },
                      ]}
                    />
                  </div>
                  <div className="field">
                    <span className="field-label">密钥交换算法</span>
                    <Segmented<'x25519' | 'mlkem768'>
                      ariaLabel="认证算法"
                      value={options.authentication}
                      onChange={(authentication) => setOptions((p) => ({ ...p, authentication }))}
                      options={[
                        { value: 'x25519', label: 'X25519' },
                        { value: 'mlkem768', label: 'ML-KEM-768' },
                      ]}
                    />
                  </div>
                </div>

                <SecretField
                  label="VLESS Decryption（服务端配置）"
                  value={draft.enc}
                  required={draft.security === 'encryption' || (draft.transport === 'xhttp' && !draft.xhttpTLS && draft.security !== 'reality')}
                  onChange={(v) => updateDraft('enc', v)}
                  actions={
                    <>
                      <button type="button" className="btn btn-sm btn-soft" disabled={!!genBusy} onClick={() => void handleGenerate('vless')}>
                        <Sparkles size={13} />
                        <span>生成配对配置</span>
                      </button>
                      {draft.enc && draft.security !== 'encryption' && (
                        <button type="button" className="btn btn-sm btn-ghost" onClick={() => updateDraft('enc', '')}>
                          关闭
                        </button>
                      )}
                    </>
                  }
                />

                {flowAllowed && (
                  <div className="field">
                    <span className="field-label">XTLS Flow</span>
                    <Segmented<'' | 'xtls-rprx-vision'>
                      ariaLabel="Flow"
                      value={draft.flow === 'xtls-rprx-vision' ? 'xtls-rprx-vision' : ''}
                      onChange={(v) => updateDraft('flow', v)}
                      options={[
                        { value: '', label: '关闭' },
                        { value: 'xtls-rprx-vision', label: 'xtls-rprx-vision' },
                      ]}
                    />
                  </div>
                )}
              </Collapsible>
            )}

            {/* XHTTP Full Configuration (Progressive Disclosure) */}
            {draft.protocol === 'vless' && draft.transport === 'xhttp' && (
              <div className="subpanel-card" style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: 14 }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 8 }}>
                  <span className="form-section-title">XHTTP 传输配置</span>
                  <Badge text={`有效模式: ${effXhttpMode}`} tone="accent" />
                </div>

                <div className="field">
                  <span className="field-label">XHTTP 模式</span>
                  <Segmented<XhttpMode>
                    ariaLabel="XHTTP 模式"
                    value={draft.xhttpMode}
                    onChange={(v) => updateDraft('xhttpMode', v)}
                    options={[
                      { value: 'packet-up', label: 'packet-up' },
                      { value: 'stream-up', label: 'stream-up' },
                      { value: 'stream-one', label: 'stream-one' },
                      { value: 'auto', label: 'auto' },
                    ]}
                  />
                </div>

                <div className="form-grid-2">
                  <div className="field">
                    <label className="field-label">XHTTP 路径</label>
                    <input className="mono ltr-force" type="text" maxLength={256} required value={draft.xhttpPath} onChange={(e) => updateDraft('xhttpPath', e.target.value)} />
                  </div>
                  <div className="field">
                    <label className="field-label">HTTP Host 覆写（可选）</label>
                    <input className="mono ltr-force" type="text" maxLength={253} placeholder="edge.example.com" value={draft.xhttpHost} onChange={(e) => updateDraft('xhttpHost', e.target.value)} />
                  </div>
                </div>

                <div className="form-grid-2">
                  <div className="field">
                    <span className="field-label">HTTP 版本</span>
                    <Segmented<'' | '1.1' | '2' | '3'>
                      ariaLabel="HTTP 版本"
                      value={draft.xhttpVersion}
                      onChange={(v) => updateDraft('xhttpVersion', v)}
                      options={[
                        { value: '', label: '自动' },
                        ...(effXhttpMode === 'packet-up' ? [{ value: '1.1' as const, label: 'H1.1' }] : []),
                        { value: '2', label: 'H2' },
                        { value: '3', label: 'H3' },
                      ]}
                    />
                  </div>
                  <div className="field">
                    <span className="field-label">上行 HTTP 方法</span>
                    <Segmented<'POST' | 'PUT' | 'OPTIONS'>
                      ariaLabel="上行 HTTP 方法"
                      value={draft.xhttpUplinkMethod}
                      onChange={(v) => updateDraft('xhttpUplinkMethod', v)}
                      options={[
                        { value: 'POST', label: 'POST' },
                        { value: 'PUT', label: 'PUT' },
                        { value: 'OPTIONS', label: 'OPTIONS' },
                      ]}
                    />
                  </div>
                </div>

                <Switch
                  checked={draft.xhttpTLS}
                  disabled={draft.security === 'reality'}
                  label="Client 连接地址使用 HTTPS"
                  onChange={(v) => updateDraft('xhttpTLS', v)}
                />

                {draft.xhttpMode !== 'stream-one' && (
                  <div className="field">
                    <span className="field-label">分离下行入口（可选）</span>
                    <Select
                      ariaLabel="分离下行入口"
                      value={draft.xhttpDownloadEndpoint}
                      onChange={(v) => updateDraft('xhttpDownloadEndpoint', v)}
                      options={[
                        { value: '', label: '与上行相同' },
                        ...enabledDownloadEndpoints.map((ep) => ({ value: ep.id, label: `${ep.name} · ${ep.host}:${ep.port}` })),
                      ]}
                    />
                  </div>
                )}

                <Collapsible title="XHTTP 高级伪装、自定义请求头与 xmux 调优">
                  <div className="field">
                    <label className="field-label">自定义请求头（JSON 对象）</label>
                    <textarea
                      className="mono ltr-force"
                      rows={3}
                      spellCheck={false}
                      value={draft.xhttpHeaders}
                      placeholder='{"User-Agent":"Mozilla/5.0 ...","X-Custom-Route":"east"}'
                      onChange={(e) => {
                        updateDraft('xhttpHeaders', e.target.value)
                        if (headersError) setHeadersError('')
                      }}
                    />
                    <InlineAlert message={headersError} />
                  </div>

                  <div className="form-grid-2">
                    <div className="field">
                      <label className="field-label">请求超时（秒，5–60）</label>
                      <input className="tabular" type="number" min={5} max={60} value={draft.xhttpTimeout} onChange={(e) => updateDraft('xhttpTimeout', Number(e.target.value))} />
                    </div>
                    <div className="field">
                      <label className="field-label">服务端请求头上限（字节）</label>
                      <input className="tabular" type="number" min={8192} max={32768} value={draft.xhttpMaxHeaderBytes} onChange={(e) => updateDraft('xhttpMaxHeaderBytes', Number(e.target.value))} />
                    </div>
                    <div className="field">
                      <label className="field-label">填充最小字节（1–1000）</label>
                      <input className="tabular" type="number" min={1} max={1000} value={draft.xhttpPadding} onChange={(e) => updateDraft('xhttpPadding', Number(e.target.value))} />
                    </div>
                    <div className="field">
                      <label className="field-label">填充最大字节（1–1000）</label>
                      <input className="tabular" type="number" min={1} max={1000} value={draft.xhttpPaddingMax} onChange={(e) => updateDraft('xhttpPaddingMax', Number(e.target.value))} />
                    </div>
                  </div>

                  <Switch checked={draft.xhttpPaddingObfs} label="自定义填充位置与方法" onChange={(v) => updateDraft('xhttpPaddingObfs', v)} />
                  {draft.xhttpPaddingObfs && (
                    <div className="form-grid-2">
                      <div className="field">
                        <span className="field-label">填充位置</span>
                        <Select<PaddingPlacement>
                          ariaLabel="填充位置"
                          value={draft.xhttpPaddingPlacement}
                          onChange={(p) =>
                            setDraft((prev) => ({
                              ...prev,
                              xhttpPaddingPlacement: p,
                              xhttpPaddingKey: 'x_padding',
                              xhttpPaddingHeader: p === 'query_in_header' ? 'Referer' : 'X-Padding',
                            }))
                          }
                          options={[
                            { value: 'query_in_header', label: '请求头内查询参数' },
                            { value: 'query', label: '查询参数' },
                            { value: 'header', label: '请求头' },
                            { value: 'cookie', label: 'Cookie' },
                          ]}
                        />
                      </div>
                      <div className="field">
                        <span className="field-label">填充方法</span>
                        <Segmented<'repeat-x' | 'tokenish'>
                          ariaLabel="填充方法"
                          value={draft.xhttpPaddingMethod}
                          onChange={(v) => updateDraft('xhttpPaddingMethod', v)}
                          options={[
                            { value: 'repeat-x', label: '重复 X' },
                            { value: 'tokenish', label: '随机 Token' },
                          ]}
                        />
                      </div>
                      {draft.xhttpPaddingPlacement !== 'header' && (
                        <div className="field">
                          <label className="field-label">填充键名</label>
                          <input className="mono ltr-force" type="text" maxLength={40} value={draft.xhttpPaddingKey} onChange={(e) => updateDraft('xhttpPaddingKey', e.target.value)} />
                        </div>
                      )}
                      {(draft.xhttpPaddingPlacement === 'header' || draft.xhttpPaddingPlacement === 'query_in_header') && (
                        <div className="field">
                          <label className="field-label">填充请求头</label>
                          <input className="mono ltr-force" type="text" maxLength={48} value={draft.xhttpPaddingHeader} onChange={(e) => updateDraft('xhttpPaddingHeader', e.target.value)} />
                        </div>
                      )}
                    </div>
                  )}

                  {effXhttpMode === 'packet-up' && (
                    <div className="form-grid-2">
                      <div className="field">
                        <label className="field-label">上行分片（1024–32768）</label>
                        <input className="tabular" type="number" min={1024} max={32768} value={draft.xhttpPostBytes} onChange={(e) => updateDraft('xhttpPostBytes', Number(e.target.value))} />
                      </div>
                      <div className="field">
                        <label className="field-label">分片最大值（0 固定）</label>
                        <input className="tabular" type="number" min={0} max={32768} value={draft.xhttpPostBytesMax} onChange={(e) => updateDraft('xhttpPostBytesMax', Number(e.target.value))} />
                      </div>
                      <div className="field">
                        <label className="field-label">分片最小间隔（ms）</label>
                        <input className="tabular" type="number" min={0} max={1000} value={draft.xhttpPostInterval} onChange={(e) => updateDraft('xhttpPostInterval', Number(e.target.value))} />
                      </div>
                      <div className="field">
                        <label className="field-label">分片最大间隔（ms）</label>
                        <input className="tabular" type="number" min={0} max={1000} value={draft.xhttpPostIntervalMax} onChange={(e) => updateDraft('xhttpPostIntervalMax', Number(e.target.value))} />
                      </div>
                      <div className="field">
                        <label className="field-label">缓冲分片上限（0–32）</label>
                        <input className="tabular" type="number" min={0} max={32} value={draft.xhttpMaxBufferedPosts} onChange={(e) => updateDraft('xhttpMaxBufferedPosts', Number(e.target.value))} />
                      </div>
                      <div className="field">
                        <label className="field-label">并发上行上限（0–8）</label>
                        <input className="tabular" type="number" min={0} max={Math.min(8, draft.xhttpMaxBufferedPosts + 1)} value={draft.xhttpMaxConcurrentPosts} onChange={(e) => updateDraft('xhttpMaxConcurrentPosts', Number(e.target.value))} />
                      </div>
                      <div className="field">
                        <span className="field-label">上行数据位置</span>
                        <Segmented<'body' | 'header' | 'cookie'>
                          ariaLabel="上行数据位置"
                          value={draft.xhttpDataPlacement}
                          onChange={(v) => updateDraft('xhttpDataPlacement', v)}
                          options={[
                            { value: 'body', label: 'body' },
                            { value: 'header', label: 'header' },
                            { value: 'cookie', label: 'cookie' },
                          ]}
                        />
                      </div>
                      {draft.xhttpDataPlacement !== 'body' && (
                        <>
                          <div className="field">
                            <label className="field-label">数据键名</label>
                            <input className="mono ltr-force" type="text" value={draft.xhttpDataKey} onChange={(e) => updateDraft('xhttpDataKey', e.target.value)} />
                          </div>
                          <div className="field">
                            <label className="field-label">编码块大小（0/64–8192）</label>
                            <input className="tabular" type="number" min={0} max={8192} value={draft.xhttpChunkSize} onChange={(e) => updateDraft('xhttpChunkSize', Number(e.target.value))} />
                          </div>
                        </>
                      )}
                    </div>
                  )}

                  {effXhttpMode !== 'stream-one' && (
                    <div className="form-grid-2">
                      <div className="field">
                        <span className="field-label">会话 ID 位置</span>
                        <Select<MetaPlacement>
                          ariaLabel="会话 ID 位置"
                          value={draft.xhttpSessionPlacement}
                          onChange={(v) => setDraft((p) => ({ ...p, xhttpSessionPlacement: v, xhttpSessionKey: '' }))}
                          options={[
                            { value: 'path', label: '路径（默认）' },
                            { value: 'query', label: '查询参数' },
                            { value: 'header', label: '请求头' },
                            { value: 'cookie', label: 'Cookie' },
                          ]}
                        />
                      </div>
                      {draft.xhttpSessionPlacement !== 'path' && (
                        <div className="field">
                          <label className="field-label">会话 ID 键名</label>
                          <input className="mono ltr-force" type="text" value={draft.xhttpSessionKey} onChange={(e) => updateDraft('xhttpSessionKey', e.target.value)} />
                        </div>
                      )}
                      {effXhttpMode === 'packet-up' && (
                        <>
                          <div className="field">
                            <span className="field-label">序号位置</span>
                            <Select<MetaPlacement>
                              ariaLabel="序号位置"
                              value={draft.xhttpSeqPlacement}
                              onChange={(v) => setDraft((p) => ({ ...p, xhttpSeqPlacement: v, xhttpSeqKey: '' }))}
                              options={[
                                { value: 'path', label: '路径（默认）' },
                                { value: 'query', label: '查询参数' },
                                { value: 'header', label: '请求头' },
                                { value: 'cookie', label: 'Cookie' },
                              ]}
                            />
                          </div>
                          {draft.xhttpSeqPlacement !== 'path' && (
                            <div className="field">
                              <label className="field-label">序号键名</label>
                              <input className="mono ltr-force" type="text" value={draft.xhttpSeqKey} onChange={(e) => updateDraft('xhttpSeqKey', e.target.value)} />
                            </div>
                          )}
                        </>
                      )}
                      <div className="field">
                        <span className="field-label">会话 ID 字符表</span>
                        <Segmented<'' | 'hex' | 'base62' | 'custom'>
                          ariaLabel="会话字符表"
                          value={sessionTableKind as '' | 'hex' | 'base62' | 'custom'}
                          onChange={(kind) =>
                            setDraft((p) => ({
                              ...p,
                              xhttpSessionTable: kind === 'custom' ? '0123456789ABCDEFGHIJKLMNOPQRSTUV' : kind,
                              xhttpSessionLength: kind ? 32 : 0,
                            }))
                          }
                          options={[
                            { value: '', label: 'UUID' },
                            { value: 'hex', label: 'hex' },
                            { value: 'base62', label: 'base62' },
                            { value: 'custom', label: '自定义' },
                          ]}
                        />
                      </div>
                      {sessionTableKind && (
                        <div className="field">
                          <label className="field-label">会话 ID 长度（24–64）</label>
                          <input className="tabular" type="number" min={24} max={64} value={draft.xhttpSessionLength} onChange={(e) => updateDraft('xhttpSessionLength', Number(e.target.value))} />
                        </div>
                      )}
                      {sessionTableKind === 'custom' && (
                        <div className="field" style={{ gridColumn: '1 / -1' }}>
                          <label className="field-label">自定义字符表</label>
                          <input className="mono ltr-force" type="text" value={draft.xhttpSessionTable} onChange={(e) => updateDraft('xhttpSessionTable', e.target.value)} />
                        </div>
                      )}
                    </div>
                  )}

                  {effXhttpMode === 'stream-up' && (
                    <div className="form-grid-2">
                      <div className="field">
                        <label className="field-label">服务端填充周期（秒）</label>
                        <input className="tabular" type="number" min={0} max={300} placeholder="默认" value={draft.streamUpMin} onChange={(e) => updateDraft('streamUpMin', e.target.value === '' ? '' : Number(e.target.value))} />
                      </div>
                      <div className="field">
                        <label className="field-label">最大填充周期（秒）</label>
                        <input className="tabular" type="number" min={0} max={300} placeholder="默认" value={draft.streamUpMax} onChange={(e) => updateDraft('streamUpMax', e.target.value === '' ? '' : Number(e.target.value))} />
                      </div>
                    </div>
                  )}

                  <div className="form-grid-2">
                    <div className="field"><label className="field-label">xmux 单连接并发</label><input className="tabular" type="number" min={0} max={1024} value={draft.xhttpMuxConcurrency} onChange={(e) => updateDraft('xhttpMuxConcurrency', Number(e.target.value))} /></div>
                    <div className="field"><label className="field-label">xmux 连接目标</label><input className="tabular" type="number" min={0} max={128} value={draft.xhttpMuxConnections} onChange={(e) => updateDraft('xhttpMuxConnections', Number(e.target.value))} /></div>
                    <div className="field"><label className="field-label">xmux 连接复用次数</label><input className="tabular" type="number" min={0} max={100000} value={draft.xhttpMuxReuse} onChange={(e) => updateDraft('xhttpMuxReuse', Number(e.target.value))} /></div>
                    <div className="field"><label className="field-label">xmux 请求次数</label><input className="tabular" type="number" min={0} max={100000} value={draft.xhttpMuxRequests} onChange={(e) => updateDraft('xhttpMuxRequests', Number(e.target.value))} /></div>
                    <div className="field"><label className="field-label">xmux 可复用时长（秒）</label><input className="tabular" type="number" min={0} max={86400} value={draft.xhttpMuxSeconds} onChange={(e) => updateDraft('xhttpMuxSeconds', Number(e.target.value))} /></div>
                    <div className="field"><label className="field-label">xmux 保活周期（秒）</label><input className="tabular" type="number" min={0} max={3600} value={draft.xhttpMuxKeepAlive} onChange={(e) => updateDraft('xhttpMuxKeepAlive', Number(e.target.value))} /></div>
                  </div>

                  {(effXhttpMode === 'stream-up' || effXhttpMode === 'stream-one') && (
                    <Switch checked={draft.xhttpNoGRPCHeader} label="流式上行不发送 application/grpc 头" onChange={(v) => updateDraft('xhttpNoGRPCHeader', v)} />
                  )}
                  <Switch checked={draft.xhttpNoSSEHeader} label="下行不发送 text/event-stream 头" onChange={(v) => updateDraft('xhttpNoSSEHeader', v)} />
                </Collapsible>
              </div>
            )}
          </div>
        </>
      )}
    </Modal>
  )
}
