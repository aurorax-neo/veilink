import { useCallback, useEffect, useRef, useState } from 'react'
import { Check, Copy, Download, KeyRound, RefreshCw } from 'lucide-react'
import { api } from '../api'
import { copyText, isOfflineNode, triggerHaptic } from '../format'
import type { JoinResult, Node, OfflineExportResult } from '../types'
import { Badge, InlineAlert } from './ui/Badge'
import { Segmented } from './ui/Controls'
import { Modal } from './ui/Overlays'

type OnlineTab = 'docker' | 'binary' | 'prepare'
type OfflineTab = 'docker' | 'docker-file' | 'binary' | 'json'

export function NodeOnboardingModal({
  node,
  onClose,
  onExported,
}: {
  node: Node | null
  onClose: () => void
  onExported?: (nodeId: string) => void
}) {
  const nodeId = node?.id || ''
  const nodeEmbedded = Boolean(node?.embedded)
  const offlineMode = isOfflineNode(node)

  const [masterURL, setMasterURL] = useState(() => (typeof location !== 'undefined' ? location.origin : ''))
  const [generatedURL, setGeneratedURL] = useState('')
  const [onlineResult, setOnlineResult] = useState<JoinResult | null>(null)
  const [offlineResult, setOfflineResult] = useState<OfflineExportResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [onlineTab, setOnlineTab] = useState<OnlineTab>('docker')
  const [offlineTab, setOfflineTab] = useState<OfflineTab>('docker')
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)

  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const onExportedRef = useRef(onExported)
  onExportedRef.current = onExported
  const reqSeqRef = useRef(0)

  const generateOnline = useCallback(async (targetId: string, embedded: boolean, urlRaw: string, resetCredential = false) => {
    if (!targetId) return
    if (embedded) {
      setError('内置节点不支持快捷接入。')
      return
    }
    const clean = urlRaw.trim()
    let parsed: URL
    try {
      parsed = new URL(clean)
    } catch {
      setError('请输入完整的 http:// 或 https:// 地址。')
      return
    }
    if (
      !['http:', 'https:'].includes(parsed.protocol) ||
      parsed.username ||
      parsed.password ||
      parsed.hash ||
      parsed.search ||
      (parsed.pathname !== '/' && parsed.pathname !== '') ||
      /[\r\n\t ]/.test(clean)
    ) {
      setError('地址须使用 http:// 或 https://，不含路径或查询参数。')
      return
    }
    const seq = ++reqSeqRef.current
    setError('')
    setBusy(true)
    try {
      const res = await api<JoinResult>(`/nodes/${encodeURIComponent(targetId)}/join`, 'POST', {
        master_url: clean,
        ...(resetCredential ? { reset_credential: true } : {}),
      })
      if (seq !== reqSeqRef.current) return
      if (!res.command || !res.token || !Number.isFinite(res.expires_at)) {
        throw new Error('接入响应不完整，请重试。')
      }
      setOnlineResult(res)
      setGeneratedURL(clean)
    } catch (err) {
      if (seq !== reqSeqRef.current) return
      setError(err instanceof Error ? err.message : '生成接入命令失败')
    } finally {
      if (seq === reqSeqRef.current) setBusy(false)
    }
  }, [])

  const exportOffline = useCallback(async (targetId: string, embedded: boolean) => {
    if (!targetId) return
    if (embedded) {
      setError('内置节点不支持脱机导出。')
      return
    }
    const seq = ++reqSeqRef.current
    setError('')
    setBusy(true)
    try {
      const res = await api<OfflineExportResult>(`/nodes/${encodeURIComponent(targetId)}/offline`, 'POST', {})
      if (seq !== reqSeqRef.current) return
      if (!res.command || !res.state_json) {
        throw new Error('脱机配置生成不完整，请重试。')
      }
      setOfflineResult(res)
      onExportedRef.current?.(targetId)
    } catch (err) {
      if (seq !== reqSeqRef.current) return
      setError(err instanceof Error ? err.message : '导出脱机配置失败')
    } finally {
      if (seq === reqSeqRef.current) setBusy(false)
    }
  }, [])

  // Keyed strictly on primitive [nodeId, offlineMode, nodeEmbedded] — immune to parent 2s clock & SSE re-renders!
  useEffect(() => {
    reqSeqRef.current += 1
    setOnlineResult(null)
    setOfflineResult(null)
    setGeneratedURL('')
    setError('')
    setCopied(false)
    setBusy(false)
    if (!nodeId) return
    if (offlineMode) {
      setOfflineTab('docker')
      void exportOffline(nodeId, nodeEmbedded)
    } else {
      const origin = typeof location !== 'undefined' ? location.origin : ''
      setMasterURL(origin)
      setOnlineTab('docker')
      void generateOnline(nodeId, nodeEmbedded, origin)
    }
  }, [nodeId, offlineMode, nodeEmbedded, generateOnline, exportOffline])

  useEffect(() => () => {
    reqSeqRef.current += 1
    if (copyTimerRef.current) clearTimeout(copyTimerRef.current)
  }, [])

  const activeCommand = offlineMode
    ? !offlineResult
      ? ''
      : offlineTab === 'docker-file'
        ? `${offlineResult.prepare}\n# 将导出的 JSON 保存至 ${offlineResult.config_path} 后执行：\n${offlineResult.file_command}`
        : offlineTab === 'binary'
          ? `# 将导出的 JSON 保存至 /etc/veilink/offline-state.json 后执行：\n${offlineResult.binary_command}`
          : offlineTab === 'json'
            ? offlineResult.state_json
            : `${offlineResult.prepare}\n${offlineResult.command}`
    : !onlineResult
      ? ''
      : onlineTab === 'binary'
        ? onlineResult.binary_command || onlineResult.offline_binary_command || ''
        : onlineTab === 'prepare'
          ? onlineResult.prepare || ''
          : onlineResult.command

  const handleCopy = async () => {
    if (!activeCommand) return
    setError('')
    try {
      await copyText(activeCommand)
      triggerHaptic(12)
      setCopied(true)
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current)
      copyTimerRef.current = setTimeout(() => setCopied(false), 2500)
    } catch {
      setError('复制失败，请手动选中复制。')
    }
  }

  const downloadOfflineJson = () => {
    if (!offlineResult?.state_json) return
    const blob = new Blob([offlineResult.state_json], { type: 'application/json;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = offlineResult.filename || 'offline-state.json'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <Modal
      open={!!node}
      onClose={onClose}
      size="lg"
      title={`${offlineMode ? '脱机独立部署' : '在线受控接入'} · ${node?.name || ''}`}
      hideSave
    >
      {offlineMode ? (
        <>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
              <Badge text="脱机独立模式" tone="info" dot />
              {(offlineResult?.revision || node?.exported_revision) ? (
                <Badge text={`已导出修订 r${offlineResult?.revision || node?.exported_revision}`} tone="good" />
              ) : null}
              <span className="cell-sub">不连接 Hub · 不轮询心跳</span>
            </div>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <button
                type="button"
                className="btn btn-sm btn-soft"
                disabled={!offlineResult?.state_json || busy}
                onClick={downloadOfflineJson}
              >
                <Download size={14} />
                <span>{offlineResult ? `下载 ${offlineResult.filename}` : '准备配置文件…'}</span>
              </button>
              <button
                type="button"
                className="btn btn-sm"
                disabled={!nodeId || busy}
                onClick={() => void exportOffline(nodeId, nodeEmbedded)}
              >
                <RefreshCw size={14} className={busy ? 'spin' : ''} />
                <span>{busy ? '导出中…' : '重新生成'}</span>
              </button>
            </div>
          </div>

          <InlineAlert message={error} />

          <div className="subpanel-card" style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
              <Segmented<OfflineTab>
                ariaLabel="脱机启动方式"
                value={offlineTab}
                disabled={!offlineResult}
                onChange={(t) => {
                  setOfflineTab(t)
                  setCopied(false)
                }}
                options={[
                  { value: 'docker', label: 'Docker 一键运行' },
                  { value: 'docker-file', label: 'Docker 挂载文件' },
                  { value: 'binary', label: '二进制启动' },
                  { value: 'json', label: '配置文件 JSON' },
                ]}
              />

              <button
                type="button"
                className={`btn btn-sm btn-primary ${copied ? 'copy-bounce' : ''}`}
                disabled={!activeCommand}
                onClick={() => void handleCopy()}
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                <span>{copied ? '已复制' : '复制'}</span>
              </button>
            </div>

            <textarea
              className="mono ltr-force"
              value={activeCommand}
              placeholder={busy ? '正在导出脱机独立配置…' : ''}
              readOnly
              rows={7}
              spellCheck={false}
              style={{ fontSize: 12.5, lineHeight: 1.5 }}
              onClick={(e) => e.currentTarget.select()}
            />
          </div>
        </>
      ) : (
        <>
          <div className="field">
            <div className="field-label">
              <label htmlFor="join-master-url">Hub 地址</label>
              <Badge text="在线受控模式" tone="good" dot />
            </div>
            <div className="field-row">
              <input
                id="join-master-url"
                className="mono ltr-force"
                type="url"
                value={masterURL}
                placeholder="https://master.example.com:8443"
                onChange={(e) => setMasterURL(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && nodeId) {
                    e.preventDefault()
                    void generateOnline(nodeId, nodeEmbedded, masterURL)
                  }
                }}
              />
              <button
                type="button"
                className="btn"
                disabled={!nodeId || busy || masterURL.trim() === generatedURL}
                onClick={() => void generateOnline(nodeId, nodeEmbedded, masterURL)}
              >
                <RefreshCw size={14} className={busy ? 'spin' : ''} />
                <span>{busy && onlineResult ? '更新中…' : '更新'}</span>
              </button>
              <button
                type="button"
                className="btn btn-ghost"
                disabled={!nodeId || busy}
                title="轮换节点凭证与接入令牌"
                onClick={() => void generateOnline(nodeId, nodeEmbedded, masterURL, true)}
              >
                <KeyRound size={14} />
                <span>轮换令牌</span>
              </button>
            </div>
            <InlineAlert message={error} />
          </div>

          <div className="subpanel-card" style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
              <Segmented<OnlineTab>
                ariaLabel="在线接入方式"
                value={onlineTab}
                disabled={!onlineResult}
                onChange={(t) => {
                  setOnlineTab(t)
                  setCopied(false)
                }}
                options={[
                  { value: 'docker', label: 'Docker 容器' },
                  { value: 'binary', label: '二进制启动' },
                  { value: 'prepare', label: '目录准备', disabled: !onlineResult?.prepare },
                ]}
              />

              <button
                type="button"
                className={`btn btn-sm btn-primary ${copied ? 'copy-bounce' : ''}`}
                disabled={!activeCommand}
                onClick={() => void handleCopy()}
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                <span>{copied ? '已复制' : '复制'}</span>
              </button>
            </div>

            <textarea
              className="mono ltr-force"
              value={activeCommand}
              placeholder={busy ? '正在签发受控接入命令…' : ''}
              readOnly
              rows={6}
              spellCheck={false}
              style={{ fontSize: 12.5, lineHeight: 1.5 }}
              onClick={(e) => e.currentTarget.select()}
            />
          </div>
        </>
      )}
    </Modal>
  )
}
