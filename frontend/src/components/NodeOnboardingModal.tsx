import { useCallback, useEffect, useRef, useState } from 'react'
import { Check, Copy, Download, RefreshCw } from 'lucide-react'
import { api } from '../api'
import { copyText, triggerHaptic } from '../format'
import type { JoinResult, Node } from '../types'
import { Alert, Badge, InlineAlert } from './ui/Badge'
import { Collapsible, Segmented } from './ui/Controls'
import { Modal } from './ui/Overlays'

type CommandTab = 'docker' | 'offline-docker' | 'binary' | 'state'

export function NodeOnboardingModal({
  node,
  onClose,
}: {
  node: Node | null
  onClose: () => void
}) {
  const [masterURL, setMasterURL] = useState(() => (typeof location !== 'undefined' ? location.origin : ''))
  const [generatedURL, setGeneratedURL] = useState('')
  const [result, setResult] = useState<JoinResult | null>(null)
  const [generating, setGenerating] = useState(false)
  const [activeTab, setActiveTab] = useState<CommandTab>('docker')
  const [status, setStatus] = useState('')
  const [error, setError] = useState('')
  const [copied, setCopied] = useState(false)
  const copyTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)

  const generate = useCallback(
    async (target: Node, urlRaw: string) => {
      if (target.embedded) {
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
        setError('地址须使用 http:// 或 https://，不能含路径、凭据、查询或片段。')
        return
      }
      setError('')
      setGenerating(true)
      try {
        const res = await api<JoinResult>(`/nodes/${encodeURIComponent(target.id)}/join`, 'POST', { master_url: clean })
        if (!res.command || !res.token || !Number.isFinite(res.expires_at)) {
          throw new Error('接入响应不完整，请重试。')
        }
        setResult(res)
        setGeneratedURL(clean)
        setStatus('')
      } catch (err) {
        setError(err instanceof Error ? err.message : '生成接入命令失败')
      } finally {
        setGenerating(false)
      }
    },
    [],
  )

  useEffect(() => {
    if (!node) {
      setResult(null)
      setGeneratedURL('')
      setStatus('')
      setError('')
      setCopied(false)
      return
    }
    const origin = typeof location !== 'undefined' ? location.origin : ''
    setMasterURL(origin)
    setActiveTab('docker')
    void generate(node, origin)
  }, [node, generate])

  useEffect(() => () => { if (copyTimerRef.current) clearTimeout(copyTimerRef.current) }, [])

  const hasOffline = !!(result?.offline_command || result?.offline_binary_command || result?.state_json)
  const activeCommand = !result
    ? ''
    : activeTab === 'offline-docker'
      ? result.offline_command || result.command
      : activeTab === 'binary'
        ? result.offline_binary_command || ''
        : activeTab === 'state'
          ? result.state_json || ''
          : result.command

  const modeHint =
    activeTab === 'offline-docker'
      ? '内嵌节点凭据与当前隧道快照，无法连接 Hub 时也可直接启动容器。'
      : activeTab === 'binary'
        ? '单二进制直接携带完整脱机参数运行，网络恢复后自动重连 Hub。'
        : activeTab === 'state'
          ? '将此 JSON 写入节点 /data/state/state.json，即可脱机加载完整隧道配置。'
          : '启动后连接 Hub 自动拉取并持续同步隧道与端口映射配置。'

  const handleCopy = async () => {
    if (!activeCommand) return
    setError('')
    try {
      await copyText(activeCommand)
      triggerHaptic(12)
      setCopied(true)
      setStatus('已复制到剪贴板。')
      if (copyTimerRef.current) clearTimeout(copyTimerRef.current)
      copyTimerRef.current = setTimeout(() => setCopied(false), 2500)
    } catch {
      setError('复制失败，请手动选中命令复制。')
    }
  }

  const downloadStateJson = () => {
    if (!result?.state_json) return
    const blob = new Blob([result.state_json], { type: 'application/json;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'state.json'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    setStatus('state.json 脱机配置已导出。')
  }

  return (
    <Modal
      open={!!node}
      onClose={onClose}
      size="lg"
      kicker="Node Onboarding"
      title={`快捷接入 · ${node?.name || ''}`}
      hideSave
    >
      <div className="field">
        <label className="field-label" htmlFor="join-master-url">
          <span>Hub 管理地址</span>
          <Badge text="节点接入令牌持久有效" tone="good" />
        </label>
        <div className="field-row">
          <input
            id="join-master-url"
            className="mono ltr-force"
            type="url"
            value={masterURL}
            placeholder="https://master.example.com:8443"
            onChange={(e) => setMasterURL(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && node) {
                e.preventDefault()
                void generate(node, masterURL)
              }
            }}
          />
          <button
            type="button"
            className="btn"
            disabled={!node || generating || masterURL.trim() === generatedURL}
            onClick={() => node && void generate(node, masterURL)}
          >
            <RefreshCw size={14} className={generating ? 'spin' : ''} />
            <span>{generating ? '更新中…' : '更新地址'}</span>
          </button>
        </div>
        <InlineAlert message={error} />
      </div>

      {result && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: 14, borderRadius: 'var(--radius-md)', background: 'var(--surface-1)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
            {hasOffline ? (
              <Segmented<CommandTab>
                ariaLabel="启动方式"
                value={activeTab}
                onChange={(t) => {
                  setActiveTab(t)
                  setCopied(false)
                }}
                options={[
                  { value: 'docker', label: '标准容器' },
                  { value: 'offline-docker', label: '脱机容器' },
                  { value: 'binary', label: '脱机二进制' },
                  { value: 'state', label: 'state.json' },
                ]}
              />
            ) : (
              <strong style={{ fontSize: 13 }}>标准接入命令</strong>
            )}

            <div style={{ display: 'flex', gap: 6 }}>
              {activeTab === 'state' && result.state_json && (
                <button type="button" className="btn btn-sm btn-ghost" onClick={downloadStateJson}>
                  <Download size={14} />
                  <span>导出文件</span>
                </button>
              )}
              <button
                type="button"
                className={`btn btn-sm btn-primary ${copied ? 'copy-bounce' : ''}`}
                onClick={() => void handleCopy()}
              >
                {copied ? <Check size={14} /> : <Copy size={14} />}
                <span>{copied ? '已复制' : '复制内容'}</span>
              </button>
            </div>
          </div>

          <p className="field-help">{modeHint}</p>

          <textarea
            className="mono ltr-force"
            value={activeCommand}
            readOnly
            rows={6}
            spellCheck={false}
            style={{ fontSize: 12.5, lineHeight: 1.55 }}
          />
          {status && <span className="field-help" style={{ color: 'var(--good)' }} role="status">{status}</span>}
        </div>
      )}

      {result?.warning && <Alert tone="warn">{result.warning}</Alert>}

      <Collapsible title="接入参数与通信说明">
        <p className="field-help">
          填写节点可访问的 Master 地址（含端口）；HTTPS 证书须匹配主机名。当节点无法连接 Hub 时，可使用「脱机容器 / 脱机二进制 / state.json」直接加载完整隧道与端口映射配置启动，待网络恢复后自动同步。
        </p>
        <p className="field-help">
          统一镜像 <code className="ltr-force">ghcr.io/aurorax-neo/veilink:latest</code> 以 <code>server</code> 或 <code>client</code> 子命令区分角色。节点接入令牌持久有效，多次生成不会覆盖旧令牌。
        </p>
        <p className="field-help">
          HTTP/h2c 不加密，仅用于可信网络；接入命令仅建立管理通信，客户端无需手写本地隧道 flags。
        </p>
      </Collapsible>
    </Modal>
  )
}
