import { useEffect, useMemo, useRef, useState } from 'react'
import { byNameAndId, endpoint, heartbeatOnline, isOfflineNode, nodeOperational, serverNowMs } from '../format'
import type { Mapping, MappingStatus, Node, PageId } from '../types'

interface Props {
  nodes: Node[]
  mappings: Mapping[]
  statuses: Record<string, MappingStatus>
  now?: number
  onNavigate: (page: PageId) => void
}

export function TopologyCanvas({ nodes, mappings, statuses, now, onNavigate }: Props) {
  const refNow = Math.max(now ?? 0, serverNowMs())
  const wrapRef = useRef<HTMLDivElement>(null)
  const [hoverId, setHoverId] = useState<string>('')
  const [canvasWidth, setCanvasWidth] = useState<number>(820)

  useEffect(() => {
    const el = wrapRef.current
    if (!el) return
    const sync = () => {
      const w = el.clientWidth - 28
      if (w > 0) setCanvasWidth(Math.max(480, Math.min(1360, Math.round(w))))
    }
    sync()
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(sync)
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  const servers = useMemo(() => nodes.filter((n) => n.role === 'server' && !n.revoked).sort(byNameAndId), [nodes])
  const clients = useMemo(() => nodes.filter((n) => n.role === 'client' && !n.revoked).sort(byNameAndId), [nodes])

  const pairMap = useMemo(() => {
    const nodeMap = new Map(nodes.map((n) => [n.id, n]))
    const map = new Map<string, { serverId: string; clientId: string; count: number; linked: number; offlineReady: number; enabled: number }>()
    for (const m of mappings) {
      const key = `${m.server_id}->${m.client_id}`
      const cur = map.get(key) || { serverId: m.server_id, clientId: m.client_id, count: 0, linked: 0, offlineReady: 0, enabled: 0 }
      cur.count += 1
      if (m.enabled) {
        cur.enabled += 1
        const st = statuses[m.id]
        const srv = nodeMap.get(m.server_id)
        const cli = nodeMap.get(m.client_id)
        if (st?.server?.linked && st?.client?.linked) {
          cur.linked += 1
        } else if (srv && cli && isOfflineNode(srv) && isOfflineNode(cli) && nodeOperational(srv, refNow) && nodeOperational(cli, refNow)) {
          cur.offlineReady += 1
        }
      }
      map.set(key, cur)
    }
    return [...map.values()]
  }, [mappings, nodes, statuses, refNow])

  // True 1:1 pixel geometry — never magnifies nodes or fonts on wide screens
  const nodeW = Math.min(188, Math.max(146, Math.round(canvasWidth * 0.23)))
  const nodeH = 38
  const rowGap = 46
  const padY = 10
  const padX = 8
  const rows = Math.max(servers.length, clients.length, 1)
  const height = rows * rowGap + padY * 2
  const width = canvasWidth

  const leftX = padX
  const rightX = width - padX - nodeW
  const serverPortX = leftX + nodeW
  const clientPortX = rightX

  const calcY = (idx: number, total: number) => {
    const span = height - padY * 2
    const step = span / Math.max(total, 1)
    return Math.round(padY + step * idx + step / 2)
  }

  const serverCoords = new Map(servers.map((s, i) => [s.id, { x: serverPortX, y: calcY(i, servers.length) }]))
  const clientCoords = new Map(clients.map((c, i) => [c.id, { x: clientPortX, y: calcY(i, clients.length) }]))
  const spanX = Math.max(80, clientPortX - serverPortX)
  const ctrlOffset = Math.round(Math.min(140, spanX * 0.38))

  return (
    <div ref={wrapRef} className="topology-canvas-wrap">
      <svg
        className="topology-svg"
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        role="img"
        aria-label="反向隧道拓扑"
      >
        <defs>
          <linearGradient id="edgeLinked" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#14b8a6" />
            <stop offset="100%" stopColor="#34d399" />
          </linearGradient>
          <linearGradient id="edgePending" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#fbbf24" />
            <stop offset="100%" stopColor="#f59e0b" />
          </linearGradient>
        </defs>

        {pairMap.map((edge) => {
          const from = serverCoords.get(edge.serverId)
          const to = clientCoords.get(edge.clientId)
          if (!from || !to) return null
          const activeLink = edge.linked > 0
          const offlineReady = !activeLink && edge.offlineReady > 0
          const muted = hoverId && hoverId !== edge.serverId && hoverId !== edge.clientId
          const midX = Math.round((from.x + to.x) / 2)
          const midY = Math.round((from.y + to.y) / 2)
          const d = `M ${from.x} ${from.y} C ${from.x + ctrlOffset} ${from.y}, ${to.x - ctrlOffset} ${to.y}, ${to.x} ${to.y}`
          return (
            <g key={`${edge.serverId}-${edge.clientId}`} opacity={muted ? 0.2 : 1} style={{ transition: 'opacity 140ms ease' }}>
              <path
                d={d}
                fill="none"
                stroke={activeLink ? 'url(#edgeLinked)' : offlineReady ? 'var(--info)' : edge.enabled > 0 ? 'url(#edgePending)' : 'var(--line-strong)'}
                strokeWidth={activeLink || offlineReady ? 1.8 : 1.25}
                strokeDasharray={activeLink ? undefined : '4 4'}
              />
              <g transform={`translate(${midX}, ${midY})`} style={{ cursor: 'pointer' }} onClick={() => onNavigate('proxies')}>
                <rect x="-26" y="-9.5" width="52" height="19" rx="9.5" fill="var(--surface-3)" stroke="var(--line-subtle)" strokeWidth="1" />
                <text x="0" y="3.5" textAnchor="middle" fill={activeLink ? 'var(--good)' : offlineReady ? 'var(--info)' : 'var(--text-secondary)'} fontSize="10.5" fontFamily="var(--font-mono)">
                  {edge.linked + edge.offlineReady}/{edge.count}
                </text>
              </g>
            </g>
          )
        })}

        {servers.map((node) => {
          const pos = serverCoords.get(node.id)!
          const offline = isOfflineNode(node)
          const online = !node.disabled && heartbeatOnline(node, refNow)
          const dotColor = node.disabled
            ? 'var(--text-muted)'
            : offline
              ? nodeOperational(node, refNow)
                ? 'var(--info)'
                : 'var(--warn)'
              : online
                ? 'var(--good)'
                : 'var(--warn)'
          const isHovered = hoverId === node.id
          const sub = node.address ? endpoint(node.address, node.port) : ''
          return (
            <g
              key={node.id}
              transform={`translate(${leftX}, ${Math.round(pos.y - nodeH / 2)})`}
              style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHoverId(node.id)}
              onMouseLeave={() => setHoverId('')}
              onClick={() => onNavigate('servers')}
            >
              <rect
                width={nodeW}
                height={nodeH}
                rx="8"
                fill={isHovered ? 'var(--surface-3)' : 'var(--surface-1)'}
                stroke={isHovered ? 'var(--accent-border)' : 'var(--line-subtle)'}
                strokeWidth="1"
              />
              <circle cx="12" cy={nodeH / 2} r="3.5" fill={dotColor} />
              <text x="22" y={sub ? 15.5 : 23} fill="var(--text-primary)" fontSize="12" fontWeight="500">
                {node.name.length > 16 ? `${node.name.slice(0, 15)}…` : node.name}
              </text>
              {sub && (
                <text x="22" y="29.5" fill="var(--text-muted)" fontSize="10" fontFamily="var(--font-mono)">
                  {sub.length > 22 ? `${sub.slice(0, 21)}…` : sub}
                </text>
              )}
              <circle cx={nodeW} cy={nodeH / 2} r="3" fill="var(--accent)" />
            </g>
          )
        })}

        {clients.map((node) => {
          const pos = clientCoords.get(node.id)!
          const offline = isOfflineNode(node)
          const online = !node.disabled && heartbeatOnline(node, refNow)
          const dotColor = node.disabled
            ? 'var(--text-muted)'
            : offline
              ? nodeOperational(node, refNow)
                ? 'var(--info)'
                : 'var(--warn)'
              : online
                ? 'var(--good)'
                : 'var(--warn)'
          const isHovered = hoverId === node.id
          const routeCount = mappings.filter((m) => m.client_id === node.id).length
          return (
            <g
              key={node.id}
              transform={`translate(${rightX}, ${Math.round(pos.y - nodeH / 2)})`}
              style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHoverId(node.id)}
              onMouseLeave={() => setHoverId('')}
              onClick={() => onNavigate('clients')}
            >
              <rect
                width={nodeW}
                height={nodeH}
                rx="8"
                fill={isHovered ? 'var(--surface-3)' : 'var(--surface-1)'}
                stroke={isHovered ? 'var(--accent-border)' : 'var(--line-subtle)'}
                strokeWidth="1"
              />
              <circle cx="0" cy={nodeH / 2} r="3" fill={online ? 'var(--good)' : offline && nodeOperational(node, refNow) ? 'var(--info)' : 'var(--text-muted)'} />
              <circle cx="12" cy={nodeH / 2} r="3.5" fill={dotColor} />
              <text x="22" y="15.5" fill="var(--text-primary)" fontSize="12" fontWeight="500">
                {node.name.length > 16 ? `${node.name.slice(0, 15)}…` : node.name}
              </text>
              <text x="22" y="29.5" fill="var(--text-muted)" fontSize="10" fontFamily="var(--font-mono)">
                {routeCount} 映射
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
