import { useMemo, useState } from 'react'
import { byNameAndId, endpoint, heartbeatOnline, tunnelSummaryText } from '../format'
import type { Mapping, MappingStatus, Node, PageId } from '../types'

interface Props {
  nodes: Node[]
  mappings: Mapping[]
  statuses: Record<string, MappingStatus>
  onNavigate: (page: PageId) => void
}

export function TopologyCanvas({ nodes, mappings, statuses, onNavigate }: Props) {
  const [hoverId, setHoverId] = useState<string>('')

  const servers = useMemo(() => nodes.filter((n) => n.role === 'server' && !n.revoked).sort(byNameAndId), [nodes])
  const clients = useMemo(() => nodes.filter((n) => n.role === 'client' && !n.revoked).sort(byNameAndId), [nodes])

  const pairMap = useMemo(() => {
    const map = new Map<string, { serverId: string; clientId: string; count: number; linked: number; enabled: number }>()
    for (const m of mappings) {
      const key = `${m.server_id}->${m.client_id}`
      const cur = map.get(key) || { serverId: m.server_id, clientId: m.client_id, count: 0, linked: 0, enabled: 0 }
      cur.count += 1
      if (m.enabled) {
        cur.enabled += 1
        const st = statuses[m.id]
        if (st?.server?.linked && st?.client?.linked) cur.linked += 1
      }
      map.set(key, cur)
    }
    return [...map.values()]
  }, [mappings, statuses])

  const rows = Math.max(servers.length, clients.length, 1)
  const rowHeight = 76
  const height = Math.max(200, rows * rowHeight + 56)
  const width = 880

  const serverY = (idx: number) => {
    const step = (height - 48) / Math.max(servers.length, 1)
    return 24 + step * idx + step / 2
  }
  const clientY = (idx: number) => {
    const step = (height - 48) / Math.max(clients.length, 1)
    return 24 + step * idx + step / 2
  }

  const serverCoords = new Map(servers.map((s, i) => [s.id, { x: 250, y: serverY(i) }]))
  const clientCoords = new Map(clients.map((c, i) => [c.id, { x: 630, y: clientY(i) }]))

  return (
    <div className="topology-canvas-wrap">
      <svg className="topology-svg" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="反向隧道实时拓扑图">
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

        {/* Column Headers */}
        <text x="24" y="18" fill="var(--text-muted)" fontSize="11" fontWeight="500">
          PUBLIC GATEWAYS (SERVER)
        </text>
        <text x="440" y="18" textAnchor="middle" fill="var(--text-muted)" fontSize="11" fontWeight="500">
          ENCRYPTED REVERSE TUNNELS
        </text>
        <text x="856" y="18" textAnchor="end" fill="var(--text-muted)" fontSize="11" fontWeight="500">
          INTRANET AGENTS (CLIENT)
        </text>

        {/* Curved Tunnel Links */}
        {pairMap.map((edge) => {
          const from = serverCoords.get(edge.serverId)
          const to = clientCoords.get(edge.clientId)
          if (!from || !to) return null
          const activeLink = edge.linked > 0
          const muted = hoverId && hoverId !== edge.serverId && hoverId !== edge.clientId
          const midX = (from.x + to.x) / 2
          const midY = (from.y + to.y) / 2
          const d = `M ${from.x} ${from.y} C ${from.x + 130} ${from.y}, ${to.x - 130} ${to.y}, ${to.x} ${to.y}`
          return (
            <g key={`${edge.serverId}-${edge.clientId}`} opacity={muted ? 0.18 : 1} style={{ transition: 'opacity 140ms ease' }}>
              <path
                d={d}
                fill="none"
                stroke={activeLink ? 'url(#edgeLinked)' : edge.enabled > 0 ? 'url(#edgePending)' : 'var(--line-strong)'}
                strokeWidth={activeLink ? 2.4 : 1.6}
                strokeDasharray={activeLink ? undefined : '5 5'}
              />
              <g transform={`translate(${midX}, ${midY})`} style={{ cursor: 'pointer' }} onClick={() => onNavigate('proxies')}>
                <rect x="-46" y="-12" width="92" height="24" rx="12" fill="var(--surface-3)" stroke="var(--line-subtle)" strokeWidth="1" />
                <text x="0" y="4" textAnchor="middle" fill={activeLink ? 'var(--good)' : 'var(--text-secondary)'} fontSize="11" fontFamily="var(--font-mono)">
                  {edge.linked}/{edge.count} routes
                </text>
              </g>
            </g>
          )
        })}

        {/* Server Nodes */}
        {servers.map((node) => {
          const pos = serverCoords.get(node.id)!
          const online = !node.disabled && heartbeatOnline(node)
          const isHovered = hoverId === node.id
          return (
            <g
              key={node.id}
              transform={`translate(24, ${pos.y - 28})`}
              style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHoverId(node.id)}
              onMouseLeave={() => setHoverId('')}
              onClick={() => onNavigate('servers')}
            >
              <rect
                width="226"
                height="56"
                rx="12"
                fill={isHovered ? 'var(--surface-3)' : 'var(--surface-1)'}
                stroke={isHovered ? 'var(--accent-border)' : 'var(--line-subtle)'}
                strokeWidth="1"
              />
              <circle cx="18" cy="21" r="4.5" fill={online ? 'var(--good)' : node.disabled ? 'var(--text-muted)' : 'var(--warn)'} />
              <text x="32" y="25" fill="var(--text-primary)" fontSize="13" fontWeight="500">
                {node.name.length > 20 ? `${node.name.slice(0, 19)}…` : node.name}
              </text>
              <text x="32" y="43" fill="var(--text-muted)" fontSize="11" fontFamily="var(--font-mono)">
                {node.address ? endpoint(node.address, node.port) : tunnelSummaryText(node).slice(0, 26)}
              </text>
              <circle cx="226" cy="28" r="4" fill="var(--accent)" />
            </g>
          )
        })}

        {/* Client Nodes */}
        {clients.map((node) => {
          const pos = clientCoords.get(node.id)!
          const online = !node.disabled && heartbeatOnline(node)
          const isHovered = hoverId === node.id
          const routeCount = mappings.filter((m) => m.client_id === node.id).length
          return (
            <g
              key={node.id}
              transform={`translate(630, ${pos.y - 28})`}
              style={{ cursor: 'pointer' }}
              onMouseEnter={() => setHoverId(node.id)}
              onMouseLeave={() => setHoverId('')}
              onClick={() => onNavigate('clients')}
            >
              <rect
                width="226"
                height="56"
                rx="12"
                fill={isHovered ? 'var(--surface-3)' : 'var(--surface-1)'}
                stroke={isHovered ? 'var(--accent-border)' : 'var(--line-subtle)'}
                strokeWidth="1"
              />
              <circle cx="0" cy="28" r="4" fill={online ? 'var(--good)' : 'var(--text-muted)'} />
              <circle cx="18" cy="21" r="4.5" fill={online ? 'var(--good)' : node.disabled ? 'var(--text-muted)' : 'var(--warn)'} />
              <text x="32" y="25" fill="var(--text-primary)" fontSize="13" fontWeight="500">
                {node.name.length > 20 ? `${node.name.slice(0, 19)}…` : node.name}
              </text>
              <text x="32" y="43" fill="var(--text-muted)" fontSize="11" fontFamily="var(--font-mono)">
                {routeCount} mapping{routeCount === 1 ? '' : 's'} · {node.software_version || 'agent'}
              </text>
            </g>
          )
        })}
      </svg>
    </div>
  )
}
