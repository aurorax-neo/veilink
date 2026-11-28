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

interface PlacedEdge {
  key: string
  serverId: string
  clientId: string
  serverName: string
  clientName: string
  count: number
  linked: number
  offlineReady: number
  enabled: number
  d: string
  startX: number
  startY: number
  endX: number
  endY: number
  pillX: number
  pillY: number
  pillW: number
  pillH: number
  label: string
}

function cubicBezierPoint(
  p0x: number,
  p0y: number,
  p1x: number,
  p1y: number,
  p2x: number,
  p2y: number,
  p3x: number,
  p3y: number,
  t: number,
): { x: number; y: number } {
  const u = 1 - t
  const tt = t * t
  const uu = u * u
  const uuu = uu * u
  const ttt = tt * t
  return {
    x: uuu * p0x + 3 * uu * t * p1x + 3 * u * tt * p2x + ttt * p3x,
    y: uuu * p0y + 3 * uu * t * p1y + 3 * u * tt * p2y + ttt * p3y,
  }
}

export function TopologyCanvas({ nodes, mappings, statuses, now, onNavigate }: Props) {
  const refNow = Math.max(now ?? 0, serverNowMs())
  const wrapRef = useRef<HTMLDivElement>(null)
  const [hoverNodeId, setHoverNodeId] = useState<string>('')
  const [hoverEdgeKey, setHoverEdgeKey] = useState<string>('')
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

  const pairList = useMemo(() => {
    const nodeMap = new Map(nodes.map((n) => [n.id, n]))
    const map = new Map<
      string,
      {
        key: string
        serverId: string
        clientId: string
        serverName: string
        clientName: string
        count: number
        linked: number
        offlineReady: number
        enabled: number
      }
    >()
    for (const m of mappings) {
      const srv = nodeMap.get(m.server_id)
      const cli = nodeMap.get(m.client_id)
      if (!srv || !cli || srv.revoked || cli.revoked) continue
      const key = `${m.server_id}->${m.client_id}`
      const cur = map.get(key) || {
        key,
        serverId: m.server_id,
        clientId: m.client_id,
        serverName: srv.name,
        clientName: cli.name,
        count: 0,
        linked: 0,
        offlineReady: 0,
        enabled: 0,
      }
      cur.count += 1
      if (m.enabled) {
        cur.enabled += 1
        const st = statuses[m.id]
        if (st?.server?.linked && st?.client?.linked) {
          cur.linked += 1
        } else if (isOfflineNode(srv) && isOfflineNode(cli) && nodeOperational(srv, refNow) && nodeOperational(cli, refNow)) {
          cur.offlineReady += 1
        }
      }
      map.set(key, cur)
    }
    return [...map.values()]
  }, [mappings, nodes, statuses, refNow])

  // True 1:1 pixel geometry — never magnifies nodes or fonts on wide screens
  const nodeW = Math.min(236, Math.max(154, Math.round(canvasWidth * 0.255)))
  const nodeH = 38
  const rowGap = 54
  const padY = 14
  const padX = 10
  const rows = Math.max(servers.length, clients.length, 1)
  const height = rows * rowGap + padY * 2
  const width = canvasWidth

  const leftX = padX
  const rightX = width - padX - nodeW
  const serverPortX = leftX + nodeW
  const clientPortX = rightX
  const maxNameChars = Math.max(14, Math.floor((nodeW - 34) / 7.4))
  const maxSubChars = Math.max(18, Math.floor((nodeW - 34) / 6.1))

  const calcY = (idx: number, total: number) => {
    const span = height - padY * 2
    const step = span / Math.max(total, 1)
    return Math.round(padY + step * idx + step / 2)
  }

  const serverCoords = new Map(servers.map((s, i) => [s.id, { x: serverPortX, y: calcY(i, servers.length), idx: i }]))
  const clientCoords = new Map(clients.map((c, i) => [c.id, { x: clientPortX, y: calcY(i, clients.length), idx: i }]))
  const spanX = Math.max(100, clientPortX - serverPortX)
  const ctrlOffset = Math.round(Math.min(175, spanX * 0.42))

  // Compute fanned port anchors + collision- & crossing-free pill positions along each edge's cubic Bezier curve
  const placedEdges = useMemo<PlacedEdge[]>(() => {
    const serverGroups = new Map<string, typeof pairList>()
    const clientGroups = new Map<string, typeof pairList>()
    for (const edge of pairList) {
      if (!serverCoords.has(edge.serverId) || !clientCoords.has(edge.clientId)) continue
      const sg = serverGroups.get(edge.serverId) || []
      sg.push(edge)
      serverGroups.set(edge.serverId, sg)
      const cg = clientGroups.get(edge.clientId) || []
      cg.push(edge)
      clientGroups.set(edge.clientId, cg)
    }

    const startOffsetMap = new Map<string, number>()
    for (const [, list] of serverGroups) {
      list.sort((a, b) => (clientCoords.get(a.clientId)?.y ?? 0) - (clientCoords.get(b.clientId)?.y ?? 0))
      const n = list.length
      const maxSpread = Math.min(10, Math.max(0, (n - 1) * 3.5))
      list.forEach((edge, i) => {
        const off = n <= 1 ? 0 : -maxSpread + (2 * maxSpread * i) / (n - 1)
        startOffsetMap.set(edge.key, Math.round(off * 10) / 10)
      })
    }

    const endOffsetMap = new Map<string, number>()
    for (const [, list] of clientGroups) {
      list.sort((a, b) => (serverCoords.get(a.serverId)?.y ?? 0) - (serverCoords.get(b.serverId)?.y ?? 0))
      const n = list.length
      const maxSpread = Math.min(11, Math.max(0, (n - 1) * 3.5))
      list.forEach((edge, i) => {
        const off = n <= 1 ? 0 : -maxSpread + (2 * maxSpread * i) / (n - 1)
        endOffsetMap.set(edge.key, Math.round(off * 10) / 10)
      })
    }

    const raw = pairList
      .map((edge) => {
        const from = serverCoords.get(edge.serverId)
        const to = clientCoords.get(edge.clientId)
        if (!from || !to) return null
        const label = `${edge.linked + edge.offlineReady}/${edge.count}`
        const pillW = Math.max(46, label.length * 7 + 22)
        const pillH = 20
        const p0x = from.x
        const p0y = from.y + (startOffsetMap.get(edge.key) ?? 0)
        const p1x = from.x + ctrlOffset
        const p1y = p0y
        const p2x = to.x - ctrlOffset
        const p2y = to.y + (endOffsetMap.get(edge.key) ?? 0)
        const p3x = to.x
        const p3y = p2y
        const d = `M ${p0x} ${p0y} C ${p1x} ${p1y}, ${p2x} ${p2y}, ${p3x} ${p3y}`
        const samples: Array<{ x: number; y: number }> = []
        for (let i = 1; i <= 27; i += 1) {
          samples.push(cubicBezierPoint(p0x, p0y, p1x, p1y, p2x, p2y, p3x, p3y, i / 28))
        }
        return {
          ...edge,
          label,
          pillW,
          pillH,
          d,
          p0x,
          p0y,
          p1x,
          p1y,
          p2x,
          p2y,
          p3x,
          p3y,
          samples,
          sortY: (p0y + p3y) / 2,
          slope: Math.abs(p3y - p0y),
        }
      })
      .filter((x): x is NonNullable<typeof x> => x !== null)
      // Place horizontal/short-slope edges first, then stagger crossing diagonals cleanly
      .sort((a, b) => a.slope - b.slope || a.sortY - b.sortY)

    const placedBoxes: Array<{ x: number; y: number; w: number; h: number }> = []
    const padGapX = 10
    const padGapY = 8
    const tCandidates = [0.5, 0.42, 0.58, 0.34, 0.66, 0.26, 0.74, 0.19, 0.81, 0.46, 0.54, 0.3, 0.7]
    const minPillX = serverPortX + 36
    const maxPillX = clientPortX - 36
    const minPillY = 12
    const maxPillY = height - 12

    const overlapArea = (cx: number, cy: number, w: number, h: number) => {
      let area = 0
      const hw = w / 2 + padGapX / 2
      const hh = h / 2 + padGapY / 2
      for (const b of placedBoxes) {
        const dx = hw + b.w / 2 + padGapX / 2 - Math.abs(cx - b.x)
        const dy = hh + b.h / 2 + padGapY / 2 - Math.abs(cy - b.y)
        if (dx > 0 && dy > 0) area += dx * dy
      }
      return area
    }

    const crossingPenalty = (selfKey: string, cx: number, cy: number, w: number, h: number) => {
      let penalty = 0
      const hw = w / 2 + 7
      const hh = h / 2 + 6
      for (const other of raw) {
        if (other.key === selfKey) continue
        for (const pt of other.samples) {
          const dx = hw - Math.abs(cx - pt.x)
          const dy = hh - Math.abs(cy - pt.y)
          if (dx > 0 && dy > 0) {
            penalty += 120 + dx * dy
          }
        }
      }
      return penalty
    }

    return raw.map((item) => {
      let chosenX = Math.round((item.p0x + item.p3x) / 2)
      let chosenY = Math.round((item.p0y + item.p3y) / 2)
      let bestScore = Number.POSITIVE_INFINITY
      let bestOverlap = Number.POSITIVE_INFINITY

      for (const t of tCandidates) {
        const pt = cubicBezierPoint(
          item.p0x,
          item.p0y,
          item.p1x,
          item.p1y,
          item.p2x,
          item.p2y,
          item.p3x,
          item.p3y,
          t,
        )
        const cx = Math.round(Math.min(maxPillX, Math.max(minPillX, pt.x)))
        const cy = Math.round(Math.min(maxPillY, Math.max(minPillY, pt.y)))
        const ov = overlapArea(cx, cy, item.pillW, item.pillH)
        const cross = crossingPenalty(item.key, cx, cy, item.pillW, item.pillH)
        const score = ov * 1000 + cross + Math.abs(t - 0.5) * 35
        if (score < bestScore) {
          bestScore = score
          bestOverlap = ov
          chosenX = cx
          chosenY = cy
        }
      }

      // If an extremely dense graph still has pill-pill overlap across all Bezier samples, nudge cleanly away
      if (bestOverlap > 0) {
        for (const dy of [-24, 24, -48, 48, -14, 14]) {
          const ny = Math.round(Math.min(maxPillY, Math.max(minPillY, chosenY + dy)))
          if (overlapArea(chosenX, ny, item.pillW, item.pillH) === 0) {
            chosenY = ny
            break
          }
        }
      }

      placedBoxes.push({ x: chosenX, y: chosenY, w: item.pillW, h: item.pillH })
      return {
        key: item.key,
        serverId: item.serverId,
        clientId: item.clientId,
        serverName: item.serverName,
        clientName: item.clientName,
        count: item.count,
        linked: item.linked,
        offlineReady: item.offlineReady,
        enabled: item.enabled,
        d: item.d,
        startX: item.p0x,
        startY: item.p0y,
        endX: item.p3x,
        endY: item.p3y,
        pillX: chosenX,
        pillY: chosenY,
        pillW: item.pillW,
        pillH: item.pillH,
        label: item.label,
      }
    })
  }, [pairList, servers, clients, serverPortX, clientPortX, ctrlOffset, height])

  const activeEdge = placedEdges.find((e) => e.key === hoverEdgeKey) || null
  const isEdgeHighlighted = (edge: PlacedEdge) => {
    if (hoverEdgeKey) return edge.key === hoverEdgeKey
    if (hoverNodeId) return edge.serverId === hoverNodeId || edge.clientId === hoverNodeId
    return false
  }
  const isEdgeMuted = (edge: PlacedEdge) => {
    if (hoverEdgeKey) return edge.key !== hoverEdgeKey
    if (hoverNodeId) return edge.serverId !== hoverNodeId && edge.clientId !== hoverNodeId
    return false
  }
  const isNodeMuted = (nodeId: string) => {
    if (hoverEdgeKey && activeEdge) return nodeId !== activeEdge.serverId && nodeId !== activeEdge.clientId
    if (!hoverNodeId) return false
    if (nodeId === hoverNodeId) return false
    return !placedEdges.some(
      (e) =>
        (e.serverId === hoverNodeId && e.clientId === nodeId) ||
        (e.clientId === hoverNodeId && e.serverId === nodeId),
    )
  }

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

        {/* Layer 1: Edge Curves (always beneath pills so lines never slice through labels) */}
        <g className="topology-edges">
          {placedEdges.map((edge) => {
            const activeLink = edge.linked > 0
            const offlineReady = !activeLink && edge.offlineReady > 0
            const highlighted = isEdgeHighlighted(edge)
            const muted = isEdgeMuted(edge)
            const stroke = activeLink
              ? 'url(#edgeLinked)'
              : offlineReady
                ? 'var(--info)'
                : edge.enabled > 0
                  ? 'url(#edgePending)'
                  : 'var(--line-strong)'
            return (
              <g
                key={edge.key}
                opacity={muted ? 0.16 : highlighted ? 1 : 0.85}
                style={{ transition: 'opacity 140ms ease', cursor: 'pointer' }}
                onMouseEnter={() => setHoverEdgeKey(edge.key)}
                onMouseLeave={() => setHoverEdgeKey('')}
                onClick={() => onNavigate('proxies')}
              >
                {/* Wide invisible hit area for effortless edge hovering */}
                <path d={edge.d} fill="none" stroke="transparent" strokeWidth={12} />
                {highlighted && (
                  <path
                    d={edge.d}
                    fill="none"
                    stroke={stroke}
                    strokeWidth={6}
                    strokeOpacity={0.18}
                    strokeLinecap="round"
                  />
                )}
                <path
                  d={edge.d}
                  fill="none"
                  stroke={stroke}
                  strokeWidth={highlighted ? 2.4 : activeLink || offlineReady ? 1.8 : 1.3}
                  strokeDasharray={activeLink ? undefined : '4 4'}
                  strokeLinecap="round"
                />
              </g>
            )
          })}
        </g>

        {/* Layer 2: Collision-Free Edge Count Pills (always above curves) */}
        <g className="topology-pills">
          {placedEdges.map((edge) => {
            const activeLink = edge.linked > 0
            const offlineReady = !activeLink && edge.offlineReady > 0
            const highlighted = isEdgeHighlighted(edge)
            const muted = isEdgeMuted(edge)
            const pillStroke = highlighted
              ? activeLink
                ? 'var(--good)'
                : offlineReady
                  ? 'var(--info)'
                  : 'var(--accent-border)'
              : 'var(--line-subtle)'
            const textColor = activeLink ? 'var(--good)' : offlineReady ? 'var(--info)' : 'var(--text-secondary)'
            return (
              <g
                key={`pill-${edge.key}`}
                transform={`translate(${edge.pillX}, ${edge.pillY})`}
                opacity={muted ? 0.2 : 1}
                style={{ transition: 'opacity 140ms ease', cursor: 'pointer' }}
                onMouseEnter={() => setHoverEdgeKey(edge.key)}
                onMouseLeave={() => setHoverEdgeKey('')}
                onClick={() => onNavigate('proxies')}
              >
                <title>{`${edge.serverName} → ${edge.clientName}：${edge.label} 条已就绪`}</title>
                <rect
                  x={-edge.pillW / 2}
                  y={-edge.pillH / 2}
                  width={edge.pillW}
                  height={edge.pillH}
                  rx={edge.pillH / 2}
                  fill={highlighted ? 'var(--surface-4)' : 'var(--surface-2)'}
                  stroke={pillStroke}
                  strokeWidth={highlighted ? 1.25 : 1}
                />
                <text
                  x="0"
                  y="3.5"
                  textAnchor="middle"
                  fill={textColor}
                  fontSize="10.5"
                  fontWeight={highlighted ? '600' : '500'}
                  fontFamily="var(--font-mono)"
                >
                  {edge.label}
                </text>
              </g>
            )
          })}
        </g>

        {/* Layer 3: Server Gateway Nodes */}
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
          const isHovered = hoverNodeId === node.id || activeEdge?.serverId === node.id
          const muted = isNodeMuted(node.id)
          const sub = node.address ? endpoint(node.address, node.port) : ''
          return (
            <g
              key={node.id}
              transform={`translate(${leftX}, ${Math.round(pos.y - nodeH / 2)})`}
              opacity={muted ? 0.36 : 1}
              style={{ cursor: 'pointer', transition: 'opacity 140ms ease' }}
              onMouseEnter={() => setHoverNodeId(node.id)}
              onMouseLeave={() => setHoverNodeId('')}
              onClick={() => onNavigate('servers')}
            >
              <title>{sub ? `${node.name} (${sub})` : node.name}</title>
              <rect
                width={nodeW}
                height={nodeH}
                rx="8"
                fill={isHovered ? 'var(--surface-3)' : 'var(--surface-1)'}
                stroke={isHovered ? 'var(--accent-border)' : 'var(--line-subtle)'}
                strokeWidth={isHovered ? '1.25' : '1'}
              />
              <circle cx="12" cy={nodeH / 2} r="3.5" fill={dotColor} />
              <text x="22" y={sub ? 15.5 : 23} fill="var(--text-primary)" fontSize="12" fontWeight="500">
                {node.name.length > maxNameChars ? `${node.name.slice(0, maxNameChars - 1)}…` : node.name}
              </text>
              {sub && (
                <text x="22" y="29.5" fill="var(--text-muted)" fontSize="10" fontFamily="var(--font-mono)">
                  {sub.length > maxSubChars ? `${sub.slice(0, maxSubChars - 1)}…` : sub}
                </text>
              )}
            </g>
          )
        })}

        {/* Layer 4: Client Nodes */}
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
          const isHovered = hoverNodeId === node.id || activeEdge?.clientId === node.id
          const muted = isNodeMuted(node.id)
          const routeCount = mappings.filter((m) => m.client_id === node.id).length
          return (
            <g
              key={node.id}
              transform={`translate(${rightX}, ${Math.round(pos.y - nodeH / 2)})`}
              opacity={muted ? 0.36 : 1}
              style={{ cursor: 'pointer', transition: 'opacity 140ms ease' }}
              onMouseEnter={() => setHoverNodeId(node.id)}
              onMouseLeave={() => setHoverNodeId('')}
              onClick={() => onNavigate('clients')}
            >
              <title>{`${node.name} (${routeCount} 映射)`}</title>
              <rect
                width={nodeW}
                height={nodeH}
                rx="8"
                fill={isHovered ? 'var(--surface-3)' : 'var(--surface-1)'}
                stroke={isHovered ? 'var(--accent-border)' : 'var(--line-subtle)'}
                strokeWidth={isHovered ? '1.25' : '1'}
              />
              <circle cx="12" cy={nodeH / 2} r="3.5" fill={dotColor} />
              <text x="22" y="15.5" fill="var(--text-primary)" fontSize="12" fontWeight="500">
                {node.name.length > maxNameChars ? `${node.name.slice(0, maxNameChars - 1)}…` : node.name}
              </text>
              <text x="22" y="29.5" fill="var(--text-muted)" fontSize="10" fontFamily="var(--font-mono)">
                {routeCount} 映射
              </text>
            </g>
          )
        })}

        {/* Layer 5: Edge Endpoint Port Sockets (crisp above node borders) */}
        <g className="topology-ports" pointerEvents="none">
          {placedEdges.map((edge) => {
            const activeLink = edge.linked > 0
            const offlineReady = !activeLink && edge.offlineReady > 0
            const highlighted = isEdgeHighlighted(edge)
            const muted = isEdgeMuted(edge)
            const color = activeLink ? 'var(--good)' : offlineReady ? 'var(--info)' : edge.enabled > 0 ? 'var(--warn)' : 'var(--text-muted)'
            return (
              <g key={`port-${edge.key}`} opacity={muted ? 0.2 : 1} style={{ transition: 'opacity 140ms ease' }}>
                <circle cx={edge.startX} cy={edge.startY} r={highlighted ? 3.2 : 2.5} fill={color} stroke="var(--surface-1)" strokeWidth="1" />
                <circle cx={edge.endX} cy={edge.endY} r={highlighted ? 3.2 : 2.5} fill={color} stroke="var(--surface-1)" strokeWidth="1" />
              </g>
            )
          })}
        </g>
      </svg>
    </div>
  )
}
