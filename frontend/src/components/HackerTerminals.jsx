import { useEffect, useState, useRef } from 'react'

// ─── Data generators ───────────────────────────────────────────────────────

function randomHex(n) {
  return Array.from({ length: n }, () =>
    Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
  ).join(' ')
}

function generateHexDump() {
  const addr = `0x${Math.floor(Math.random() * 0xffffffff)
    .toString(16)
    .toUpperCase()
    .padStart(8, '0')}`
  const bytes = randomHex(8)
  const chars = Array.from({ length: 8 }, () => {
    const c = Math.floor(Math.random() * (126 - 33) + 33)
    return String.fromCharCode(c)
  }).join('')
  return { type: 'hex', text: `${addr}  ${bytes}  |${chars}|` }
}

function generateFirewallLog() {
  const ip = `${rn(1, 254)}.${rn(0, 255)}.${rn(0, 255)}.${rn(1, 254)}`
  const actions = ['DROP', 'REJECT', 'BLOCK', 'TRACE', 'DENY']
  const protocols = ['TCP', 'UDP', 'ICMP']
  const action = pick(actions)
  const proto = pick(protocols)
  const highlight = action === 'DROP' || action === 'DENY'
  return {
    type: highlight ? 'warn' : 'info',
    text: `[${action}] ${proto} SRC=${ip} → DST=10.0.0.1 PORT=${rn(1, 65535)} LEN=${rn(40, 1500)}`,
  }
}

function generateNeuralLog() {
  const entries = [
    { level: 'INFO',  msg: 'Loading threat-intel model weights' },
    { level: 'DEBUG', msg: `Tokenizing batch of ${rn(64, 512)} log entries` },
    { level: 'WARN',  msg: `Anomaly score ${(Math.random() * 0.4 + 0.6).toFixed(4)} exceeds threshold` },
    { level: 'INFO',  msg: `Embedding extracted — dim=768 norm=${(Math.random()).toFixed(4)}` },
    { level: 'DEBUG', msg: 'Running temporal correlation across sliding window' },
    { level: 'INFO',  msg: `Backprop loss=${(Math.random() * 0.05).toFixed(6)} lr=1e-4` },
    { level: 'WARN',  msg: `Suspicious cluster ID=${rn(0, 99)} — flagging for review` },
    { level: 'INFO',  msg: `Inference latency ${rn(4, 40)}ms p95=${rn(40, 120)}ms` },
  ]
  const { level, msg } = pick(entries)
  return { type: level.toLowerCase(), text: `[${level}] ${msg}` }
}

function generateThreatLine(scenario) {
  const templates = {
    brute_force: [
      () => `ATTEMPT #${rn(1000, 9999)} user=admin passwd=${randomHex(4)}`,
      () => `Rate: ${rn(100, 9999)} req/s from ${randIP()}`,
      () => `LOCKOUT triggered — account suspended`,
    ],
    sql_injection: [
      () => `PAYLOAD: ' OR 1=1; DROP TABLE users; --`,
      () => `WAF rule 942100 triggered — SQL keyword in URI`,
      () => `Injection vector: param=id value=${randomHex(3)}`,
    ],
    xss: [
      () => `PAYLOAD: <script>document.cookie</script>`,
      () => `CSP violation detected — blocked inline script`,
      () => `Reflected XSS probe from ${randIP()}`,
    ],
    port_scan: [
      () => `PROBE ${randIP()} → port ${rn(1, 65535)} [SYN]`,
      () => `Nmap fingerprint detected — OS: Linux 5.x`,
      () => `${rn(100, 999)} ports scanned in ${rn(1, 30)}s`,
    ],
    privilege_escalation: [
      () => `sudo attempt by uid=${rn(1000, 9999)} — FAILED`,
      () => `SUID binary exploited: /usr/bin/${pick(['pkexec','sudo','find'])}`,
      () => `Root shell spawned — PID=${rn(10000, 99999)}`,
    ],
    impossible_travel: [
      () => `LOGIN Singapore (${randIP()}) → London 4min apart`,
      () => `GeoIP delta: ${rn(5000, 15000)}km in ${rn(2, 10)}min`,
      () => `Session token reuse across ${rn(2, 5)} continents`,
    ],
  }
  const list = templates[scenario] || templates.brute_force
  return { type: 'attack', text: pick(list)() }
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function rn(min, max) { return Math.floor(Math.random() * (max - min + 1) + min) }
function pick(arr) { return arr[Math.floor(Math.random() * arr.length)] }
function randIP() { return `${rn(1,254)}.${rn(0,255)}.${rn(0,255)}.${rn(1,254)}` }

const SCENARIO_META = {
  brute_force:         { label: 'BRUTE FORCE',         icon: '🔐', color: '#ff6b6b' },
  sql_injection:       { label: 'SQL INJECTION',        icon: '💉', color: '#ffd93d' },
  xss:                 { label: 'XSS',                  icon: '📜', color: '#ff9f43' },
  port_scan:           { label: 'PORT SCAN',            icon: '🔍', color: '#a29bfe' },
  privilege_escalation:{ label: 'PRIV ESCALATION',      icon: '⬆️', color: '#fd79a8' },
  impossible_travel:   { label: 'IMPOSSIBLE TRAVEL',    icon: '✈️', color: '#55efc4' },
}

// ─── Component ───────────────────────────────────────────────────────────────
export default function HackerTerminals({ running, scenario, completed }) {
  const [payloadLines, setPayloadLines]   = useState([])
  const [firewallLines, setFirewallLines] = useState([])
  const [neuralLines, setNeuralLines]     = useState([])
  const [attackLines, setAttackLines]     = useState([])
  const [ticker, setTicker]               = useState(0)   // elapsed seconds

  const pRef = useRef(null)
  const fRef = useRef(null)
  const nRef = useRef(null)
  const aRef = useRef(null)

  // Streaming data
  useEffect(() => {
    if (!running && !completed) {
      setPayloadLines([])
      setFirewallLines([])
      setNeuralLines([])
      setAttackLines([])
      return
    }
    if (completed) return

    const pInt = setInterval(() => {
      setPayloadLines(prev => [...prev.slice(-40), generateHexDump()])
      if (pRef.current) pRef.current.scrollTop = pRef.current.scrollHeight
    }, 35)

    const fInt = setInterval(() => {
      setFirewallLines(prev => [...prev.slice(-25), generateFirewallLog()])
      if (fRef.current) fRef.current.scrollTop = fRef.current.scrollHeight
    }, 130)

    const nInt = setInterval(() => {
      setNeuralLines(prev => [...prev.slice(-30), generateNeuralLog()])
      if (nRef.current) nRef.current.scrollTop = nRef.current.scrollHeight
    }, 200)

    const aInt = setInterval(() => {
      setAttackLines(prev => [...prev.slice(-20), generateThreatLine(scenario)])
      if (aRef.current) aRef.current.scrollTop = aRef.current.scrollHeight
    }, 180)

    return () => {
      clearInterval(pInt)
      clearInterval(fInt)
      clearInterval(nInt)
      clearInterval(aInt)
    }
  }, [running, completed, scenario])

  // Elapsed ticker
  useEffect(() => {
    if (!running || completed) return
    setTicker(0)
    const t = setInterval(() => setTicker(s => s + 1), 1000)
    return () => clearInterval(t)
  }, [running, completed])

  if (!running && !completed) return null

  const meta = SCENARIO_META[scenario] || { label: scenario?.toUpperCase(), icon: '⚡', color: '#00e5ff' }

  return (
    <div className={`ht-overlay ${completed ? 'ht-fadeOut' : ''}`}>
      {/* Top bar */}
      <div className="ht-topbar">
        <div className="ht-topbar-left">
          <span className="ht-status-dot" style={{ background: completed ? '#00ff88' : '#ff4444' }} />
          <span className="ht-title">S-MAS // THREAT SIMULATION CONSOLE</span>
        </div>
        <div className="ht-topbar-center">
          <span className="ht-scenario-badge" style={{ borderColor: meta.color, color: meta.color }}>
            {meta.icon} {meta.label}
          </span>
        </div>
        <div className="ht-topbar-right">
          {completed
            ? <span className="ht-elapsed ht-done">[ SIMULATION COMPLETE ]</span>
            : <span className="ht-elapsed">ELAPSED: <strong>{String(Math.floor(ticker/60)).padStart(2,'0')}:{String(ticker%60).padStart(2,'0')}</strong></span>
          }
        </div>
      </div>

      {/* Terminal grid */}
      <div className="ht-grid">
        {/* Payload hex dump */}
        <div className="ht-term ht-payload">
          <div className="ht-term-titlebar">
            <span className="ht-dot r"/><span className="ht-dot y"/><span className="ht-dot g"/>
            <span className="ht-term-title">PAYLOAD_INJECTOR :: {meta.label}</span>
            <span className="ht-blink">●</span>
          </div>
          <div className="ht-term-body" ref={pRef}>
            <div className="ht-term-col-header">ADDR          BYTES                    ASCII</div>
            {payloadLines.map((l, i) => (
              <div key={i} className="ht-line ht-hex">{l.text}</div>
            ))}
          </div>
        </div>

        {/* Attack stream */}
        <div className="ht-term ht-attack">
          <div className="ht-term-titlebar">
            <span className="ht-dot r"/><span className="ht-dot y"/><span className="ht-dot g"/>
            <span className="ht-term-title">THREAT_STREAM :: LIVE</span>
            <span className="ht-blink">●</span>
          </div>
          <div className="ht-term-body" ref={aRef}>
            {attackLines.map((l, i) => (
              <div key={i} className={`ht-line ht-attack-line ht-${l.type}`}>
                <span className="ht-ts">[{new Date().toLocaleTimeString('en-GB')}]</span> {l.text}
              </div>
            ))}
          </div>
        </div>

        {/* Firewall */}
        <div className="ht-term ht-firewall">
          <div className="ht-term-titlebar">
            <span className="ht-dot r"/><span className="ht-dot y"/><span className="ht-dot g"/>
            <span className="ht-term-title">SYS.FIREWALL_DEFENSE</span>
            <span className="ht-blink">●</span>
          </div>
          <div className="ht-term-body" ref={fRef}>
            {firewallLines.map((l, i) => (
              <div key={i} className={`ht-line ht-fw-line ht-fw-${l.type}`}>{l.text}</div>
            ))}
          </div>
        </div>

        {/* Neural AI */}
        <div className="ht-term ht-neural">
          <div className="ht-term-titlebar">
            <span className="ht-dot r"/><span className="ht-dot y"/><span className="ht-dot g"/>
            <span className="ht-term-title">NEURAL_ANALYSIS_ENGINE</span>
            <span className="ht-blink">●</span>
          </div>
          <div className="ht-term-body" ref={nRef}>
            {neuralLines.map((l, i) => (
              <div key={i} className={`ht-line ht-n-${l.type}`}>{l.text}</div>
            ))}
            {completed && (
              <div className="ht-complete-banner">
                ✓ ANALYSIS COMPLETE — THREAT NEUTRALISED
              </div>
            )}
          </div>
        </div>
      </div>

      {/* CRT scanlines */}
      <div className="ht-scanlines" />
      {/* Corner decorations */}
      <div className="ht-corner ht-corner-tl" />
      <div className="ht-corner ht-corner-tr" />
      <div className="ht-corner ht-corner-bl" />
      <div className="ht-corner ht-corner-br" />
    </div>
  )
}
