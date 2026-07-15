import { useEffect, useState, useRef } from 'react'

function generateHexDump() {
  const addr = `0x${Math.floor(Math.random() * 0xFFFFFFFF).toString(16).toUpperCase().padStart(8, '0')}`
  const bytes = Array.from({length: 8}, () => Math.floor(Math.random() * 256).toString(16).padStart(2, '0')).join(' ')
  const chars = Array.from({length: 8}, () => {
    const c = Math.floor(Math.random() * (126 - 33) + 33)
    return String.fromCharCode(c)
  }).join('')
  return `${addr}  ${bytes}  |${chars}|`
}

function generateFirewallLog() {
  const ip = `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`
  const actions = ['DROP', 'REJECT', 'BLOCK', 'ROUTE', 'TRACE']
  const action = actions[Math.floor(Math.random() * actions.length)]
  return `[${action}] SRC=${ip} DST=10.0.0.1 PORT=${Math.floor(Math.random() * 65535)} LEN=${Math.floor(Math.random() * 1500)}`
}

function generateNeuralLog() {
  const actions = [
    'Adjusting heuristic weights...',
    'Extracting semantic embeddings...',
    'Performing real-time anomaly detection...',
    'Backpropagating error gradients...',
    'Correlating temporal signatures...',
    'Isolating suspicious subgraphs...',
  ]
  const action = actions[Math.floor(Math.random() * actions.length)]
  const conf = (Math.random() * 0.99).toFixed(4)
  return `[SYS.NEURAL] ${action} [CONFIDENCE: ${conf}]`
}

export default function HackerTerminals({ running, scenario, completed }) {
  const [payloadLines, setPayloadLines] = useState([])
  const [firewallLines, setFirewallLines] = useState([])
  const [neuralLines, setNeuralLines] = useState([])
  
  const pRef = useRef(null)
  const fRef = useRef(null)
  const nRef = useRef(null)

  useEffect(() => {
    if (!running && !completed) {
      setPayloadLines([])
      setFirewallLines([])
      setNeuralLines([])
      return
    }

    if (completed) return // stop streaming new data if completed

    const pInt = setInterval(() => {
      setPayloadLines(prev => [...prev.slice(-30), generateHexDump()])
      if (pRef.current) pRef.current.scrollTop = pRef.current.scrollHeight
    }, 40)

    const fInt = setInterval(() => {
      setFirewallLines(prev => [...prev.slice(-20), generateFirewallLog()])
      if (fRef.current) fRef.current.scrollTop = fRef.current.scrollHeight
    }, 150)

    const nInt = setInterval(() => {
      setNeuralLines(prev => [...prev.slice(-25), generateNeuralLog()])
      if (nRef.current) nRef.current.scrollTop = nRef.current.scrollHeight
    }, 250)

    return () => {
      clearInterval(pInt)
      clearInterval(fInt)
      clearInterval(nInt)
    }
  }, [running, completed])

  if (!running && !completed) return null

  return (
    <div className={`hacker-overlay ${completed ? 'hacker-overlay-fadeOut' : ''}`}>
      <div className="hacker-grid">
        <div className="hacker-term term-payload">
          <div className="term-header">[ PAYLOAD_INJECTOR :: {scenario?.toUpperCase()} ]</div>
          <div className="term-body" ref={pRef}>
            {payloadLines.map((l, i) => <div key={i}>{l}</div>)}
          </div>
        </div>
        <div className="hacker-term term-firewall">
          <div className="term-header">[ SYS.FIREWALL_DEFENSE ]</div>
          <div className="term-body" ref={fRef}>
            {firewallLines.map((l, i) => <div key={i}>{l}</div>)}
          </div>
        </div>
        <div className="hacker-term term-neural">
          <div className="term-header">[ NEURAL_ANALYSIS_ENGINE ]</div>
          <div className="term-body" ref={nRef}>
            {neuralLines.map((l, i) => <div key={i}>{l}</div>)}
            {completed && <div className="hacker-complete-msg">[ SIMULATION COMPLETE ]</div>}
          </div>
        </div>
      </div>
      <div className="hacker-overlay-scanlines"></div>
    </div>
  )
}
