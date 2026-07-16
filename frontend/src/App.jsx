import { useRef, useState } from 'react'
import { downloadReport, streamPipeline, uploadLog, simulateAttack, fetchAlerts } from './api/client'
import PipelineStatus from './components/PipelineStatus'
import IncidentsTable from './components/IncidentsTable'
import IncidentDetail from './components/IncidentDetail'
import RiskChart from './components/RiskChart'
import ActivityLog from './components/ActivityLog'
import BlockedIPs from './components/BlockedIPs'
import AlertToast from './components/AlertToast'
import AlertPanel from './components/AlertPanel'
import HackerTerminals from './components/HackerTerminals'
import { NODE_ORDER, runningMessage, completedMessage, startMessage, doneMessage } from './components/narration'
import './App.css'

const SCENARIOS = [
  { id: 'brute_force', name: 'Brute Force', icon: '🔐', desc: 'Flood of failed login attempts' },
  { id: 'sql_injection', name: 'SQL Injection', icon: '💉', desc: 'Malicious SQL in web requests' },
  { id: 'xss', name: 'XSS', icon: '📜', desc: 'Script injection payloads' },
  { id: 'port_scan', name: 'Port Scan', icon: '🔍', desc: 'Endpoint probing from a single IP' },
  { id: 'privilege_escalation', name: 'Priv Escalation', icon: '⬆️', desc: 'sudo / root escalation' },
  { id: 'impossible_travel', name: 'Impossible Travel', icon: '✈️', desc: 'Login from distant cities' },
]

function App() {
  const [statusByNode, setStatusByNode] = useState({})
  const [running, setRunning] = useState(false)
  const [incidents, setIncidents] = useState([])
  const [findingCount, setFindingCount] = useState(0)
  const [error, setError] = useState(null)
  const [fileName, setFileName] = useState(null)
  const [selectedIncident, setSelectedIncident] = useState(null)
  const [activityLines, setActivityLines] = useState([])
  const [selectedScenario, setSelectedScenario] = useState(null)
  const [simCount, setSimCount] = useState(100)
  const [alerts, setAlerts] = useState([])
  const [alertPanelOpen, setAlertPanelOpen] = useState(false)
  const [simPanelOpen, setSimPanelOpen] = useState(false)
  const [simCompleted, setSimCompleted] = useState(false)
  const [isSimulating, setIsSimulating] = useState(false)
  const [blockedCount, setBlockedCount] = useState(0)
  const [refreshTrigger, setRefreshTrigger] = useState(0)
  const fileInputRef = useRef(null)
  const startTimeRef = useRef(0)

  function makeLine(kind, text) {
    const id = typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`
    return { id, kind, text }
  }

  function addLines(...lines) {
    setActivityLines((prev) => [...prev, ...lines])
  }

  function handlePipelineEvent(event, entries) {
    if (event.node === 'done') {
      const elapsed = (performance.now() - startTimeRef.current) / 1000
      addLines(makeLine('success', doneMessage(event.result.incidents, elapsed)))
      setIncidents(event.result.incidents)
      setFindingCount(event.result.findings.length)
      setRunning(false)
      setRefreshTrigger((p) => p + 1)
      // Fetch alerts after pipeline completes
      fetchAlerts().then((data) => setAlerts(data.alerts || [])).catch(() => {})
      return
    }

    setStatusByNode((prev) => ({ ...prev, [event.node]: event.status }))
    setFindingCount(event.findings_count ?? 0)

    const newLines = [makeLine('success', completedMessage(event.node, event))]
    const nextIndex = NODE_ORDER.indexOf(event.node) + 1
    if (nextIndex < NODE_ORDER.length) {
      newLines.push(makeLine('running', runningMessage(NODE_ORDER[nextIndex], {
        entryCount: entries?.length ?? 0,
        findingsCount: event.findings_count,
        incidentsCount: event.incidents_count,
      })))
    }
    addLines(...newLines)
  }

  function handleSimulationEvent(event) {
    if (event.node === 'done') {
      const elapsedMs = performance.now() - startTimeRef.current
      
      const finishUp = () => {
        setSimCompleted(true)
        setTimeout(() => {
          setRunning(false)
          setSimCompleted(false)
          setIsSimulating(false)
        }, 10000)
        
        const elapsed = (performance.now() - startTimeRef.current) / 1000
        addLines(makeLine('success', doneMessage(event.result.incidents, elapsed)))
        setIncidents(event.result.incidents)
        setFindingCount(event.result.findings.length)
        setRefreshTrigger((p) => p + 1)
        fetchAlerts().then((data) => setAlerts(data.alerts || [])).catch(() => {})
      }

      if (elapsedMs < 15000) {
        setTimeout(finishUp, 15000 - elapsedMs)
      } else {
        finishUp()
      }
      return
    }
    handlePipelineEvent(event, [])
  }

  async function handleFileChange(e) {
    const file = e.target.files?.[0]
    if (!file) return

    setError(null)
    setFileName(file.name)
    setStatusByNode({})
    setIncidents([])
    setFindingCount(0)
    setSelectedIncident(null)
    setActivityLines([])
    setRunning(true)
    startTimeRef.current = performance.now()

    try {
      const uploadResult = await uploadLog(file)
      const entries = uploadResult.entries

      addLines(
        makeLine('start', startMessage(entries.length)),
        makeLine('running', runningMessage(NODE_ORDER[0], { entryCount: entries.length, findingsCount: 0, incidentsCount: 0 })),
      )

      await streamPipeline(entries, (event) => handlePipelineEvent(event, entries))
    } catch (err) {
      setError(err.message)
      setRunning(false)
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  async function handleSimulate() {
    if (!selectedScenario || running) return

    setError(null)
    setFileName(null)
    setStatusByNode({})
    setIncidents([])
    setFindingCount(0)
    setSelectedIncident(null)
    setActivityLines([])
    setRunning(true)
    startTimeRef.current = performance.now()

    const scenarioName = SCENARIOS.find((s) => s.id === selectedScenario)?.name || selectedScenario

    addLines(
      makeLine('start', `Simulating ${scenarioName} attack (${simCount} log entries)...`),
      makeLine('running', runningMessage(NODE_ORDER[0], { entryCount: simCount, findingsCount: 0, incidentsCount: 0 })),
    )

    try {
      setSimPanelOpen(false)
      setIsSimulating(true)
      await simulateAttack(selectedScenario, simCount, (event) => handleSimulationEvent(event))
    } catch (err) {
      setError(err.message)
      setRunning(false)
    }
  }

  const unreadAlerts = alerts.filter((a) => !a.acknowledged).length

  return (
    <div className="app">
      {isSimulating && (
        <HackerTerminals 
          running={running} 
          scenario={selectedScenario} 
          completed={simCompleted} 
        />
      )}
      <header>
        <div className="header-row">
          <h1>S-MAS // COMMAND</h1>
          <div className="header-actions">
            <button className="sim-toggle-btn" onClick={() => setSimPanelOpen(true)}>
              ⚡
            </button>
            <button className="alert-bell" onClick={() => setAlertPanelOpen(true)}>
              🔔
              {unreadAlerts > 0 && <span className="alert-bell-badge">{unreadAlerts}</span>}
            </button>
          </div>
        </div>
        <p>MULTI-AGENT INTELLIGENCE CONSTRUCT</p>
      </header>

      <section className="upload-panel">
        <label className="upload-button">
          {running ? '[ PROCESSING_INGEST ]' : '[ INITIALIZE_INGEST ] (CSV / JSON / LOG)'}
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv,.json,.txt,.log"
            onChange={handleFileChange}
            disabled={running}
            hidden
          />
        </label>
        {fileName && <span className="file-name">{fileName}</span>}
        {error && <p className="error">{error}</p>}
      </section>

      {simPanelOpen && (
        <div className="sim-overlay" onClick={() => setSimPanelOpen(false)}>
          <div className="sim-panel-modal" onClick={(e) => e.stopPropagation()}>
            <div className="sim-panel-header">
              <h2>
                <span className="sim-icon">⚡</span>
                [ EXECUTE_SIMULATION ]
              </h2>
              <button className="detail-close" onClick={() => setSimPanelOpen(false)}>×</button>
            </div>
            
            <div className="sim-grid">
              {SCENARIOS.map((s) => (
                <button
                  key={s.id}
                  className={`sim-card ${selectedScenario === s.id ? 'sim-card-active' : ''}`}
                  onClick={() => setSelectedScenario(s.id)}
                  disabled={running}
                >
                  <span className="sim-card-icon">{s.icon}</span>
                  <span className="sim-card-name">{s.name}</span>
                  <span className="sim-card-desc">{s.desc}</span>
                </button>
              ))}
            </div>
            
            <div className="sim-controls">
              <label className="sim-slider-label">
                Log entries: <strong>{simCount}</strong>
                <input
                  type="range"
                  min={50}
                  max={500}
                  step={10}
                  value={simCount}
                  onChange={(e) => setSimCount(Number(e.target.value))}
                  disabled={running}
                  className="sim-slider"
                />
              </label>
              <button
                className="sim-run-btn"
                onClick={handleSimulate}
                disabled={!selectedScenario || running}
              >
                {running ? 'Simulating…' : '▶ Simulate'}
              </button>
            </div>
          </div>
        </div>
      )}

      <section className="summary-bar">
        <div className="summary-card">
          <span className="summary-value">{findingCount}</span>
          <span className="summary-label">SYS.FINDINGS</span>
        </div>
        <div className="summary-card">
          <span className="summary-value">{incidents.length}</span>
          <span className="summary-label">SYS.INCIDENTS</span>
        </div>
        <div className="summary-card">
          <span className="summary-value">
            {incidents.filter((i) => i.threat_level === 'Critical').length}
          </span>
          <span className="summary-label">SYS.CRITICAL</span>
        </div>
        <div className="summary-card">
          <span className="summary-value">
            {blockedCount}
          </span>
          <span className="summary-label">SYS.BLOCKED</span>
        </div>
      </section>

      <ActivityLog lines={activityLines} running={running} />

      <section className="grid">
        <PipelineStatus statusByNode={statusByNode} running={running} />
        <RiskChart incidents={incidents} />
      </section>

      <BlockedIPs refreshTrigger={refreshTrigger} onBlockedCountChange={setBlockedCount} />

      <section>
        <div className="incidents-header">
          <h2>[ SYS.INCIDENTS_DB ]</h2>
          {incidents.length > 0 && (
            <div className="report-buttons">
              <button onClick={() => downloadReport(incidents, 'pdf')}>PDF</button>
              <button onClick={() => downloadReport(incidents, 'html')}>HTML</button>
              <button onClick={() => downloadReport(incidents, 'json')}>JSON</button>
            </div>
          )}
        </div>
        <IncidentsTable incidents={incidents} onSelect={setSelectedIncident} />
      </section>

      {selectedIncident && (
        <IncidentDetail incident={selectedIncident} onClose={() => setSelectedIncident(null)} />
      )}

      <AlertToast alerts={alerts} />
      <AlertPanel
        open={alertPanelOpen}
        onClose={() => setAlertPanelOpen(false)}
        refreshTrigger={refreshTrigger}
        onAlertsUpdated={setAlerts}
      />
    </div>
  )
}

export default App
