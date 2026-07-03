import { useRef, useState } from 'react'
import { downloadReport, streamPipeline, uploadLog } from './api/client'
import PipelineStatus from './components/PipelineStatus'
import IncidentsTable from './components/IncidentsTable'
import IncidentDetail from './components/IncidentDetail'
import RiskChart from './components/RiskChart'
import ActivityLog from './components/ActivityLog'
import { NODE_ORDER, runningMessage, completedMessage, startMessage, doneMessage } from './components/narration'
import './App.css'

function App() {
  const [statusByNode, setStatusByNode] = useState({})
  const [running, setRunning] = useState(false)
  const [incidents, setIncidents] = useState([])
  const [findingCount, setFindingCount] = useState(0)
  const [error, setError] = useState(null)
  const [fileName, setFileName] = useState(null)
  const [selectedIncident, setSelectedIncident] = useState(null)
  const [activityLines, setActivityLines] = useState([])
  const fileInputRef = useRef(null)
  const startTimeRef = useRef(0)

  function makeLine(kind, text) {
    const id = typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`
    return { id, kind, text }
  }

  // Adds one or more lines as a single state update. Batching matters here:
  // a stage's "completed" and the next stage's "running" line are produced
  // together in the same tick, and issuing them as separate setState calls
  // (each spreading the same stale `prev`) is the kind of pattern React 18
  // StrictMode's dev-only double-render flags with spurious duplicate-key
  // warnings, even though the final committed state is correct either way.
  function addLines(...lines) {
    setActivityLines((prev) => [...prev, ...lines])
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

      await streamPipeline(entries, (event) => {
        if (event.node === 'done') {
          const elapsed = (performance.now() - startTimeRef.current) / 1000
          addLines(makeLine('success', doneMessage(event.result.incidents, elapsed)))
          setIncidents(event.result.incidents)
          setFindingCount(event.result.findings.length)
          setRunning(false)
          return
        }

        setStatusByNode((prev) => ({ ...prev, [event.node]: event.status }))
        setFindingCount(event.findings_count ?? 0)

        const newLines = [makeLine('success', completedMessage(event.node, event))]
        const nextIndex = NODE_ORDER.indexOf(event.node) + 1
        if (nextIndex < NODE_ORDER.length) {
          newLines.push(makeLine('running', runningMessage(NODE_ORDER[nextIndex], {
            entryCount: entries.length,
            findingsCount: event.findings_count,
            incidentsCount: event.incidents_count,
          })))
        }
        addLines(...newLines)
      })
    } catch (err) {
      setError(err.message)
      setRunning(false)
    } finally {
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  return (
    <div className="app">
      <header>
        <h1>SecureOrch</h1>
        <p>Multi-Agent AI Security Operations Center</p>
      </header>

      <section className="upload-panel">
        <label className="upload-button">
          {running ? 'Processing…' : 'Upload security log (CSV / JSON / TXT / Apache / Linux)'}
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

      <section className="summary-bar">
        <div className="summary-card">
          <span className="summary-value">{findingCount}</span>
          <span className="summary-label">Findings</span>
        </div>
        <div className="summary-card">
          <span className="summary-value">{incidents.length}</span>
          <span className="summary-label">Incidents</span>
        </div>
        <div className="summary-card">
          <span className="summary-value">
            {incidents.filter((i) => i.threat_level === 'Critical').length}
          </span>
          <span className="summary-label">Critical</span>
        </div>
      </section>

      <ActivityLog lines={activityLines} running={running} />

      <section className="grid">
        <PipelineStatus statusByNode={statusByNode} running={running} />
        <RiskChart incidents={incidents} />
      </section>

      <section>
        <div className="incidents-header">
          <h2>Incidents</h2>
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
    </div>
  )
}

export default App
