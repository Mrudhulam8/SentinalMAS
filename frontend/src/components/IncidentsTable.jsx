<<<<<<< HEAD
import { useMemo, useState } from 'react'

=======
>>>>>>> 4e42fe27b608da871312434e17e16aaee9671e70
const LEVEL_CLASS = {
  Critical: 'level-critical',
  High: 'level-high',
  Medium: 'level-medium',
  Low: 'level-low',
}

<<<<<<< HEAD
const SEVERITY_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 }

const FILTER_OPTIONS = ['All', 'Critical', 'High', 'Medium', 'Low']

export default function IncidentsTable({ incidents, onSelect }) {
  const [activeFilter, setActiveFilter] = useState('All')

  const filtered = useMemo(() => {
    const sorted = [...incidents].sort(
      (a, b) =>
        (SEVERITY_ORDER[a.threat_level] ?? 99) -
        (SEVERITY_ORDER[b.threat_level] ?? 99)
    )
    if (activeFilter === 'All') return sorted
    return sorted.filter((i) => i.threat_level === activeFilter)
  }, [incidents, activeFilter])

=======
export default function IncidentsTable({ incidents, onSelect }) {
>>>>>>> 4e42fe27b608da871312434e17e16aaee9671e70
  if (!incidents.length) {
    return <p className="empty-state">No incidents yet. Upload a log file to run the pipeline.</p>
  }

  return (
<<<<<<< HEAD
    <div>
      <div className="filter-bar">
        {FILTER_OPTIONS.map((level) => (
          <button
            key={level}
            className={`filter-pill ${activeFilter === level ? 'filter-active' : ''} ${
              level !== 'All' ? (LEVEL_CLASS[level] || '') : ''
            }`}
            onClick={() => setActiveFilter(level)}
          >
            {level}
            {level !== 'All' && (
              <span className="filter-count">
                {incidents.filter((i) => i.threat_level === level).length}
              </span>
            )}
          </button>
        ))}
      </div>

      <table className="incidents-table">
        <thead>
          <tr>
            <th>Priority</th>
            <th>Threat Level</th>
            <th>Risk Score</th>
            <th>IP / User</th>
            <th>Attack Types</th>
            <th>MITRE</th>
            <th>Recommended Actions</th>
          </tr>
        </thead>
        <tbody>
          {filtered.map((incident) => (
            <tr key={incident.incident_id} className="incident-row" onClick={() => onSelect(incident)}>
              <td>{incident.priority}</td>
              <td>
                <span className={`badge ${LEVEL_CLASS[incident.threat_level] || ''}`}>
                  {incident.threat_level}
                </span>
              </td>
              <td>{incident.risk_score}</td>
              <td>
                {incident.ip || incident.username || '—'}
                {incident.blocked && <span className="blocked-badge">🛑 Blocked</span>}
              </td>
              <td>{incident.attack_types.join(', ')}</td>
              <td>
                {[...new Set(incident.mitre_techniques.map((m) => m.technique_id))].join(', ')}
              </td>
              <td>{incident.recommended_actions.join(', ')}</td>
            </tr>
          ))}
          {filtered.length === 0 && (
            <tr>
              <td colSpan={7} className="empty-state" style={{ textAlign: 'center', padding: '1.5rem' }}>
                No {activeFilter} incidents found.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
=======
    <table className="incidents-table">
      <thead>
        <tr>
          <th>Priority</th>
          <th>Threat Level</th>
          <th>Risk Score</th>
          <th>IP / User</th>
          <th>Attack Types</th>
          <th>MITRE</th>
          <th>Recommended Actions</th>
        </tr>
      </thead>
      <tbody>
        {incidents.map((incident) => (
          <tr key={incident.incident_id} className="incident-row" onClick={() => onSelect(incident)}>
            <td>{incident.priority}</td>
            <td>
              <span className={`badge ${LEVEL_CLASS[incident.threat_level] || ''}`}>
                {incident.threat_level}
              </span>
            </td>
            <td>{incident.risk_score}</td>
            <td>{incident.ip || incident.username || '—'}</td>
            <td>{incident.attack_types.join(', ')}</td>
            <td>
              {[...new Set(incident.mitre_techniques.map((m) => m.technique_id))].join(', ')}
            </td>
            <td>{incident.recommended_actions.join(', ')}</td>
          </tr>
        ))}
      </tbody>
    </table>
>>>>>>> 4e42fe27b608da871312434e17e16aaee9671e70
  )
}
