const LEVEL_CLASS = {
  Critical: 'level-critical',
  High: 'level-high',
  Medium: 'level-medium',
  Low: 'level-low',
}

export default function IncidentsTable({ incidents }) {
  if (!incidents.length) {
    return <p className="empty-state">No incidents yet. Upload a log file to run the pipeline.</p>
  }

  return (
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
          <tr key={incident.incident_id}>
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
  )
}
