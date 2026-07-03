import { useEffect, useState } from 'react'
import { explainStage } from './reasoning'

const SEVERITY_CLASS = { high: 'level-high', medium: 'level-medium', low: 'level-low' }
const LEVEL_CLASS = { Critical: 'level-critical', High: 'level-high', Medium: 'level-medium', Low: 'level-low' }

function pluralize(count, word) {
  return `${count} ${word}${count === 1 ? '' : 's'}`
}

function buildStages(incident) {
  const mitreCount = new Set(incident.mitre_techniques.map((m) => m.technique_id)).size
  const hasReputation = incident.findings?.some(
    (f) => f.threat_intel?.abuseipdb || f.threat_intel?.virustotal
  )
  const asset = incident.asset_context

  return [
    {
      key: 'log_analysis',
      label: 'Log Analysis',
      detail: `${pluralize(incident.finding_count, 'finding')} · ${incident.attack_types.join(', ')}`,
    },
    {
      key: 'threat_intel',
      label: 'Threat Intelligence',
      detail: hasReputation
        ? `Live IP reputation checked · ${pluralize(mitreCount, 'MITRE technique')}`
        : `${pluralize(mitreCount, 'MITRE technique')} mapped`,
    },
    {
      key: 'asset_context',
      label: 'Asset Context',
      detail: asset
        ? `${asset.asset_id || asset.hostname || 'Matched asset'} · criticality ${asset.criticality ?? '—'}`
        : 'No registered asset match',
    },
    {
      key: 'correlation',
      label: 'Correlation',
      detail: `${pluralize(incident.finding_count, 'finding')} grouped into this incident`,
    },
    {
      key: 'risk_assessment',
      label: 'Risk Assessment',
      detail: `Score ${incident.risk_score} / 10 · ${incident.threat_level}`,
    },
    {
      key: 'response',
      label: 'Response',
      detail: `${pluralize(incident.recommended_actions.length, 'action')} recommended`,
    },
  ]
}

export default function IncidentDetail({ incident, onClose }) {
  const [expandedStage, setExpandedStage] = useState(null)

  useEffect(() => {
    function onKeyDown(e) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [onClose])

  useEffect(() => {
    setExpandedStage(null)
  }, [incident?.incident_id])

  if (!incident) return null

  const stages = buildStages(incident)
  const uniqueMitre = Object.values(
    Object.fromEntries(incident.mitre_techniques.map((m) => [m.technique_id, m]))
  )

  return (
    <div className="detail-overlay" onClick={onClose}>
      <aside className="detail-panel" onClick={(e) => e.stopPropagation()}>
        <div className="detail-header">
          <div>
            <span className={`badge ${LEVEL_CLASS[incident.threat_level] || ''}`}>
              {incident.threat_level}
            </span>
            <h2>{incident.ip || incident.username || incident.incident_id.slice(0, 8)}</h2>
            <p className="detail-subtitle">
              {incident.priority} · Risk score {incident.risk_score} / 10
            </p>
          </div>
          <button className="detail-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>

        <section className="detail-section">
          <h3>What happened</h3>
          <div className="pipeline-diagram">
            {stages.map((stage) => {
              const isOpen = expandedStage === stage.key
              const reasoning = isOpen ? explainStage(stage.key, incident) : null
              return (
                <div className="pipeline-stage" key={stage.key}>
                  <div className="pipeline-track">
                    <span className="pipeline-dot" />
                    <span className="pipeline-line" />
                  </div>
                  <div className="pipeline-content">
                    <div className="pipeline-label-row">
                      <span className="pipeline-label">{stage.label}</span>
                      <button
                        className={`stage-info-btn ${isOpen ? 'stage-info-btn-active' : ''}`}
                        onClick={() => setExpandedStage(isOpen ? null : stage.key)}
                        aria-label={`Why: ${stage.label}`}
                        title="Why?"
                      >
                        !
                      </button>
                    </div>
                    <p className="pipeline-detail">{stage.detail}</p>
                    {isOpen && (
                      <div className="stage-reasoning">
                        {reasoning.paragraphs.map((p, i) => (
                          <p key={i}>{p}</p>
                        ))}
                        {reasoning.breakdown && (
                          <>
                            <table className="reasoning-table">
                              <tbody>
                                {reasoning.breakdown.rows.map((r) => (
                                  <tr key={r.label}>
                                    <td>{r.label}</td>
                                    <td className="reasoning-detail-col">{r.detail}</td>
                                    <td className="reasoning-value-col">{r.value.toFixed(2)}</td>
                                  </tr>
                                ))}
                                <tr className="reasoning-total-row">
                                  <td colSpan={2}>Total (capped at 10)</td>
                                  <td className="reasoning-value-col">{reasoning.breakdown.total.toFixed(2)}</td>
                                </tr>
                              </tbody>
                            </table>
                            <p className="reasoning-band">{reasoning.breakdown.band}</p>
                          </>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </section>

        {uniqueMitre.length > 0 && (
          <section className="detail-section">
            <h3>MITRE ATT&CK</h3>
            <div className="mitre-badges">
              {uniqueMitre.map((m) => (
                <span className="mitre-badge" key={m.technique_id}>
                  {m.technique_id} · {m.technique}
                </span>
              ))}
            </div>
          </section>
        )}

        <section className="detail-section">
          <h3>Evidence ({incident.findings.length})</h3>
          <ul className="evidence-list">
            {incident.findings.map((f) => (
              <li key={f.id} className="evidence-item">
                <div className="evidence-head">
                  <span className={`badge ${SEVERITY_CLASS[f.severity] || ''}`}>
                    {f.severity}
                  </span>
                  <span className="evidence-type">{f.attack_type.replace(/_/g, ' ')}</span>
                </div>
                <p className="evidence-text">{f.evidence}</p>
                {f.explanation && <p className="evidence-explanation">{f.explanation}</p>}
              </li>
            ))}
          </ul>
        </section>

        {incident.asset_context && (
          <section className="detail-section">
            <h3>Asset Context</h3>
            <div className="asset-card">
              <div>
                <span className="asset-label">Asset</span>
                <span>{incident.asset_context.asset_id || incident.asset_context.hostname || '—'}</span>
              </div>
              <div>
                <span className="asset-label">Owner</span>
                <span>{incident.asset_context.owner || '—'}</span>
              </div>
              <div>
                <span className="asset-label">Department</span>
                <span>{incident.asset_context.department || '—'}</span>
              </div>
              <div>
                <span className="asset-label">Criticality</span>
                <span>{incident.asset_context.criticality ?? '—'} / 5</span>
              </div>
              <div>
                <span className="asset-label">Data sensitivity</span>
                <span>{incident.asset_context.data_sensitivity || '—'}</span>
              </div>
            </div>
          </section>
        )}

        <section className="detail-section">
          <h3>Recommended Actions</h3>
          <ul className="actions-list">
            {incident.recommended_actions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ul>
        </section>
      </aside>
    </div>
  )
}
