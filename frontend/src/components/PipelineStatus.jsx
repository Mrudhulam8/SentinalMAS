const NODE_LABELS = {
  log_analysis: 'Log Analysis Agent',
  threat_intel: 'Threat Intelligence Agent',
  asset_context: 'Asset Context Agent',
  correlation: 'Correlation Agent',
  risk_assessment: 'Risk Assessment Agent',
  response: 'Response Recommendation Agent',
}

const NODE_ORDER = Object.keys(NODE_LABELS)

export default function PipelineStatus({ statusByNode, running }) {
  return (
    <div className="pipeline-status">
      <h3>Agent Execution Status {running && <span className="live-dot" />}</h3>
      <ol>
        {NODE_ORDER.map((node) => {
          const status = statusByNode[node] || 'pending'
          return (
            <li key={node} className={`node-${status}`}>
              <span className="status-icon">
                {status === 'completed' ? '✓' : status === 'running' ? '…' : '○'}
              </span>
              {NODE_LABELS[node]}
            </li>
          )
        })}
      </ol>
    </div>
  )
}
