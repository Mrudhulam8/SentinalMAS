/**
 * Natural-language narration for the live activity log.
 *
 * Templates are filled with real numbers from the SSE pipeline stream
 * (findings_count / incidents_count as they arrive) -- not canned/fake
 * text -- so the log genuinely reflects what the backend just did.
 */

export const NODE_ORDER = [
  'log_analysis', 'threat_intel', 'asset_context',
  'correlation', 'risk_assessment', 'response',
]

const RUNNING_MESSAGES = {
  log_analysis: (ctx) =>
    `Scanning ${ctx.entryCount.toLocaleString()} log entries for attack patterns (brute force, SQLi, XSS, port scans...)`,
  threat_intel: (ctx) =>
    `Cross-referencing ${ctx.findingsCount.toLocaleString()} finding(s) against threat intelligence feeds and mapping MITRE ATT&CK techniques`,
  asset_context: () => 'Looking up asset criticality and ownership for affected systems',
  correlation: (ctx) =>
    `Grouping ${ctx.findingsCount.toLocaleString()} finding(s) by source IP / user into incidents`,
  risk_assessment: (ctx) =>
    `Calculating risk scores for ${ctx.incidentsCount.toLocaleString()} incident(s) from severity, diversity, asset criticality, and reputation`,
  response: (ctx) =>
    `Generating recommended mitigation actions for ${ctx.incidentsCount.toLocaleString()} incident(s)`,
}

const COMPLETED_MESSAGES = {
  log_analysis: (event) =>
    `Detected ${event.findings_count.toLocaleString()} suspicious finding(s) in the log data`,
  threat_intel: (event) =>
    `Threat intelligence enrichment complete for ${event.findings_count.toLocaleString()} finding(s)`,
  asset_context: () => 'Asset context resolved',
  correlation: (event) =>
    `Correlated ${event.findings_count.toLocaleString()} finding(s) into ${event.incidents_count.toLocaleString()} incident(s)`,
  risk_assessment: (event) =>
    `Risk-scored ${event.incidents_count.toLocaleString()} incident(s)`,
  response: (event) =>
    `Response playbook ready for all ${event.incidents_count.toLocaleString()} incident(s)`,
}

export function runningMessage(node, ctx) {
  return RUNNING_MESSAGES[node]?.(ctx) ?? `Running ${node}...`
}

export function completedMessage(node, event) {
  return COMPLETED_MESSAGES[node]?.(event) ?? `${node} complete`
}

export function startMessage(entryCount) {
  return `Parsed ${entryCount.toLocaleString()} log entries — starting analysis...`
}

export function doneMessage(incidents, elapsedSeconds) {
  const byLevel = { Critical: 0, High: 0, Medium: 0, Low: 0 }
  for (const i of incidents) byLevel[i.threat_level] = (byLevel[i.threat_level] || 0) + 1
  const parts = Object.entries(byLevel)
    .filter(([, count]) => count > 0)
    .map(([level, count]) => `${count} ${level}`)
    .join(', ')
  return (
    `Analysis complete in ${elapsedSeconds.toFixed(1)}s — ${incidents.length} incident(s) identified` +
    (parts ? ` (${parts})` : '')
  )
}
