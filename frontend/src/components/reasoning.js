/**
 * Per-stage "why" explanations for the incident detail panel.
 *
 * These mirror the exact backend formulas (not paraphrases) so the reasoning
 * shown is correct for any incident, not just an example:
 *   agents/log_analysis.py, agents/threat_intel.py, agents/asset_context.py,
 *   agents/correlation.py, agents/risk_assessment.py, agents/response.py
 */

const ATTACK_TYPE_EXPLANATIONS = {
  brute_force: 'flagged once a single user/IP pair hit 3+ failed logins',
  failed_login: 'failed login(s) that stayed below the brute-force threshold',
  sql_injection: 'a SQL syntax pattern (e.g. OR 1=1, UNION SELECT) matched in the request',
  xss: 'a script/event-handler pattern (e.g. <script>, onerror=) matched in the request',
  port_scan: 'the same IP probed 4+ distinct endpoints',
  suspicious_traffic: 'the same IP triggered 3+ server error (4xx/5xx) responses',
  privilege_escalation: 'a privileged command pattern (sudo, usermod, chmod +s) matched the event',
<<<<<<< HEAD
  impossible_travel: 'the same user authenticated from geographically distant locations within 30 minutes',
=======
>>>>>>> 4e42fe27b608da871312434e17e16aaee9671e70
}

const SEVERITY_WEIGHT = { low: 1, medium: 2, high: 3 }

const ATTACK_ACTIONS = {
  brute_force: ['Block IP', 'Enable MFA', 'Notify administrator'],
  failed_login: ['Monitor account', 'Enable MFA'],
  sql_injection: ['Patch vulnerable systems', 'Block IP', 'Notify administrator'],
  xss: ['Patch vulnerable systems', 'Notify administrator'],
  port_scan: ['Block IP', 'Notify administrator'],
  suspicious_traffic: ['Block IP', 'Notify administrator'],
  privilege_escalation: ['Disable account', 'Notify administrator', 'Patch vulnerable systems'],
<<<<<<< HEAD
  impossible_travel: ['Disable account', 'Enable MFA', 'Notify administrator'],
=======
>>>>>>> 4e42fe27b608da871312434e17e16aaee9671e70
}

const THREAT_LEVEL_EXTRA_ACTIONS = {
  Critical: ['Notify administrator', 'Isolate affected asset'],
  High: ['Notify administrator'],
}

function readable(type) {
  return type.replace(/_/g, ' ')
}

function explainLogAnalysis(incident) {
  const byType = {}
  for (const f of incident.findings) byType[f.attack_type] = (byType[f.attack_type] || 0) + 1

  return {
    paragraphs: [
      `Rule-based detection (deterministic, no AI) scanned the uploaded log entries and matched ` +
        `${incident.finding_count} finding(s) against known attack patterns:`,
      ...Object.entries(byType).map(
        ([type, count]) =>
          `• ${count} × ${readable(type)} — ${ATTACK_TYPE_EXPLANATIONS[type] || 'matched a detection rule'}`
      ),
    ],
  }
}

function explainThreatIntel(incident) {
  const mitreList = Object.values(
    Object.fromEntries(incident.mitre_techniques.map((m) => [m.technique_id, m]))
  )
  const mitreLine = mitreList.length
    ? `Each attack type maps to a MITRE ATT&CK technique via a static lookup table: ` +
      `${mitreList.map((m) => `${m.technique_id} (${m.technique})`).join(', ')}.`
    : 'No MITRE technique mapping applies to these attack types.'

  const threatIntels = incident.findings.map((f) => f.threat_intel).filter(Boolean)
  const abuseScores = threatIntels
    .map((t) => t.abuseipdb?.abuse_confidence_score)
    .filter((v) => v != null)
  const vtScores = threatIntels.map((t) => t.virustotal?.malicious).filter((v) => v != null)

  let repLine
  if (abuseScores.length || vtScores.length) {
    const maxAbuse = abuseScores.length ? Math.max(...abuseScores) : null
    const maxVt = vtScores.length ? Math.max(...vtScores) : null
    const bits = []
    if (maxAbuse != null) bits.push(`AbuseIPDB confidence up to ${maxAbuse}/100`)
    if (maxVt != null) bits.push(`VirusTotal: up to ${maxVt} vendor(s) flagged it malicious`)
    const neutral = (maxAbuse || 0) === 0 && (maxVt || 0) === 0
    repLine =
      `Live IP reputation was checked (${bits.join(', ')}).` +
      (neutral
        ? ' Neither service had this IP on record, so it contributed 0 to the risk score.'
        : ' This score feeds directly into the risk calculation below.')
  } else {
    repLine =
      'No live reputation data was available for this incident (key not configured, or lookup ' +
      'skipped/failed), so it contributed 0 to the risk score.'
  }

  return { paragraphs: [mitreLine, repLine] }
}

function explainAssetContext(incident) {
  if (incident.asset_context) {
    const a = incident.asset_context
    return {
      paragraphs: [
        `This IP/user matched a registered asset: ${a.asset_id || a.hostname || 'unnamed asset'} ` +
          `(criticality ${a.criticality ?? '—'}/5${a.department ? `, ${a.department}` : ''}). ` +
          `That criticality feeds directly into the risk score below.`,
      ],
    }
  }
  return {
    paragraphs: [
      'No match was found in the asset registry (database table or local seed) for this IP/user. ' +
        'The risk formula falls back to a default criticality of 1 (lowest), so this incident is ' +
        'not being boosted by asset importance.',
    ],
  }
}

function explainCorrelation(incident) {
  const key = incident.ip
    ? `IP ${incident.ip}`
    : incident.username
      ? `username ${incident.username}`
      : 'a shared identifier'
  return {
    paragraphs: [
      `Findings are grouped by source IP first, username second. All ${incident.finding_count} ` +
        `finding(s) here share ${key}, so they were merged into this single incident instead of ` +
        `appearing as ${incident.finding_count} separate ones.`,
    ],
  }
}

function explainRiskAssessment(incident) {
  const severityWeight = SEVERITY_WEIGHT[incident.max_severity] ?? 1
  const severityComponent = severityWeight * 2.0

  const diversityCount = Math.min(incident.attack_types.length, 4)
  const diversityComponent = diversityCount * 1.0

  const rawCriticality = incident.asset_context?.criticality
  const criticality = rawCriticality || 1
  const criticalityComponent = criticality * 0.6

  let reputationComponent = 0
  for (const f of incident.findings) {
    const ti = f.threat_intel || {}
    const abuse = ti.abuseipdb || {}
    const vt = ti.virustotal || {}
    if (abuse.abuse_confidence_score != null) {
      reputationComponent = Math.max(reputationComponent, (abuse.abuse_confidence_score / 100) * 3)
    }
    if (vt.malicious != null) {
      reputationComponent = Math.max(reputationComponent, (Math.min(vt.malicious, 10) / 10) * 3)
    }
  }

  const rawTotal = severityComponent + diversityComponent + criticalityComponent + reputationComponent
  const total = Math.min(rawTotal, 10)

  const band =
    incident.risk_score >= 8
      ? '≥ 8.0 → Critical / P1'
      : incident.risk_score >= 6
        ? '6.0 – 7.99 → High / P2'
        : incident.risk_score >= 3.5
          ? '3.5 – 5.99 → Medium / P3'
          : '< 3.5 → Low / P4'

  return {
    paragraphs: [
      `Risk score = severity + attack diversity + asset criticality + IP reputation, capped at 10:`,
    ],
    breakdown: {
      rows: [
        { label: 'Severity', detail: `${incident.max_severity} (weight ${severityWeight}) × 2.0`, value: severityComponent },
        { label: 'Attack diversity', detail: `${diversityCount} type(s) × 1.0`, value: diversityComponent },
        {
          label: 'Asset criticality',
          detail: incident.asset_context ? `${criticality} × 0.6` : 'default 1 × 0.6 (no asset match)',
          value: criticalityComponent,
        },
        {
          label: 'IP reputation',
          detail: reputationComponent > 0 ? 'live reputation score' : 'no signal',
          value: reputationComponent,
        },
      ],
      total,
      band,
    },
  }
}

function explainResponse(incident) {
  const perType = incident.attack_types
    .filter((t) => ATTACK_ACTIONS[t])
    .map((t) => `${readable(t)} → ${ATTACK_ACTIONS[t].join(', ')}`)
  const extra = THREAT_LEVEL_EXTRA_ACTIONS[incident.threat_level]

  const paragraphs = [
    `Each attack type contributes a fixed action set: ${perType.join('; ') || 'none matched'}.`,
  ]
  if (extra) {
    paragraphs.push(`Because this incident is ${incident.threat_level}, "${extra.join('", "')}" is also added.`)
  }
  paragraphs.push(
    `Duplicate actions are merged and ordered by urgency, giving ${incident.recommended_actions.length} ` +
      `action(s) total.`
  )
  return { paragraphs }
}

const EXPLAINERS = {
  log_analysis: explainLogAnalysis,
  threat_intel: explainThreatIntel,
  asset_context: explainAssetContext,
  correlation: explainCorrelation,
  risk_assessment: explainRiskAssessment,
  response: explainResponse,
}

export function explainStage(key, incident) {
  const fn = EXPLAINERS[key]
  return fn ? fn(incident) : { paragraphs: [] }
}
