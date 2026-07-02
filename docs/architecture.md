# SecureOrch Architecture

```
User
  |
  v
React Dashboard  --upload log--> FastAPI Backend
  |                                   |
  | <---- SSE per-agent progress -----+
  v
Orchestrator Agent (LangGraph pipeline)
  |
  v  Log Analysis  ->  Threat Intelligence  ->  Asset Context
  |
  v  Correlation  ->  Risk Assessment  ->  Response Recommendation
  |
  v
scored incidents
  |
  +--> Report Agent (on-demand, via /api/reports): JSON / HTML / PDF

Supporting capability (not a pipeline node):
  Vulnerability Agent -- NVD CVE / CVSS lookup + patch recommendations
```

The orchestrator wires **six** nodes in a linear LangGraph:
`log_analysis → threat_intel → asset_context → correlation → risk_assessment → response`.

The **Report Agent** is invoked on demand when the user requests a report
(`/api/reports/{json,html,pdf}`), so reports reflect the current incident set
rather than being pinned to a pipeline run. The **Vulnerability Agent** is a
standalone enrichment capability (NVD lookups) available to the system but not
part of the linear log-processing flow.

## Graceful degradation

Every external dependency is optional. With no credentials configured:
threat-intel lookups return `None`, LLM explanations are skipped, asset context
falls back to a local seed registry, and Postgres persistence is a no-op. The
full pipeline and all report formats still run — this is the path exercised by
the test suite. See [testing-and-performance.md](testing-and-performance.md).

## Agent Responsibilities

| Agent | Responsibility |
|---|---|
| Orchestrator | Coordinates workflow via LangGraph |
| Log Analysis | Parses logs and detects attacks |
| Threat Intelligence | Checks IP/domain reputation (AbuseIPDB, VirusTotal), maps MITRE ATT&CK |
| Vulnerability | Maps software to CVEs via NVD, CVSS scoring |
| Asset Context | Determines business criticality from the `assets` registry table |
| Correlation | Merges evidence into incidents |
| Risk Assessment | Calculates risk score, threat level, priority |
| Response | Recommends mitigation actions |
| Report | Generates PDF/HTML/JSON incident reports |

## Data Model (Postgres tables)

Each table stores the document as a `jsonb` `data` column keyed by its natural
id, so flat log entries and nested incidents round-trip without a rigid schema.
Tables are created automatically on first write.

- `logs`: id, timestamp, ip, username, event, severity, source
- `findings`: id, attack_type, ip, username, severity, evidence, threat_intel, asset_context
- `assets`: ip, asset_id, hostname, owner, department, criticality, data_sensitivity
- `incidents`: incident_id, risk_score, threat_level, priority, attack_types, mitre_techniques, recommended_actions, findings, status
