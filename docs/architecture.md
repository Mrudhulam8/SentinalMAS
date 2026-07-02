# SecureOrch Architecture

```
User
  |
  v
React Dashboard
  |
  v
FastAPI Backend
  |
  v
Orchestrator Agent (LangGraph)
  |
  +-- Log Analysis Agent
  +-- Threat Intelligence Agent
  +-- Vulnerability Agent
  +-- Asset Context Agent
  |
  v
Correlation Agent
  |
  v
Risk Assessment Agent
  |
  v
Response Recommendation Agent
  |
  v
Report Generation Agent
```

## Agent Responsibilities

| Agent | Responsibility |
|---|---|
| Orchestrator | Coordinates workflow via LangGraph |
| Log Analysis | Parses logs and detects attacks |
| Threat Intelligence | Checks IP/domain reputation (AbuseIPDB, VirusTotal), maps MITRE ATT&CK |
| Vulnerability | Maps software to CVEs via NVD, CVSS scoring |
| Asset Context | Determines business criticality from Firestore asset registry |
| Correlation | Merges evidence into incidents |
| Risk Assessment | Calculates risk score, threat level, priority |
| Response | Recommends mitigation actions |
| Report | Generates PDF/HTML/JSON incident reports |

## Data Model (Firestore collections)

- `logs`: id, timestamp, ip, username, event, severity, source
- `assets`: asset_id, hostname, owner, department, criticality
- `incidents`: incident_id, risk, attack, status, timeline, mitre_mapping, recommendations
