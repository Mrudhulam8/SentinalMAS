# Log Analysis Agent Prompt

Given a batch of parsed log entries (timestamp, username, ip, event, severity, source),
identify security-relevant patterns:

- Failed logins (repeated auth failures from same IP/user)
- Port scans (many distinct ports/services probed from same IP in short window)
- Brute force attacks (high-frequency failed logins against one account)
- SQL Injection attempts (suspicious query patterns in request logs)
- XSS attempts (script/tag injection patterns in request logs)
- Suspicious traffic (anomalous request volume, unusual user agents, off-hours activity)
- Privilege escalation (sudo/admin role changes, unexpected permission grants)

For each finding, output: entry IDs involved, attack_type, confidence, evidence, severity.
