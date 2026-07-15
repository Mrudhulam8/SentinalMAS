const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

export async function uploadLog(file) {
  const formData = new FormData()
  formData.append('file', file)
  const res = await fetch(`${API_BASE}/api/logs/upload`, { method: 'POST', body: formData })
  if (!res.ok) throw new Error(`Upload failed: ${res.status}`)
  return res.json()
}

export async function streamPipeline(entries, onEvent) {
  const res = await fetch(`${API_BASE}/api/pipeline/stream`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ entries }),
  })
  if (!res.ok || !res.body) throw new Error(`Pipeline stream failed: ${res.status}`)

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })

    let boundary
    while ((boundary = buffer.indexOf('\n\n')) !== -1) {
      const chunk = buffer.slice(0, boundary)
      buffer = buffer.slice(boundary + 2)
      const line = chunk.split('\n').find((l) => l.startsWith('data: '))
      if (line) {
        const event = JSON.parse(line.slice(6))
        onEvent(event)
      }
    }
  }
}

export async function downloadReport(incidents, format) {
  const res = await fetch(`${API_BASE}/api/reports/${format}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ incidents }),
  })
  if (!res.ok) throw new Error(`Report generation failed: ${res.status}`)

  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
<<<<<<< HEAD
  a.download = `sentinelmas_report.${format === 'json' ? 'json' : format === 'html' ? 'html' : 'pdf'}`
  a.click()
  URL.revokeObjectURL(url)
}

/** SSE helper reused by both streamPipeline and simulateAttack */
async function _streamSSE(url, body, onEvent) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok || !res.body) throw new Error(`Stream failed: ${res.status}`)

  const reader = res.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''

  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })

    let boundary
    while ((boundary = buffer.indexOf('\n\n')) !== -1) {
      const chunk = buffer.slice(0, boundary)
      buffer = buffer.slice(boundary + 2)
      const line = chunk.split('\n').find((l) => l.startsWith('data: '))
      if (line) {
        const event = JSON.parse(line.slice(6))
        onEvent(event)
      }
    }
  }
}

export async function simulateAttack(scenario, count, onEvent) {
  return _streamSSE(`${API_BASE}/api/simulate/stream`, { scenario, count }, onEvent)
}

// --- Blocklist API ---

export async function fetchBlocklist() {
  const res = await fetch(`${API_BASE}/api/blocklist`)
  if (!res.ok) throw new Error(`Blocklist fetch failed: ${res.status}`)
  return res.json()
}

export async function unblockIP(ip) {
  const res = await fetch(`${API_BASE}/api/blocklist/${encodeURIComponent(ip)}`, { method: 'DELETE' })
  if (!res.ok) throw new Error(`Unblock failed: ${res.status}`)
  return res.json()
}

// --- Alerts API ---

export async function fetchAlerts() {
  const res = await fetch(`${API_BASE}/api/alerts`)
  if (!res.ok) throw new Error(`Alerts fetch failed: ${res.status}`)
  return res.json()
}

export async function acknowledgeAlert(alertId) {
  const res = await fetch(`${API_BASE}/api/alerts/${alertId}/acknowledge`, { method: 'POST' })
  if (!res.ok) throw new Error(`Acknowledge failed: ${res.status}`)
  return res.json()
}

export async function acknowledgeAllAlerts() {
  const res = await fetch(`${API_BASE}/api/alerts/acknowledge-all`, { method: 'POST' })
  if (!res.ok) throw new Error(`Acknowledge all failed: ${res.status}`)
  return res.json()
}
=======
  a.download = `secureorch_report.${format === 'json' ? 'json' : format === 'html' ? 'html' : 'pdf'}`
  a.click()
  URL.revokeObjectURL(url)
}
>>>>>>> 4e42fe27b608da871312434e17e16aaee9671e70
