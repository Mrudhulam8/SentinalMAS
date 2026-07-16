import { useEffect, useState } from 'react'
import { fetchBlocklist, unblockIP } from '../api/client'

export default function BlockedIPs({ refreshTrigger, onBlockedCountChange }) {
  const [blocked, setBlocked] = useState([])
  const [loading, setLoading] = useState(false)

  async function loadBlocklist() {
    setLoading(true)
    try {
      const newBlocked = data.blocked || []
      setBlocked(newBlocked)
      if (onBlockedCountChange) onBlockedCountChange(newBlocked.length)
    } catch {
      /* silent */
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadBlocklist()
  }, [refreshTrigger])

  async function handleUnblock(ip) {
    await unblockIP(ip)
    loadBlocklist()
  }

  if (!blocked.length && !loading) return null

  return (
    <div className="blocked-panel">
      <h3>
        <span className="blocked-icon">🛑</span>
        [ SYS.BLOCKED_IPS ]
        <span className="blocked-count-badge">{blocked.length}</span>
      </h3>
      <div className="blocked-list">
        {blocked.map((entry) => (
          <div key={entry.ip} className="blocked-entry">
            <div className="blocked-info">
              <span className="blocked-ip">{entry.ip}</span>
              <span className={`badge level-${entry.threat_level?.toLowerCase()}`}>
                {entry.threat_level}
              </span>
            </div>
            <div className="blocked-reason">{entry.reason}</div>
            <div className="blocked-actions">
              <span className="blocked-time">
                {new Date(entry.blocked_at).toLocaleTimeString()}
              </span>
              <button className="unblock-btn" onClick={() => handleUnblock(entry.ip)}>
                [ UNBLOCK ]
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
