import { useEffect, useState } from 'react'
import { fetchAlerts, acknowledgeAlert, acknowledgeAllAlerts } from '../api/client'

export default function AlertPanel({ open, onClose, refreshTrigger, onAlertsUpdated }) {
  const [alerts, setAlerts] = useState([])
  const [unreadCount, setUnreadCount] = useState(0)

  async function loadAlerts() {
    try {
      const data = await fetchAlerts()
      setAlerts(data.alerts || [])
      setUnreadCount(data.unread_count || 0)
      if (onAlertsUpdated) onAlertsUpdated(data.alerts || [])
    } catch {
      /* silent */
    }
  }

  useEffect(() => {
    loadAlerts()
  }, [refreshTrigger])

  async function handleAcknowledge(id) {
    await acknowledgeAlert(id)
    loadAlerts()
  }

  async function handleAcknowledgeAll() {
    await acknowledgeAllAlerts()
    loadAlerts()
  }

  if (!open) return null

  return (
    <div className="alert-overlay" onClick={onClose}>
      <div className="alert-panel" onClick={(e) => e.stopPropagation()}>
        <div className="alert-panel-header">
          <h2>
            [ SYS.ALERTS ]
            {unreadCount > 0 && (
              <span className="alert-unread-badge">{unreadCount}</span>
            )}
          </h2>
          <div className="alert-panel-actions">
            {unreadCount > 0 && (
              <button className="alert-ack-all-btn" onClick={handleAcknowledgeAll}>
                [ ACK_ALL ]
              </button>
            )}
            <button className="detail-close" onClick={onClose}>×</button>
          </div>
        </div>

        <div className="alert-list">
          {alerts.length === 0 && (
            <p className="empty-state" style={{ border: 'none', background: 'none', padding: '1rem' }}>
              No alerts yet.
            </p>
          )}
          {alerts.map((alert) => (
            <div
              key={alert.id}
              className={`alert-item ${alert.acknowledged ? 'alert-read' : 'alert-unread'}`}
            >
              <div className="alert-item-header">
                <span className="alert-severity-dot" data-severity={alert.severity?.toLowerCase()} />
                <span className={`badge level-${alert.severity?.toLowerCase()}`}>
                  {alert.severity}
                </span>
                <span className="alert-time">
                  {new Date(alert.timestamp).toLocaleTimeString()}
                </span>
              </div>
              <p className="alert-message">{alert.message}</p>
              {!alert.acknowledged && (
                <button
                  className="alert-ack-btn"
                  onClick={() => handleAcknowledge(alert.id)}
                >
                  [ ACKNOWLEDGE ]
                </button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
