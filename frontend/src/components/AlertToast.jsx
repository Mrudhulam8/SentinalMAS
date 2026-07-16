import { useEffect, useState } from 'react'

export default function AlertToast({ alerts }) {
  const [visible, setVisible] = useState([])

  useEffect(() => {
    const unreadAlerts = alerts.filter(a => !a.acknowledged)
    if (!unreadAlerts.length) return
    const latest = unreadAlerts[0]
    if (!latest || visible.find((v) => v.id === latest.id)) return

    setVisible((prev) => [latest, ...prev].slice(0, 5))

    const timer = setTimeout(() => {
      setVisible((prev) => prev.filter((v) => v.id !== latest.id))
    }, 8000)
    return () => clearTimeout(timer)
  }, [alerts])

  function dismiss(id) {
    setVisible((prev) => prev.filter((v) => v.id !== id))
  }

  if (!visible.length) return null

  return (
    <div className="toast-container">
      {visible.map((alert) => (
        <div
          key={alert.id}
          className={`toast toast-${alert.severity?.toLowerCase()}`}
        >
          <div className="toast-content">
            <span className="toast-icon">
              {alert.severity === 'Critical' ? '🔴' : '🟠'}
            </span>
            <span className="toast-message">{alert.message}</span>
          </div>
          <button className="toast-close" onClick={() => dismiss(alert.id)}>×</button>
        </div>
      ))}
    </div>
  )
}
