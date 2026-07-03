import { useEffect, useRef } from 'react'

export default function ActivityLog({ lines, running }) {
  const scrollRef = useRef(null)

  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  if (!lines.length) return null

  return (
    <section className="activity-log">
      <h3>
        Live Activity {running && <span className="live-dot" />}
      </h3>
      <div className="activity-log-scroll" ref={scrollRef}>
        {lines.map((line) => (
          <p key={line.id} className={`activity-line activity-line-${line.kind}`}>
            <span className="activity-line-prefix">
              {line.kind === 'success' ? '✓' : line.kind === 'start' ? '▸' : '…'}
            </span>
            {line.text}
          </p>
        ))}
        {running && <span className="activity-cursor" />}
      </div>
    </section>
  )
}
