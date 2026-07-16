import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

const LEVEL_COLOR = {
  Critical: '#ff3333',
  High: '#ffb000',
  Medium: '#ffcf5c',
  Low: '#4ade80',
}

function barColor(score) {
  if (score >= 8) return LEVEL_COLOR.Critical
  if (score >= 6) return LEVEL_COLOR.High
  if (score >= 3.5) return LEVEL_COLOR.Medium
  return LEVEL_COLOR.Low
}

export default function RiskChart({ incidents }) {
  if (!incidents.length) return null

  const data = incidents.map((incident) => ({
    name: incident.ip || incident.username || incident.incident_id.slice(0, 8),
    risk_score: incident.risk_score,
  }))

  return (
    <div className="risk-chart">
      <h3>[ SYS.RISK_DISTR ]</h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -18 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#2a2a2a" vertical={false} />
          <XAxis
            dataKey="name"
            tick={{ fill: '#888888', fontSize: 11, fontFamily: 'var(--mono)' }}
            tickLine={false}
            axisLine={{ stroke: '#2a2a2a' }}
          />
          <YAxis
            domain={[0, 10]}
            tick={{ fill: '#888888', fontSize: 11, fontFamily: 'var(--mono)' }}
            tickLine={false}
            axisLine={{ stroke: '#2a2a2a' }}
          />
          <Tooltip
            cursor={{ fill: 'rgba(0, 229, 255, 0.05)' }}
            contentStyle={{
              background: '#000000',
              border: '1px solid #2a2a2a',
              borderRadius: 0,
              color: '#ffffff',
              fontSize: 12,
              fontFamily: 'var(--mono)'
            }}
            labelStyle={{ color: '#888888' }}
          />
          <Bar dataKey="risk_score" radius={[0, 0, 0, 0]}>
            {data.map((entry, i) => (
              <Cell key={i} fill={barColor(entry.risk_score)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
