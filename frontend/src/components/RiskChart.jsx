import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

export default function RiskChart({ incidents }) {
  if (!incidents.length) return null

  const data = incidents.map((incident) => ({
    name: incident.ip || incident.username || incident.incident_id.slice(0, 8),
    risk_score: incident.risk_score,
  }))

  return (
    <div className="risk-chart">
      <h3>Risk Score by Incident</h3>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" />
          <YAxis domain={[0, 10]} />
          <Tooltip />
          <Bar dataKey="risk_score" fill="#e5484d" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
