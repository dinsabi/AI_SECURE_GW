export default function SocDashboard({ dashboard }) {
  if (!dashboard) {
    return null;
  }

  const summary = dashboard.summary || {};
  const recentEvents = dashboard.recentEvents || [];
  const topFindingTypes = dashboard.topFindingTypes || [];

  return (
    <div style={{ marginTop: 30 }}>
      <h2>4. SOC / GRC Dashboard</h2>

      <p>
        Vue synthétique des événements IA : prompts analysés, fichiers analysés,
        risques critiques, décisions de sécurité et types de données détectées.
      </p>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(5, 1fr)",
          gap: 12,
          marginTop: 20,
        }}
      >
        <DashboardCard title="Total Events" value={summary.total_events || 0} />
        <DashboardCard
          title="Average Risk"
          value={summary.average_risk_score || 0}
        />
        <DashboardCard
          title="Critical"
          value={summary.critical_events || 0}
        />
        <DashboardCard title="High" value={summary.high_events || 0} />
        <DashboardCard
          title="Blocked"
          value={summary.blocked_events || 0}
        />
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 2fr",
          gap: 20,
          marginTop: 30,
        }}
      >
        <div>
          <h3>Top Detected Data Types</h3>

          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={thStyle}>Type</th>
                <th style={thStyle}>Count</th>
              </tr>
            </thead>
            <tbody>
              {topFindingTypes.length === 0 && (
                <tr>
                  <td style={tdStyle} colSpan="2">
                    No findings yet
                  </td>
                </tr>
              )}

              {topFindingTypes.map((item, index) => (
                <tr key={index}>
                  <td style={tdStyle}>{item.finding_type}</td>
                  <td style={tdStyle}>{item.count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div>
          <h3>Recent Audit Events</h3>

          <table style={tableStyle}>
            <thead>
              <tr>
                <th style={thStyle}>Date</th>
                <th style={thStyle}>Type</th>
                <th style={thStyle}>User</th>
                <th style={thStyle}>Risk</th>
                <th style={thStyle}>Decision</th>
                <th style={thStyle}>Findings</th>
              </tr>
            </thead>
            <tbody>
              {recentEvents.length === 0 && (
                <tr>
                  <td style={tdStyle} colSpan="6">
                    No audit events yet
                  </td>
                </tr>
              )}

              {recentEvents.map((event) => (
                <tr key={event.id}>
                  <td style={tdStyle}>
                    {event.created_at
                      ? new Date(event.created_at).toLocaleString()
                      : "-"}
                  </td>
                  <td style={tdStyle}>{event.event_type}</td>
                  <td style={tdStyle}>{event.user_email}</td>
                  <td style={tdStyle}>
                    {event.risk_level} / {event.risk_score}
                  </td>
                  <td style={tdStyle}>{event.decision}</td>
                  <td style={tdStyle}>
                    {Array.isArray(event.finding_types)
                      ? event.finding_types.join(", ")
                      : String(event.finding_types || "")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function DashboardCard({ title, value }) {
  return (
    <div
      style={{
        border: "1px solid #ddd",
        borderRadius: 8,
        padding: 16,
        background: "#f7f7f7",
      }}
    >
      <div style={{ fontSize: 14, color: "#666" }}>{title}</div>
      <div style={{ fontSize: 28, fontWeight: "bold", marginTop: 8 }}>
        {value}
      </div>
    </div>
  );
}

const tableStyle = {
  width: "100%",
  borderCollapse: "collapse",
  background: "#fff",
};

const thStyle = {
  border: "1px solid #ddd",
  padding: 8,
  background: "#f1f1f1",
  textAlign: "left",
};

const tdStyle = {
  border: "1px solid #ddd",
  padding: 8,
  fontSize: 13,
};