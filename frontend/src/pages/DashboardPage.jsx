import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Grid,
  Typography,
} from "@mui/material";

import {
  Activity,
  AlertTriangle,
  BarChart3,
  Lock,
  RefreshCw,
  ShieldCheck,
} from "lucide-react";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

function getRiskColor(level) {
  switch (level) {
    case "LOW":
      return "success";
    case "MEDIUM":
      return "warning";
    case "HIGH":
      return "error";
    case "CRITICAL":
      return "secondary";
    default:
      return "default";
  }
}

function normalizeDashboard(dashboard) {
  const summary = dashboard?.summary || {};

  const recentEvents =
    dashboard?.recentEvents ||
    dashboard?.recent_events ||
    dashboard?.events ||
    [];

  const riskData = [
    { name: "LOW", value: summary.low_events || 0 },
    { name: "MEDIUM", value: summary.medium_events || 0 },
    { name: "HIGH", value: summary.high_events || 0 },
    { name: "CRITICAL", value: summary.critical_events || 0 },
  ];

  const eventTypeData = dashboard?.eventTypes || dashboard?.event_types || [];

  return {
    summary,
    recentEvents,
    riskData,
    eventTypeData,
  };
}

export default function DashboardPage({ dashboard, onLoadDashboard }) {
  const { summary, recentEvents, riskData, eventTypeData } =
    normalizeDashboard(dashboard);

  const cards = [
    {
      title: "AI Events",
      value: summary.total_events || 0,
      icon: <Activity size={28} />,
      subtitle: "Total analyzed AI activities",
    },
    {
      title: "Blocked Events",
      value: summary.blocked_events || 0,
      icon: <Lock size={28} />,
      subtitle: "Blocked by policy",
    },
    {
      title: "High / Critical",
      value: (summary.high_events || 0) + (summary.critical_events || 0),
      icon: <AlertTriangle size={28} />,
      subtitle: "Requires security review",
    },
    {
      title: "Avg Risk Score",
      value: summary.average_risk_score || 0,
      icon: <BarChart3 size={28} />,
      subtitle: "Average AI risk exposure",
    },
  ];

  return (
    <Box>
      <Box
        sx={{
          mb: 3,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "flex-start",
          gap: 2,
        }}
      >
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            SOC / GRC Dashboard
          </Typography>

          <Typography sx={{ color: "#94a3b8" }}>
            Executive view of AI usage, sensitive data exposure, policy
            decisions and compliance evidence.
          </Typography>
        </Box>

        <Button
          variant="contained"
          startIcon={<RefreshCw size={18} />}
          onClick={onLoadDashboard}
        >
          Refresh
        </Button>
      </Box>

      <Grid container spacing={2}>
        {cards.map((card) => (
          <Grid item xs={12} md={3} key={card.title}>
            <Card sx={{ background: "#111827", color: "#fff", height: "100%" }}>
              <CardContent>
                <Box
                  sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    gap: 2,
                  }}
                >
                  <Box>
                    <Typography sx={{ color: "#94a3b8", fontSize: 14 }}>
                      {card.title}
                    </Typography>

                    <Typography variant="h4" sx={{ fontWeight: 800, mt: 1 }}>
                      {card.value}
                    </Typography>

                    <Typography sx={{ color: "#64748b", fontSize: 13, mt: 1 }}>
                      {card.subtitle}
                    </Typography>
                  </Box>

                  <Box sx={{ color: "#38bdf8" }}>{card.icon}</Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Grid container spacing={2} sx={{ mt: 1 }}>
        <Grid item xs={12} md={6}>
          <Card sx={{ background: "#111827", color: "#fff", height: 380 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Risk Distribution
              </Typography>

              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie
                    data={riskData}
                    dataKey="value"
                    nameKey="name"
                    outerRadius={95}
                    label
                  >
                    {riskData.map((entry) => (
                      <Cell key={entry.name} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card sx={{ background: "#111827", color: "#fff", height: 380 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Event Types
              </Typography>

              {eventTypeData.length === 0 ? (
                <Box
                  sx={{
                    height: 280,
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    color: "#64748b",
                  }}
                >
                  No event type data available yet.
                </Box>
              ) : (
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={eventTypeData}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                    <XAxis dataKey="event_type" stroke="#94a3b8" />
                    <YAxis stroke="#94a3b8" />
                    <Tooltip />
                    <Bar dataKey="count">
                      {eventTypeData.map((entry, index) => (
                        <Cell key={`cell-${index}`} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Card sx={{ mt: 3, background: "#111827", color: "#fff" }}>
        <CardContent>
          <Box sx={{ display: "flex", alignItems: "center", gap: 1.5, mb: 2 }}>
            <ShieldCheck size={22} color="#38bdf8" />
            <Typography variant="h6">Recent Security Timeline</Typography>
          </Box>

          {!recentEvents.length ? (
            <Typography sx={{ color: "#94a3b8" }}>
              No audit events loaded yet. Click Refresh after running prompt or
              file analysis.
            </Typography>
          ) : (
            recentEvents.slice(0, 10).map((event, index) => (
              <Box
                key={event.id || index}
                sx={{
                  py: 1.5,
                  borderBottom:
                    index === recentEvents.length - 1
                      ? "none"
                      : "1px solid #1f2937",
                  display: "grid",
                  gridTemplateColumns: "1.5fr 1fr 1fr 1fr",
                  gap: 2,
                  alignItems: "center",
                }}
              >
                <Box>
                  <Typography sx={{ fontWeight: 700 }}>
                    {event.event_type || event.eventType || "AI_SECURITY_EVENT"}
                  </Typography>

                  <Typography sx={{ color: "#64748b", fontSize: 13 }}>
                    {event.created_at || event.createdAt || "No timestamp"}
                  </Typography>
                </Box>

                <Typography sx={{ color: "#94a3b8" }}>
                  {event.provider || "gateway"}
                </Typography>

                <Chip
                  size="small"
                  label={event.risk_level || event.riskLevel || "UNKNOWN"}
                  color={getRiskColor(event.risk_level || event.riskLevel)}
                />

                <Typography sx={{ textAlign: "right", color: "#cbd5e1" }}>
                  Score: {event.risk_score || event.riskScore || 0}
                </Typography>
              </Box>
            ))
          )}
        </CardContent>
      </Card>
    </Box>
  );
}