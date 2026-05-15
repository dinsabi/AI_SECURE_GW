import { useEffect } from "react";

import {
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  Grid,
  Typography,
  Divider,
} from "@mui/material";

import {
  Activity,
  AlertTriangle,
  BarChart3,
  Lock,
  RadioTower,
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

function getSeverityBg(level) {
  switch (level) {
    case "LOW":
      return "rgba(34,197,94,0.12)";

    case "MEDIUM":
      return "rgba(245,158,11,0.12)";

    case "HIGH":
      return "rgba(239,68,68,0.15)";

    case "CRITICAL":
      return "rgba(168,85,247,0.15)";

    default:
      return "rgba(148,163,184,0.08)";
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

  const eventTypeData = dashboard?.eventTypes || [];

  return {
    summary,
    recentEvents,
    riskData,
    eventTypeData,
  };
}

export default function DashboardPage({
  dashboard,
  loading,
  onLoadDashboard,
}) {
  const { summary, recentEvents, riskData, eventTypeData } =
    normalizeDashboard(dashboard);

  useEffect(() => {
    onLoadDashboard();

    const interval = setInterval(() => {
      onLoadDashboard();
    }, 5000);

    return () => clearInterval(interval);
  }, []);

  const cards = [
    {
      title: "AI Events",
      value: summary.total_events || 0,
      icon: <Activity size={28} />,
      subtitle: "Total AI security activities",
    },
    {
      title: "Blocked Events",
      value: summary.blocked_events || 0,
      icon: <Lock size={28} />,
      subtitle: "Blocked by AI policies",
    },
    {
      title: "High Risks",
      value: (summary.high_events || 0) + (summary.critical_events || 0),
      icon: <AlertTriangle size={28} />,
      subtitle: "Requires immediate review",
    },
    {
      title: "Risk Score",
      value: summary.average_risk_score || 0,
      icon: <BarChart3 size={28} />,
      subtitle: "Global AI exposure",
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
          flexWrap: "wrap",
          gap: 2,
        }}
      >
        <Box>
          <Typography variant="h4" sx={{ fontWeight: 800, mb: 1 }}>
            AI Security Operations Center
          </Typography>

          <Typography sx={{ color: "#94a3b8" }}>
            Real-time monitoring of AI risks, prompt activities and compliance
            events.
          </Typography>
        </Box>

        <Box sx={{ display: "flex", gap: 1.5, alignItems: "center" }}>
          <Chip
            icon={<RadioTower size={15} />}
            label="LIVE"
            color="success"
          />

          <Chip
            label="Auto refresh 5s"
            sx={{
              background: "rgba(14,165,233,0.15)",
              color: "#bae6fd",
            }}
          />

          <Button
            variant="contained"
            startIcon={<RefreshCw size={16} />}
            onClick={onLoadDashboard}
            disabled={loading}
          >
            Refresh
          </Button>
        </Box>
      </Box>

      <Grid container spacing={2}>
        {cards.map((card) => (
          <Grid item xs={12} md={3} key={card.title}>
            <Card
              sx={{
                background: "#111827",
                color: "#fff",
                height: "100%",
              }}
            >
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

                    <Typography
                      variant="h4"
                      sx={{
                        fontWeight: 800,
                        mt: 1,
                      }}
                    >
                      {card.value}
                    </Typography>

                    <Typography
                      sx={{
                        color: "#64748b",
                        fontSize: 13,
                        mt: 1,
                      }}
                    >
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
          <Card
            sx={{
              background: "#111827",
              color: "#fff",
              height: 380,
            }}
          >
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
          <Card
            sx={{
              background: "#111827",
              color: "#fff",
              height: 380,
            }}
          >
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Event Categories
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
                  No event statistics available yet.
                </Box>
              ) : (
                <ResponsiveContainer width="100%" height={280}>
                  <BarChart data={eventTypeData}>
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="#1f2937"
                    />

                    <XAxis
                      dataKey="event_type"
                      stroke="#94a3b8"
                    />

                    <YAxis stroke="#94a3b8" />

                    <Tooltip />

                    <Bar dataKey="count">
                      {eventTypeData.map((entry, index) => (
                        <Cell key={index} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Card
        sx={{
          mt: 3,
          background: "#111827",
          color: "#fff",
        }}
      >
        <CardContent>
          <Box
            sx={{
              display: "flex",
              alignItems: "center",
              gap: 1.5,
              mb: 2,
            }}
          >
            <ShieldCheck size={22} color="#38bdf8" />

            <Typography variant="h6">
              Live Security Timeline
            </Typography>

            <Chip
              size="small"
              label={`${recentEvents.length} events`}
              sx={{
                background: "rgba(14,165,233,0.15)",
                color: "#bae6fd",
              }}
            />
          </Box>

          <Divider
            sx={{
              borderColor: "#1f2937",
              mb: 2,
            }}
          />

          {!recentEvents.length ? (
            <Typography sx={{ color: "#94a3b8" }}>
              No security events detected yet.
            </Typography>
          ) : (
            recentEvents.slice(0, 12).map((event, index) => {
              const risk =
                event.risk_level ||
                event.riskLevel ||
                "LOW";

              return (
                <Box
                  key={event.id || index}
                  sx={{
                    mb: 2,
                    p: 2,
                    borderRadius: 3,
                    background: getSeverityBg(risk),
                    border: "1px solid rgba(255,255,255,0.05)",
                    transition: "all 0.3s ease",
                    "&:hover": {
                      transform: "translateY(-2px)",
                    },
                  }}
                >
                  <Grid
                    container
                    spacing={2}
                    alignItems="center"
                  >
                    <Grid item xs={12} md={4}>
                      <Typography
                        sx={{
                          fontWeight: 700,
                          color: "#fff",
                        }}
                      >
                        {event.event_type ||
                          event.eventType ||
                          "AI_SECURITY_EVENT"}
                      </Typography>

                      <Typography
                        sx={{
                          color: "#94a3b8",
                          fontSize: 13,
                          mt: 0.5,
                        }}
                      >
                        {event.created_at ||
                          event.createdAt ||
                          "No timestamp"}
                      </Typography>
                    </Grid>

                    <Grid item xs={12} md={3}>
                      <Typography
                        sx={{
                          color: "#cbd5e1",
                        }}
                      >
                        Provider:
                      </Typography>

                      <Typography
                        sx={{
                          color: "#38bdf8",
                          fontWeight: 700,
                        }}
                      >
                        {event.provider || "gateway"}
                      </Typography>
                    </Grid>

                    <Grid item xs={12} md={2}>
                      <Chip
                        label={risk}
                        color={getRiskColor(risk)}
                      />
                    </Grid>

                    <Grid item xs={12} md={3}>
                      <Typography
                        sx={{
                          textAlign: "right",
                          color: "#e2e8f0",
                          fontWeight: 700,
                        }}
                      >
                        Risk Score:
                        {" "}
                        {event.risk_score ||
                          event.riskScore ||
                          0}
                      </Typography>
                    </Grid>
                  </Grid>
                </Box>
              );
            })
          )}
        </CardContent>
      </Card>
    </Box>
  );
}