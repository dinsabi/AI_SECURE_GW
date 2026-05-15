import { Box, Card, CardContent, Typography, Button, Grid } from "@mui/material";
import { ShieldAlert, Lock, Activity, Database } from "lucide-react";

export default function DashboardPage({ dashboard, onLoadDashboard }) {
  const summary = dashboard?.summary || {};

  const cards = [
    {
      title: "AI Events",
      value: summary.total_events || 0,
      icon: <Activity size={28} />,
    },
    {
      title: "Critical Risks",
      value: summary.critical_events || 0,
      icon: <ShieldAlert size={28} />,
    },
    {
      title: "Blocked Events",
      value: summary.blocked_events || 0,
      icon: <Lock size={28} />,
    },
    {
      title: "Avg Risk Score",
      value: summary.average_risk_score || 0,
      icon: <Database size={28} />,
    },
  ];

  return (
    <Box>
      <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
        SOC / GRC Dashboard
      </Typography>

      <Typography sx={{ color: "#94a3b8", mb: 3 }}>
        Vue exécutive des usages IA, risques, décisions de sécurité et contrôles
        NIS2 / GDPR / ISO27001.
      </Typography>

      <Button variant="contained" onClick={onLoadDashboard} sx={{ mb: 3 }}>
        Refresh Dashboard
      </Button>

      <Grid container spacing={2}>
        {cards.map((card) => (
          <Grid item xs={12} md={3} key={card.title}>
            <Card sx={{ background: "#111827", color: "#fff" }}>
              <CardContent>
                <Box sx={{ display: "flex", justifyContent: "space-between" }}>
                  <Box>
                    <Typography sx={{ color: "#94a3b8" }}>
                      {card.title}
                    </Typography>
                    <Typography variant="h4" sx={{ fontWeight: 700 }}>
                      {card.value}
                    </Typography>
                  </Box>
                  <Box sx={{ color: "#38bdf8" }}>{card.icon}</Box>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>

      <Card sx={{ mt: 3, background: "#111827", color: "#fff" }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 2 }}>
            Recent Audit Events
          </Typography>

          {!dashboard?.recentEvents?.length ? (
            <Typography sx={{ color: "#94a3b8" }}>
              Aucun événement chargé pour le moment.
            </Typography>
          ) : (
            dashboard.recentEvents.slice(0, 8).map((event) => (
              <Box
                key={event.id}
                sx={{
                  py: 1.5,
                  borderBottom: "1px solid #1f2937",
                  display: "flex",
                  justifyContent: "space-between",
                }}
              >
                <Typography>{event.event_type}</Typography>
                <Typography sx={{ color: "#94a3b8" }}>
                  {event.risk_level} / {event.risk_score}
                </Typography>
              </Box>
            ))
          )}
        </CardContent>
      </Card>
    </Box>
  );
}