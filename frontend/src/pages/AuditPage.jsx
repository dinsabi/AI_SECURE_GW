import { Box, Button, Card, CardContent, Typography } from "@mui/material";
import SocDashboard from "../components/SocDashboard.jsx";

export default function AuditPage({ dashboard, onLoadDashboard }) {
  return (
    <Box>
      <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
        Audit Logs
      </Typography>

      <Typography sx={{ color: "#94a3b8", mb: 3 }}>
        Journal GRC des prompts, fichiers, décisions, risques et réponses IA.
      </Typography>

      <Button variant="contained" onClick={onLoadDashboard} sx={{ mb: 3 }}>
        Load Audit Logs
      </Button>

      <Card sx={{ background: "#111827", color: "#fff" }}>
        <CardContent>
          <SocDashboard dashboard={dashboard} />
        </CardContent>
      </Card>
    </Box>
  );
}