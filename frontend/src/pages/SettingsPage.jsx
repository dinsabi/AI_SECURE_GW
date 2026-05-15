import { Box, Card, CardContent, Typography } from "@mui/material";

export default function SettingsPage() {
  return (
    <Box>
      <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
        Settings
      </Typography>

      <Typography sx={{ color: "#94a3b8", mb: 3 }}>
        Configuration plateforme : IA, tenants, sécurité, SIEM et conformité.
      </Typography>

      <Card sx={{ background: "#111827", color: "#fff" }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 2 }}>
            Platform Configuration
          </Typography>

          <Typography sx={{ color: "#94a3b8" }}>
            Prochaine évolution : OpenAI, Claude, Gemini, Azure OpenAI,
            secrets, quotas, tenants, SIEM connectors et export conformité.
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
}