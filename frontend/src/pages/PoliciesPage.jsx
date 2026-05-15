import { Box, Card, CardContent, Typography } from "@mui/material";

export default function PoliciesPage() {
  return (
    <Box>
      <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
        Policies
      </Typography>

      <Typography sx={{ color: "#94a3b8", mb: 3 }}>
        Gestion future des règles NIS2 / GDPR / ISO27001.
      </Typography>

      <Card sx={{ background: "#111827", color: "#fff" }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 2 }}>
            Policy Engine
          </Typography>

          <Typography sx={{ color: "#94a3b8" }}>
            Prochaine évolution : règles configurables par département,
            fournisseur IA, niveau de risque, type de donnée sensible et tenant.
          </Typography>
        </CardContent>
      </Card>
    </Box>
  );
}