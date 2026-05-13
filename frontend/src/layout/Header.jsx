import { Box, Chip, Typography } from "@mui/material";
import { Shield, RadioTower } from "lucide-react";

export default function Header() {
  return (
    <Box
      sx={{
        height: 72,
        px: 3,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        background: "#0f172a",
        borderBottom: "1px solid #1f2937",
        color: "#fff",
      }}
    >
      <Box>
        <Typography variant="h6" sx={{ fontWeight: 700 }}>
          AI Security Operations Center
        </Typography>
        <Typography variant="body2" sx={{ color: "#94a3b8" }}>
          Zero Trust gateway for enterprise AI usage
        </Typography>
      </Box>

      <Box sx={{ display: "flex", gap: 1.5, alignItems: "center" }}>
        <Chip
          icon={<Shield size={16} />}
          label="NIS2 / GDPR / ISO27001"
          sx={{
            color: "#bbf7d0",
            background: "rgba(34, 197, 94, 0.15)",
            border: "1px solid rgba(34, 197, 94, 0.35)",
          }}
        />

        <Chip
          icon={<RadioTower size={16} />}
          label="Gateway Online"
          sx={{
            color: "#bae6fd",
            background: "rgba(14, 165, 233, 0.15)",
            border: "1px solid rgba(14, 165, 233, 0.35)",
          }}
        />
      </Box>
    </Box>
  );
}