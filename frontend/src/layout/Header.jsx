import { Avatar, Box, Button, Chip, Typography } from "@mui/material";
import { LogOut, RadioTower, Shield } from "lucide-react";

import logo from "../assets/cidns-logo.jpeg";

export default function Header({ username = "admin", onLogout }) {
  return (
    <Box
      sx={{
        height: 76,
        px: 3,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        background: "#0f172a",
        borderBottom: "1px solid #1f2937",
        color: "#fff",
      }}
    >
      <Box sx={{ display: "flex", alignItems: "center", gap: 2 }}>
        <Avatar
          src={logo}
          alt="CIDNS"
          sx={{
            width: 44,
            height: 44,
            background: "#fff",
            border: "2px solid #38bdf8",
          }}
        />

        <Box>
          <Typography variant="h6" sx={{ fontWeight: 800 }}>
            AI Security Operations Center
          </Typography>

          <Typography variant="body2" sx={{ color: "#94a3b8" }}>
            Zero Trust gateway for enterprise AI usage
          </Typography>
        </Box>
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

        <Chip
          label={`User: ${username}`}
          sx={{
            color: "#e2e8f0",
            background: "rgba(148, 163, 184, 0.12)",
            border: "1px solid rgba(148, 163, 184, 0.25)",
          }}
        />

        <Button
          variant="outlined"
          size="small"
          startIcon={<LogOut size={16} />}
          onClick={onLogout}
          sx={{
            color: "#fca5a5",
            borderColor: "rgba(248, 113, 113, 0.45)",
            "&:hover": {
              borderColor: "#ef4444",
              background: "rgba(239, 68, 68, 0.08)",
            },
          }}
        >
          Logout
        </Button>
      </Box>
    </Box>
  );
}