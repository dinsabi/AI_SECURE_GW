import {
  Box,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Typography,
  Divider,
} from "@mui/material";

import { ShieldCheck, LayoutDashboard } from "lucide-react";

const menuItems = [
  {
    id: "security",
    label: "AI Security Console",
    icon: <ShieldCheck size={20} />,
  },
  {
    id: "dashboard",
    label: "SOC / GRC Dashboard",
    icon: <LayoutDashboard size={20} />,
  },
];

export default function Sidebar({ activePage, setActivePage }) {
  return (
    <Box
      sx={{
        width: 260,
        background: "#080d1a",
        borderRight: "1px solid #1f2937",
        color: "#fff",
        minHeight: "100vh",
        p: 2,
      }}
    >
      <Box sx={{ mb: 3 }}>
        <Typography variant="h6" sx={{ fontWeight: 700 }}>
          AI Secure Gateway
        </Typography>

        <Typography variant="body2" sx={{ color: "#94a3b8", mt: 0.5 }}>
          CIDNS Security Platform
        </Typography>
      </Box>

      <Divider sx={{ borderColor: "#1f2937", mb: 2 }} />

      <List>
        {menuItems.map((item) => {
          const selected = activePage === item.id;

          return (
            <ListItemButton
              key={item.id}
              selected={selected}
              onClick={() => setActivePage(item.id)}
              sx={{
                borderRadius: 2,
                mb: 1,
                color: selected ? "#38bdf8" : "#cbd5e1",
                background: selected ? "rgba(56, 189, 248, 0.12)" : "none",
                "&:hover": {
                  background: "rgba(56, 189, 248, 0.08)",
                },
                "&.Mui-selected": {
                  background: "rgba(56, 189, 248, 0.12)",
                },
              }}
            >
              <ListItemIcon
                sx={{
                  color: selected ? "#38bdf8" : "#94a3b8",
                  minWidth: 38,
                }}
              >
                {item.icon}
              </ListItemIcon>

              <ListItemText primary={item.label} />
            </ListItemButton>
          );
        })}
      </List>
    </Box>
  );
}