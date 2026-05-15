import { createTheme } from "@mui/material/styles";

export const theme = createTheme({
  palette: {
    mode: "dark",
    primary: {
      main: "#38bdf8",
    },
    secondary: {
      main: "#2563eb",
    },
    background: {
      default: "#0b1020",
      paper: "#111827",
    },
    text: {
      primary: "#ffffff",
      secondary: "#94a3b8",
    },
    success: {
      main: "#22c55e",
    },
    warning: {
      main: "#f59e0b",
    },
    error: {
      main: "#ef4444",
    },
  },

  typography: {
    fontFamily: ["Inter", "Arial", "sans-serif"].join(","),
    h4: {
      fontWeight: 800,
    },
    h6: {
      fontWeight: 700,
    },
    button: {
      textTransform: "none",
      fontWeight: 700,
    },
  },

  shape: {
    borderRadius: 14,
  },

  components: {
    MuiCard: {
      styleOverrides: {
        root: {
          backgroundImage: "none",
          border: "1px solid #1f2937",
          boxShadow: "0 12px 30px rgba(0,0,0,0.25)",
        },
      },
    },

    MuiButton: {
      styleOverrides: {
        root: {
          borderRadius: 12,
        },
      },
    },

    MuiTextField: {
      styleOverrides: {
        root: {
          "& .MuiOutlinedInput-root": {
            backgroundColor: "#0f172a",
            color: "#ffffff",
          },
          "& .MuiInputLabel-root": {
            color: "#cbd5e1",
          },
          "& .MuiInputLabel-root.Mui-focused": {
            color: "#38bdf8",
          },
        },
      },
    },
  },
});