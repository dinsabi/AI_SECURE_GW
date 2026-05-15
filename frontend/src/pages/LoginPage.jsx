import {
  Box,
  Button,
  Card,
  CardContent,
  CircularProgress,
  Container,
  TextField,
  Typography,
  Avatar,
} from "@mui/material";

import logo from "../assets/cidns-logo.jpeg";

export default function LoginPage({
  username,
  setUsername,
  password,
  setPassword,
  status,
  loading,
  onLogin,
}) {
  const fieldStyle = {
    mb: 3,
    "& .MuiOutlinedInput-root": {
      color: "#ffffff",
      background: "#0f172a",
      "& fieldset": {
        borderColor: "#334155",
      },
      "&:hover fieldset": {
        borderColor: "#38bdf8",
      },
      "&.Mui-focused fieldset": {
        borderColor: "#38bdf8",
      },
    },
    "& .MuiInputLabel-root": {
      color: "#cbd5e1",
    },
    "& .MuiInputLabel-root.Mui-focused": {
      color: "#38bdf8",
    },
  };

  return (
    <Box
      sx={{
        minHeight: "100vh",
        background:
          "linear-gradient(135deg, #020617 0%, #0f172a 45%, #111827 100%)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        p: 2,
      }}
    >
      <Container maxWidth="sm">
        <Card
          sx={{
            background: "rgba(15,23,42,0.96)",
            backdropFilter: "blur(12px)",
            border: "1px solid #1e293b",
            borderRadius: 5,
            color: "#fff",
            overflow: "hidden",
            boxShadow: "0 20px 60px rgba(0,0,0,0.5)",
          }}
        >
          <CardContent sx={{ p: 5 }}>
            <Box
              sx={{
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                mb: 4,
              }}
            >
              <Avatar
                src={logo}
                alt="CIDNS"
                sx={{
                  width: 150,
                  height: 150,
                  mb: 2,
                  background: "#fff",
                  border: "3px solid #38bdf8",
                  boxShadow: "0 0 35px rgba(56,189,248,0.35)",
                }}
              />

              <Typography
                variant="h4"
                sx={{
                  fontWeight: 800,
                  mb: 1,
                  textAlign: "center",
                  letterSpacing: 0.3,
                }}
              >
                AI Secure Gateway
              </Typography>

              <Typography
                sx={{
                  color: "#38bdf8",
                  fontWeight: 700,
                  textAlign: "center",
                  fontSize: 16,
                }}
              >
                CIDNS Enterprise AI Security Platform
              </Typography>

              <Typography
                sx={{
                  color: "#94a3b8",
                  mt: 1,
                  fontSize: 14,
                  textAlign: "center",
                }}
              >
                NIS2 • GDPR • ISO27001 • Zero Trust AI
              </Typography>
            </Box>

            <TextField
              fullWidth
              label="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              variant="outlined"
              placeholder="admin"
              disabled={loading}
              sx={fieldStyle}
            />

            <TextField
              fullWidth
              type="password"
              label="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              variant="outlined"
              placeholder="admin"
              disabled={loading}
              sx={fieldStyle}
            />

            <Button
              fullWidth
              variant="contained"
              size="large"
              onClick={onLogin}
              disabled={loading}
              sx={{
                py: 1.5,
                fontWeight: 800,
                background:
                  "linear-gradient(90deg,#2563eb 0%, #38bdf8 100%)",
                borderRadius: 3,
                fontSize: 16,
                textTransform: "none",
                boxShadow: "0 10px 30px rgba(37,99,235,0.35)",
                "&:hover": {
                  background:
                    "linear-gradient(90deg,#1d4ed8 0%, #0ea5e9 100%)",
                },
              }}
            >
              {loading ? (
                <>
                  <CircularProgress
                    size={20}
                    sx={{ color: "#fff", mr: 1 }}
                  />
                  Connecting...
                </>
              ) : (
                "Login with Keycloak"
              )}
            </Button>

            <Box
              sx={{
                mt: 3,
                background: "#020617",
                border: "1px solid #1e293b",
                borderRadius: 3,
                p: 2,
              }}
            >
              <Typography
                sx={{
                  color: "#38bdf8",
                  fontWeight: 800,
                  mb: 1,
                }}
              >
                Demo Credentials
              </Typography>

              <Typography sx={{ color: "#e2e8f0", fontSize: 15 }}>
                Username: <strong>admin</strong>
              </Typography>

              <Typography sx={{ color: "#e2e8f0", fontSize: 15 }}>
                Password: <strong>admin</strong>
              </Typography>
            </Box>

            <Typography
              sx={{
                mt: 3,
                textAlign: "center",
                color: status?.toLowerCase().includes("failed")
                  ? "#f87171"
                  : status?.toLowerCase().includes("erreur")
                  ? "#f87171"
                  : status?.toLowerCase().includes("ok")
                  ? "#22c55e"
                  : "#94a3b8",
                fontSize: 14,
                fontWeight: 600,
              }}
            >
              {status || "Ready"}
            </Typography>
          </CardContent>
        </Card>
      </Container>
    </Box>
  );
}