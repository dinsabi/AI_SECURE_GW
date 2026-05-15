import {
  Box,
  Button,
  Card,
  CardContent,
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
  onLogin,
}) {
  return (
    <Box
      sx={{
        minHeight: "100vh",
        background:
          "linear-gradient(135deg, #020617 0%, #0f172a 40%, #111827 100%)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        p: 2,
      }}
    >
      <Container maxWidth="sm">
        <Card
          sx={{
            background: "rgba(15,23,42,0.95)",
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
                  width: 140,
                  height: 140,
                  mb: 2,
                  background: "#fff",
                  border: "3px solid #38bdf8",
                }}
              />

              <Typography
                variant="h4"
                sx={{
                  fontWeight: 700,
                  mb: 1,
                  textAlign: "center",
                }}
              >
                AI Secure Gateway
              </Typography>

              <Typography
                sx={{
                  color: "#38bdf8",
                  fontWeight: 600,
                  textAlign: "center",
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
              sx={{
                mb: 3,
                input: { color: "#fff" },
              }}
              InputLabelProps={{
                style: { color: "#94a3b8" },
              }}
            />

            <TextField
              fullWidth
              type="password"
              label="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              sx={{
                mb: 3,
                input: { color: "#fff" },
              }}
              InputLabelProps={{
                style: { color: "#94a3b8" },
              }}
            />

            <Button
              fullWidth
              variant="contained"
              size="large"
              onClick={onLogin}
              sx={{
                py: 1.5,
                fontWeight: 700,
                background:
                  "linear-gradient(90deg,#2563eb 0%, #38bdf8 100%)",
                borderRadius: 3,
                fontSize: 16,
              }}
            >
              Login with Keycloak
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
                  fontWeight: 700,
                  mb: 1,
                }}
              >
                Demo Credentials
              </Typography>

              <Typography sx={{ color: "#cbd5e1", fontSize: 14 }}>
                User: <strong>admin</strong>
              </Typography>

              <Typography sx={{ color: "#cbd5e1", fontSize: 14 }}>
                Password: <strong>admin</strong>
              </Typography>
            </Box>

            <Typography
              sx={{
                mt: 3,
                textAlign: "center",
                color: "#94a3b8",
                fontSize: 14,
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