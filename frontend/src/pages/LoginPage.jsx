import {
  Box,
  Button,
  Card,
  CardContent,
  Container,
  TextField,
  Typography,
} from "@mui/material";

import ShieldIcon from "@mui/icons-material/Shield";

export default function LoginPage({
  username,
  setUsername,
  password,
  setPassword,
  status,
  onLogin,
}) {
  return (
    <Container maxWidth="sm">
      <Box
        sx={{
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
        }}
      >
        <Card
          sx={{
            width: "100%",
            background: "#111827",
            color: "#fff",
            borderRadius: 4,
            boxShadow: "0px 10px 40px rgba(0,0,0,0.4)",
          }}
        >
          <CardContent sx={{ p: 5 }}>
            <Box sx={{ textAlign: "center", mb: 4 }}>
              <ShieldIcon
                sx={{
                  fontSize: 70,
                  color: "#38bdf8",
                  mb: 2,
                }}
              />

              <Typography
                variant="h4"
                sx={{
                  fontWeight: 700,
                  mb: 1,
                }}
              >
                AI Secure Gateway
              </Typography>

              <Typography
                sx={{
                  color: "#94a3b8",
                }}
              >
                Enterprise AI Security Platform
              </Typography>

              <Typography
                sx={{
                  color: "#64748b",
                  mt: 1,
                  fontSize: 14,
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
              sx={{ mb: 3 }}
              InputLabelProps={{
                style: { color: "#94a3b8" },
              }}
              inputProps={{
                style: { color: "#fff" },
              }}
            />

            <TextField
              fullWidth
              type="password"
              label="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              sx={{ mb: 3 }}
              InputLabelProps={{
                style: { color: "#94a3b8" },
              }}
              inputProps={{
                style: { color: "#fff" },
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
                background: "#2563eb",
              }}
            >
              Login with Keycloak
            </Button>

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
      </Box>
    </Container>
  );
}