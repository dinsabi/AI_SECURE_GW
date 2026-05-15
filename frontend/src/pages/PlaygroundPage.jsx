import {
  Box,
  Button,
  Card,
  CardContent,
  Grid,
  MenuItem,
  TextField,
  Typography,
} from "@mui/material";

import SecurityResult from "../components/SecurityResult.jsx";

export default function PlaygroundPage({
  username,
  setUsername,
  password,
  setPassword,
  modelType,
  setModelType,
  prompt,
  setPrompt,
  status,
  result,
  onLogin,
  onAnalyzePrompt,
}) {
  return (
    <Box>
      <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
        AI Playground sécurisé
      </Typography>

      <Typography sx={{ color: "#94a3b8", mb: 3 }}>
        Teste un prompt IA avec masking, scoring, prompt injection protection,
        routing LLM et audit GRC.
      </Typography>

      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <Card sx={{ background: "#111827", color: "#fff" }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Keycloak Login
              </Typography>

              <TextField
                fullWidth
                label="Username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                sx={{ mb: 2 }}
                InputLabelProps={{ style: { color: "#94a3b8" } }}
                inputProps={{ style: { color: "#fff" } }}
              />

              <TextField
                fullWidth
                type="password"
                label="Password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                sx={{ mb: 2 }}
                InputLabelProps={{ style: { color: "#94a3b8" } }}
                inputProps={{ style: { color: "#fff" } }}
              />

              <Button variant="contained" fullWidth onClick={onLogin}>
                Login
              </Button>

              <Typography sx={{ color: "#94a3b8", mt: 2 }}>
                Status: {status || "Ready"}
              </Typography>
            </CardContent>
          </Card>

          <Card sx={{ background: "#111827", color: "#fff", mt: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                AI Provider
              </Typography>

              <TextField
                select
                fullWidth
                value={modelType}
                onChange={(e) => setModelType(e.target.value)}
                inputProps={{ style: { color: "#fff" } }}
              >
                <MenuItem value="mock">Mock LLM</MenuItem>
                <MenuItem value="openai">OpenAI / ChatGPT</MenuItem>
              </TextField>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={8}>
          <Card sx={{ background: "#111827", color: "#fff" }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Prompt Protection
              </Typography>

              <TextField
                multiline
                minRows={9}
                fullWidth
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                placeholder="Enter your prompt..."
                InputProps={{
                  style: {
                    color: "#fff",
                    background: "#0b1020",
                  },
                }}
              />

              <Button
                variant="contained"
                sx={{ mt: 2 }}
                onClick={onAnalyzePrompt}
              >
                Analyze & Protect Prompt
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <SecurityResult data={result} />
    </Box>
  );
}