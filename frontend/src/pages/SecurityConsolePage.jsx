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

export default function SecurityConsolePage({
  modelType,
  setModelType,
  prompt,
  setPrompt,
  file,
  setFile,
  result,
  status,
  onAnalyzePrompt,
  onAnalyzeFile,
}) {
  return (
    <Box>
      <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
        AI Security Console
      </Typography>

      <Typography sx={{ color: "#94a3b8", mb: 3 }}>
        Analyse les prompts et fichiers avant leur envoi vers une IA.
      </Typography>

      <Typography sx={{ color: "#94a3b8", mb: 3 }}>
        Status: {status || "Ready"}
      </Typography>

      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <Card sx={{ background: "#111827", color: "#fff", mb: 2 }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                AI Provider
              </Typography>

              <TextField
                select
                fullWidth
                value={modelType}
                onChange={(e) => setModelType(e.target.value)}
              >
                <MenuItem value="mock">Mock LLM</MenuItem>
                <MenuItem value="openai">OpenAI / ChatGPT</MenuItem>
              </TextField>
            </CardContent>
          </Card>

          <Card sx={{ background: "#111827", color: "#fff" }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                File Protection
              </Typography>

              <Typography sx={{ color: "#94a3b8", mb: 2 }}>
                Formats : .txt, .csv, .json, .log, .docx, .pdf, .xlsx, .xls
              </Typography>

              <input
                type="file"
                accept=".txt,.csv,.json,.log,.docx,.pdf,.xlsx,.xls"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
              />

              {file && (
                <Typography sx={{ mt: 2 }}>
                  Fichier : <strong>{file.name}</strong> —{" "}
                  {(file.size / 1024).toFixed(2)} KB
                </Typography>
              )}

              <Button
                variant="contained"
                sx={{ mt: 3 }}
                onClick={onAnalyzeFile}
              >
                Analyze File
              </Button>
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
                minRows={11}
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
                Analyze Prompt
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <SecurityResult data={result} />
    </Box>
  );
}