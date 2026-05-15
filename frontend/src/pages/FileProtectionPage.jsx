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

export default function FileProtectionPage({
  file,
  setFile,
  modelType,
  setModelType,
  result,
  onAnalyzeFile,
}) {
  return (
    <Box>
      <Typography variant="h4" sx={{ fontWeight: 700, mb: 1 }}>
        File Protection
      </Typography>

      <Typography sx={{ color: "#94a3b8", mb: 3 }}>
        Analyse les fichiers avant usage avec une IA : masking, tokenisation,
        chiffrement AES, prompt injection protection et audit GRC.
      </Typography>

      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <Card sx={{ background: "#111827", color: "#fff" }}>
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
        </Grid>

        <Grid item xs={12} md={8}>
          <Card sx={{ background: "#111827", color: "#fff" }}>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 2 }}>
                Upload File
              </Typography>

              <Typography sx={{ color: "#94a3b8", mb: 2 }}>
                Formats supportés : .txt, .csv, .json, .log, .docx, .pdf,
                .xlsx, .xls
              </Typography>

              <input
                type="file"
                accept=".txt,.csv,.json,.log,.docx,.pdf,.xlsx,.xls"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
              />

              {file && (
                <Typography sx={{ mt: 2 }}>
                  Fichier sélectionné : <strong>{file.name}</strong> —{" "}
                  {(file.size / 1024).toFixed(2)} KB
                </Typography>
              )}

              <Button variant="contained" sx={{ mt: 3 }} onClick={onAnalyzeFile}>
                Analyze Uploaded File
              </Button>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <SecurityResult data={result} />
    </Box>
  );
}