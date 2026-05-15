import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  Grid,
  Typography,
} from "@mui/material";

function getRiskColor(level) {
  switch (level) {
    case "LOW":
      return "success";

    case "MEDIUM":
      return "warning";

    case "HIGH":
      return "error";

    case "CRITICAL":
      return "secondary";

    default:
      return "default";
  }
}

export default function SecurityResult({ data }) {
  if (!data) {
    return null;
  }

  const findings = data.findings || [];
  const responseSecurity = data.response?.responseSecurity || {};

  return (
    <Box sx={{ mt: 3 }}>
      <Grid container spacing={2}>
        <Grid item xs={12} md={3}>
          <Card
            sx={{
              background: "#111827",
              color: "#fff",
              border: "1px solid #1f2937",
            }}
          >
            <CardContent>
              <Typography sx={{ color: "#94a3b8" }}>
                Decision
              </Typography>

              <Typography variant="h6" sx={{ mt: 1 }}>
                {data.decision || "UNKNOWN"}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card
            sx={{
              background: "#111827",
              color: "#fff",
              border: "1px solid #1f2937",
            }}
          >
            <CardContent>
              <Typography sx={{ color: "#94a3b8" }}>
                Risk Score
              </Typography>

              <Typography variant="h4" sx={{ mt: 1, fontWeight: 700 }}>
                {data.riskScore || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card
            sx={{
              background: "#111827",
              color: "#fff",
              border: "1px solid #1f2937",
            }}
          >
            <CardContent>
              <Typography sx={{ color: "#94a3b8" }}>
                Risk Level
              </Typography>

              <Box sx={{ mt: 2 }}>
                <Chip
                  label={data.riskLevel || "UNKNOWN"}
                  color={getRiskColor(data.riskLevel)}
                />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card
            sx={{
              background: "#111827",
              color: "#fff",
              border: "1px solid #1f2937",
            }}
          >
            <CardContent>
              <Typography sx={{ color: "#94a3b8" }}>
                Findings
              </Typography>

              <Typography variant="h4" sx={{ mt: 1, fontWeight: 700 }}>
                {findings.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Card
        sx={{
          mt: 3,
          background: "#111827",
          color: "#fff",
          border: "1px solid #1f2937",
        }}
      >
        <CardContent>
          <Typography variant="h6" sx={{ mb: 2 }}>
            Protected Prompt
          </Typography>

          <Box
            sx={{
              background: "#020617",
              borderRadius: 2,
              p: 2,
              border: "1px solid #1e293b",
              overflowX: "auto",
            }}
          >
            <Typography
              sx={{
                color: "#cbd5e1",
                fontFamily: "monospace",
                whiteSpace: "pre-wrap",
              }}
            >
              {data.protectedPrompt ||
                data.protectedText ||
                "No protected content"}
            </Typography>
          </Box>
        </CardContent>
      </Card>

      {findings.length > 0 && (
        <Card
          sx={{
            mt: 3,
            background: "#111827",
            color: "#fff",
            border: "1px solid #1f2937",
          }}
        >
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2 }}>
              Sensitive Data Detected
            </Typography>

            {findings.map((finding, index) => (
              <Alert
                key={index}
                severity={getRiskColor(finding.severity)}
                sx={{ mb: 2 }}
              >
                <strong>{finding.type}</strong> detected → token{" "}
                <strong>{finding.token}</strong>
              </Alert>
            ))}
          </CardContent>
        </Card>
      )}

      {data.injection && (
        <Card
          sx={{
            mt: 3,
            background: "#111827",
            color: "#fff",
            border: "1px solid #1f2937",
          }}
        >
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2 }}>
              Prompt Injection Analysis
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Typography sx={{ color: "#94a3b8" }}>
                  Detected
                </Typography>

                <Typography variant="h6">
                  {data.injection.detected ? "YES" : "NO"}
                </Typography>
              </Grid>

              <Grid item xs={12} md={4}>
                <Typography sx={{ color: "#94a3b8" }}>
                  Risk Level
                </Typography>

                <Chip
                  label={data.injection.riskLevel}
                  color={getRiskColor(data.injection.riskLevel)}
                />
              </Grid>

              <Grid item xs={12} md={4}>
                <Typography sx={{ color: "#94a3b8" }}>
                  Score
                </Typography>

                <Typography variant="h6">
                  {data.injection.score}
                </Typography>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}

      {data.response && (
        <Card
          sx={{
            mt: 3,
            background: "#111827",
            color: "#fff",
            border: "1px solid #1f2937",
          }}
        >
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2 }}>
              AI Response
            </Typography>

            <Divider sx={{ borderColor: "#1f2937", mb: 2 }} />

            <Typography sx={{ color: "#94a3b8", mb: 1 }}>
              Provider
            </Typography>

            <Typography sx={{ mb: 2 }}>
              {data.response.provider || "unknown"}
            </Typography>

            <Typography sx={{ color: "#94a3b8", mb: 1 }}>
              Routing Decision
            </Typography>

            <Typography sx={{ mb: 2 }}>
              {data.response.routingDecision || "unknown"}
            </Typography>

            {data.response.error ? (
              <Alert severity="error">
                {data.response.message}
              </Alert>
            ) : (
              <Box
                sx={{
                  background: "#020617",
                  borderRadius: 2,
                  p: 2,
                  border: "1px solid #1e293b",
                }}
              >
                <Typography
                  sx={{
                    whiteSpace: "pre-wrap",
                    color: "#cbd5e1",
                  }}
                >
                  {data.response.answer || "No response"}
                </Typography>
              </Box>
            )}

            <Divider sx={{ borderColor: "#1f2937", my: 3 }} />

            <Typography variant="h6" sx={{ mb: 2 }}>
              Response Security
            </Typography>

            <Grid container spacing={2}>
              <Grid item xs={12} md={4}>
                <Typography sx={{ color: "#94a3b8" }}>
                  Decision
                </Typography>

                <Typography>
                  {responseSecurity.decision || "UNKNOWN"}
                </Typography>
              </Grid>

              <Grid item xs={12} md={4}>
                <Typography sx={{ color: "#94a3b8" }}>
                  Risk Level
                </Typography>

                <Chip
                  label={responseSecurity.riskLevel || "UNKNOWN"}
                  color={getRiskColor(responseSecurity.riskLevel)}
                />
              </Grid>

              <Grid item xs={12} md={4}>
                <Typography sx={{ color: "#94a3b8" }}>
                  Risk Score
                </Typography>

                <Typography>
                  {responseSecurity.riskScore || 0}
                </Typography>
              </Grid>
            </Grid>
          </CardContent>
        </Card>
      )}
    </Box>
  );
}