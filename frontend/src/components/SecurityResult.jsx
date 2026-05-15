import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  Grid,
  Stack,
  Typography,
} from "@mui/material";

import {
  AlertTriangle,
  Bot,
  CheckCircle,
  Database,
  KeyRound,
  Landmark,
  Network,
  ShieldAlert,
  ShieldX,
  UserRound,
} from "lucide-react";

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

function getCategory(type = "") {
  const t = type.toUpperCase();

  if (
    [
      "OPENAI_API_KEY",
      "API_KEY",
      "JWT_TOKEN",
      "BEARER_TOKEN",
      "PASSWORD",
      "PRIVATE_KEY",
      "AWS_ACCESS_KEY",
      "AWS_SECRET_KEY",
      "GITHUB_TOKEN",
      "AZURE_SECRET",
      "CONNECTION_STRING",
    ].includes(t)
  ) {
    return {
      label: "Secrets / Credentials",
      color: "error",
      icon: <KeyRound size={16} />,
    };
  }

  if (
    [
      "EMAIL",
      "PHONE",
      "NATIONAL_ID_BE",
      "DATE_OF_BIRTH",
      "ADDRESS",
      "PASSPORT_NUMBER",
      "DRIVING_LICENSE",
      "LICENSE_PLATE",
    ].includes(t)
  ) {
    return {
      label: "Personal Data / GDPR",
      color: "info",
      icon: <UserRound size={16} />,
    };
  }

  if (
    ["IBAN", "CREDIT_CARD", "VAT", "SALARY", "REVENUE", "MARGIN"].includes(t)
  ) {
    return {
      label: "Financial Data",
      color: "warning",
      icon: <Landmark size={16} />,
    };
  }

  if (["PRIVATE_IP", "PUBLIC_IP", "HOSTNAME", "INTERNAL_URL"].includes(t)) {
    return {
      label: "Infrastructure",
      color: "secondary",
      icon: <Network size={16} />,
    };
  }

  if (["CONTRACT_NUMBER", "CUSTOMER_NAME", "SUPPLIER_NAME"].includes(t)) {
    return {
      label: "Business Sensitive",
      color: "warning",
      icon: <Database size={16} />,
    };
  }

  return {
    label: "Sensitive Data",
    color: "default",
    icon: <ShieldAlert size={16} />,
  };
}

function groupFindings(findings = []) {
  const grouped = {};

  for (const finding of findings) {
    const category = getCategory(finding.type).label;

    if (!grouped[category]) {
      grouped[category] = [];
    }

    grouped[category].push(finding);
  }

  return grouped;
}

function getDecisionIcon(decision = "") {
  if (decision.includes("BLOCK")) {
    return <AlertTriangle size={22} color="#ef4444" />;
  }

  if (decision.includes("MASK")) {
    return <ShieldAlert size={22} color="#f59e0b" />;
  }

  return <CheckCircle size={22} color="#22c55e" />;
}

function getInjectionTypeLabel(type = "") {
  return String(type || "")
    .replaceAll("_", " ")
    .toLowerCase()
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export default function SecurityResult({ data }) {
  if (!data) {
    return null;
  }

  const findings = data.findings || [];
  const groupedFindings = groupFindings(findings);
  const responseSecurity = data.response?.responseSecurity || {};
  const frameworks = data.stats?.frameworks || data.frameworks || [];
  const injectionHits = data.injection?.hits || [];

  return (
    <Box sx={{ mt: 3 }}>
      <Grid container spacing={2}>
        <Grid item xs={12} md={3}>
          <Card sx={{ background: "#111827", color: "#fff" }}>
            <CardContent>
              <Stack direction="row" spacing={1.5} alignItems="center">
                {getDecisionIcon(data.decision || "")}
                <Box>
                  <Typography sx={{ color: "#94a3b8" }}>Decision</Typography>
                  <Typography variant="h6">
                    {data.decision || "UNKNOWN"}
                  </Typography>
                </Box>
              </Stack>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card sx={{ background: "#111827", color: "#fff" }}>
            <CardContent>
              <Typography sx={{ color: "#94a3b8" }}>Risk Score</Typography>
              <Typography variant="h4" sx={{ mt: 1, fontWeight: 800 }}>
                {data.riskScore || 0}
              </Typography>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card sx={{ background: "#111827", color: "#fff" }}>
            <CardContent>
              <Typography sx={{ color: "#94a3b8" }}>Risk Level</Typography>
              <Box sx={{ mt: 2 }}>
                <Chip
                  label={data.riskLevel || "UNKNOWN"}
                  color={getRiskColor(data.riskLevel)}
                  sx={{ fontWeight: 800 }}
                />
              </Box>
            </CardContent>
          </Card>
        </Grid>

        <Grid item xs={12} md={3}>
          <Card sx={{ background: "#111827", color: "#fff" }}>
            <CardContent>
              <Typography sx={{ color: "#94a3b8" }}>DLP Findings</Typography>
              <Typography variant="h4" sx={{ mt: 1, fontWeight: 800 }}>
                {findings.length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {data.injection && (
        <Card sx={{ mt: 3, background: "#111827", color: "#fff" }}>
          <CardContent>
            <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 2 }}>
              <ShieldX size={24} color="#ef4444" />
              <Box>
                <Typography variant="h6">AI Prompt Firewall</Typography>
                <Typography sx={{ color: "#94a3b8", fontSize: 14 }}>
                  Jailbreak, prompt injection, data exfiltration and system prompt leak detection.
                </Typography>
              </Box>
            </Stack>

            <Grid container spacing={2}>
              <Grid item xs={12} md={3}>
                <Typography sx={{ color: "#94a3b8" }}>Detected</Typography>
                <Typography variant="h6">
                  {data.injection.detected ? "YES" : "NO"}
                </Typography>
              </Grid>

              <Grid item xs={12} md={3}>
                <Typography sx={{ color: "#94a3b8" }}>Decision</Typography>
                <Chip
                  label={data.injection.decision || "ALLOW"}
                  color={
                    data.injection.decision === "BLOCK"
                      ? "error"
                      : data.injection.decision === "REVIEW"
                      ? "warning"
                      : "success"
                  }
                  sx={{ fontWeight: 800 }}
                />
              </Grid>

              <Grid item xs={12} md={3}>
                <Typography sx={{ color: "#94a3b8" }}>Risk Level</Typography>
                <Chip
                  label={data.injection.riskLevel || "LOW"}
                  color={getRiskColor(data.injection.riskLevel)}
                  sx={{ fontWeight: 800 }}
                />
              </Grid>

              <Grid item xs={12} md={3}>
                <Typography sx={{ color: "#94a3b8" }}>Score</Typography>
                <Typography variant="h6">{data.injection.score || 0}</Typography>
              </Grid>
            </Grid>

            {injectionHits.length > 0 && (
              <Box sx={{ mt: 3 }}>
                <Typography sx={{ mb: 1.5, fontWeight: 800 }}>
                  Firewall Rules Triggered
                </Typography>

                <Grid container spacing={1.5}>
                  {injectionHits.map((hit, index) => (
                    <Grid item xs={12} md={6} key={`${hit.id}-${index}`}>
                      <Alert
                        severity={getRiskColor(hit.severity)}
                        sx={{
                          background: "#020617",
                          color: "#e2e8f0",
                          border: "1px solid #1f2937",
                        }}
                      >
                        <Stack spacing={1}>
                          <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                            <Chip
                              size="small"
                              label={hit.id}
                              color={getRiskColor(hit.severity)}
                              sx={{ fontWeight: 800 }}
                            />
                            <Chip
                              size="small"
                              label={getInjectionTypeLabel(hit.type)}
                              variant="outlined"
                              color={getRiskColor(hit.severity)}
                            />
                            <Chip
                              size="small"
                              label={hit.severity}
                              variant="outlined"
                              color={getRiskColor(hit.severity)}
                            />
                          </Stack>

                          <Typography sx={{ fontSize: 14 }}>
                            {hit.description}
                          </Typography>

                          <Typography sx={{ color: "#94a3b8", fontSize: 13 }}>
                            Rule score: {hit.score}
                          </Typography>
                        </Stack>
                      </Alert>
                    </Grid>
                  ))}
                </Grid>
              </Box>
            )}
          </CardContent>
        </Card>
      )}

      {findings.length > 0 && (
        <Card sx={{ mt: 3, background: "#111827", color: "#fff" }}>
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2 }}>
              Advanced DLP Detection
            </Typography>

            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap sx={{ mb: 3 }}>
              {Object.keys(groupedFindings).map((category) => {
                const categoryInfo = getCategory(groupedFindings[category][0]?.type);

                return (
                  <Chip
                    key={category}
                    icon={categoryInfo.icon}
                    label={`${category} (${groupedFindings[category].length})`}
                    color={categoryInfo.color}
                    variant="outlined"
                    sx={{ fontWeight: 700 }}
                  />
                );
              })}
            </Stack>

            {Object.entries(groupedFindings).map(([category, items]) => {
              const categoryInfo = getCategory(items[0]?.type);

              return (
                <Box key={category} sx={{ mb: 3 }}>
                  <Stack direction="row" spacing={1} alignItems="center" sx={{ mb: 1 }}>
                    {categoryInfo.icon}
                    <Typography sx={{ fontWeight: 800 }}>{category}</Typography>
                  </Stack>

                  <Grid container spacing={1.5}>
                    {items.map((finding, index) => (
                      <Grid item xs={12} md={6} key={`${finding.type}-${index}`}>
                        <Alert
                          severity={getRiskColor(finding.severity)}
                          sx={{
                            background: "#020617",
                            color: "#e2e8f0",
                            border: "1px solid #1f2937",
                          }}
                        >
                          <Stack spacing={1}>
                            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                              <Chip
                                size="small"
                                label={finding.type}
                                color={getRiskColor(finding.severity)}
                                sx={{ fontWeight: 800 }}
                              />

                              <Chip
                                size="small"
                                label={finding.severity}
                                variant="outlined"
                                color={getRiskColor(finding.severity)}
                              />

                              {finding.encrypted && (
                                <Chip
                                  size="small"
                                  label="AES encrypted"
                                  variant="outlined"
                                  color="success"
                                />
                              )}
                            </Stack>

                            <Typography sx={{ fontSize: 14 }}>
                              Token generated: <strong>{finding.token}</strong>
                            </Typography>

                            <Typography sx={{ color: "#94a3b8", fontSize: 13 }}>
                              Original length: {finding.originalLength || 0} characters
                            </Typography>

                            {finding.frameworks?.length > 0 && (
                              <Stack direction="row" spacing={0.8} flexWrap="wrap" useFlexGap>
                                {finding.frameworks.map((fw) => (
                                  <Chip
                                    key={fw}
                                    size="small"
                                    label={fw}
                                    sx={{
                                      background: "rgba(56,189,248,0.12)",
                                      color: "#bae6fd",
                                    }}
                                  />
                                ))}
                              </Stack>
                            )}
                          </Stack>
                        </Alert>
                      </Grid>
                    ))}
                  </Grid>
                </Box>
              );
            })}
          </CardContent>
        </Card>
      )}

      <Card sx={{ mt: 3, background: "#111827", color: "#fff" }}>
        <CardContent>
          <Typography variant="h6" sx={{ mb: 2 }}>
            Protected Content
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
              {data.protectedPrompt || data.protectedText || "No protected content"}
            </Typography>
          </Box>
        </CardContent>
      </Card>

      {data.response && (
        <Card sx={{ mt: 3, background: "#111827", color: "#fff" }}>
          <CardContent>
            <Stack direction="row" spacing={1.5} alignItems="center" sx={{ mb: 2 }}>
              <Bot size={22} color="#38bdf8" />
              <Typography variant="h6">AI Response Security</Typography>
            </Stack>

            <Divider sx={{ borderColor: "#1f2937", mb: 2 }} />

            <Grid container spacing={2} sx={{ mb: 2 }}>
              <Grid item xs={12} md={4}>
                <Typography sx={{ color: "#94a3b8" }}>Provider</Typography>
                <Typography sx={{ fontWeight: 700 }}>
                  {data.response.provider || "unknown"}
                </Typography>
              </Grid>

              <Grid item xs={12} md={4}>
                <Typography sx={{ color: "#94a3b8" }}>Routing Decision</Typography>
                <Typography sx={{ fontWeight: 700 }}>
                  {data.response.routingDecision || "unknown"}
                </Typography>
              </Grid>

              <Grid item xs={12} md={4}>
                <Typography sx={{ color: "#94a3b8" }}>Response Risk</Typography>
                <Chip
                  label={responseSecurity.riskLevel || "UNKNOWN"}
                  color={getRiskColor(responseSecurity.riskLevel)}
                />
              </Grid>
            </Grid>

            {data.response.error ? (
              <Alert severity="error">{data.response.message}</Alert>
            ) : (
              <Box
                sx={{
                  background: "#020617",
                  borderRadius: 2,
                  p: 2,
                  border: "1px solid #1e293b",
                }}
              >
                <Typography sx={{ whiteSpace: "pre-wrap", color: "#cbd5e1" }}>
                  {data.response.answer || "No response"}
                </Typography>
              </Box>
            )}
          </CardContent>
        </Card>
      )}

      {frameworks.length > 0 && (
        <Card sx={{ mt: 3, background: "#111827", color: "#fff" }}>
          <CardContent>
            <Typography variant="h6" sx={{ mb: 2 }}>
              Compliance Mapping
            </Typography>

            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
              {frameworks.map((fw) => (
                <Chip
                  key={fw}
                  label={fw}
                  sx={{
                    background: "rgba(34,197,94,0.15)",
                    color: "#bbf7d0",
                    border: "1px solid rgba(34,197,94,0.35)",
                    fontWeight: 700,
                  }}
                />
              ))}
            </Stack>
          </CardContent>
        </Card>
      )}

      {findings.length === 0 && !data.injection?.detected && (
        <Card sx={{ mt: 3, background: "#111827", color: "#fff" }}>
          <CardContent>
            <Alert severity="success">
              No sensitive data or prompt injection detected. The request can be
              processed according to the current policy.
            </Alert>
          </CardContent>
        </Card>
      )}
    </Box>
  );
}