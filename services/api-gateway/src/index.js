import express from "express";

const app = express();
app.use(express.json());

const PORT = process.env.PORT || 3000;

function readUserFromHeaders(req) {
  return {
    email: req.headers["x-user-email"] || "admin@cidns.eu",
    department: req.headers["x-user-department"] || "Unknown",
    roles: req.headers["x-user-roles"] || "user",
    country: req.headers["x-user-country"] || "BE",
    mfaVerified: req.headers["x-mfa-verified"] || "false",
  };
}

function extractBearerToken(req) {
  const auth = req.headers.authorization || "";

  if (!auth.startsWith("Bearer ")) {
    return null;
  }

  return auth.substring("Bearer ".length);
}

function requireAuth(req, res, next) {
  const token = extractBearerToken(req);

  if (!token) {
    return res.status(401).json({
      ok: false,
      error: "missing_token",
      message: "Missing Authorization Bearer token",
    });
  }

  req.token = token;
  next();
}

async function callLlmMock(prompt, modelType) {
  const llmUrl = process.env.LLM_URL || "http://llm-mock:3006";

  try {
    const response = await fetch(`${llmUrl}/generate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        prompt,
        modelType,
      }),
    });

    if (!response.ok) {
      return {
        provider: "gateway-fallback",
        answer: `LLM mock returned HTTP ${response.status}`,
      };
    }

    return await response.json();
  } catch (error) {
    return {
      provider: "gateway-fallback",
      answer: `Réponse mock du Gateway pour: ${String(prompt).slice(0, 120)}`,
      warning: error.message,
    };
  }
}

function calculateRiskScore(prompt) {
  const sensitivePattern =
    /iban|password|secret|token|api[_-]?key|email|@|client|confidentiel|salaire|salary|contrat|contract/i;

  return sensitivePattern.test(prompt) ? "HIGH" : "LOW";
}

async function handleGenerate(req, res, routeName) {
  const prompt = String(req.body.prompt || "");
  const modelType = String(req.body.modelType || "public_llm");
  const user = readUserFromHeaders(req);

  const llmResponse = await callLlmMock(prompt, modelType);

  return res.json({
    ok: true,
    route: routeName,
    authenticated: true,
    user,
    modelType,
    prompt,
    response: llmResponse,
  });
}

async function handleGatewayProcess(req, res, routeName) {
  const prompt = String(req.body.prompt || "");
  const modelType = String(req.body.modelType || "public_llm");
  const frameworks = req.body.frameworks || ["NIS2", "GDPR", "ISO27001"];
  const user = readUserFromHeaders(req);

  const riskScore = calculateRiskScore(prompt);
  const llmResponse = await callLlmMock(prompt, modelType);

  return res.json({
    ok: true,
    route: routeName,
    authenticated: true,
    user,
    frameworks,
    riskScore,
    decision: riskScore === "HIGH" ? "MASK_OR_REVIEW" : "ALLOW",
    modelType,
    prompt,
    response: llmResponse,
  });
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "api-gateway",
    message: "AI Secure Gateway API",
    availableRoutes: [
      "GET /",
      "GET /health",
      "POST /generate",
      "POST /gateway/process",
      "POST /v1/generate",
      "POST /v1/gateway/process",
    ],
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "api-gateway",
    status: "UP",
  });
});

app.post("/generate", requireAuth, async (req, res) => {
  return handleGenerate(req, res, "/generate");
});

app.post("/gateway/process", requireAuth, async (req, res) => {
  return handleGatewayProcess(req, res, "/gateway/process");
});

app.post("/v1/generate", requireAuth, async (req, res) => {
  return handleGenerate(req, res, "/v1/generate");
});

app.post("/v1/gateway/process", requireAuth, async (req, res) => {
  return handleGatewayProcess(req, res, "/v1/gateway/process");
});

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: "not_found",
    method: req.method,
    path: req.originalUrl,
    availableRoutes: [
      "GET /",
      "GET /health",
      "POST /generate",
      "POST /gateway/process",
      "POST /v1/generate",
      "POST /v1/gateway/process",
    ],
  });
});

app.listen(PORT, () => {
  console.log(`api-gateway ready on port ${PORT}`);
});