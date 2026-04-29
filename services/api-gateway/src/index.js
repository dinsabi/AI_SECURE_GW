import express from "express";
import cors from "cors";

const app = express();

app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-User-Email",
      "X-User-Department",
      "X-User-Roles",
      "X-User-Country",
      "X-MFA-Verified",
    ],
  })
);

app.use(express.json());

const PORT = process.env.PORT || 3000;

// 👉 IMPORTANT : accès fiable depuis Docker
const KEYCLOAK_URL =
  process.env.KEYCLOAK_URL || "http://keycloak:8080";

const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || "aigw";
const KEYCLOAK_CLIENT_ID =
  process.env.KEYCLOAK_CLIENT_ID || "ai-secure-gateway";
const KEYCLOAK_CLIENT_SECRET =
  process.env.KEYCLOAK_CLIENT_SECRET || "";

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
  return auth.startsWith("Bearer ") ? auth.substring("Bearer ".length) : null;
}

function requireAuth(req, res, next) {
  const token = extractBearerToken(req);

  if (!token) {
    return res.status(401).json({
      ok: false,
      error: "missing_token",
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
      body: JSON.stringify({ prompt, modelType }),
    });

    return await response.json();
  } catch (error) {
    return {
      provider: "fallback",
      answer: "LLM indisponible",
    };
  }
}

// ========================
// 🔐 MASQUAGE DONNÉES
// ========================
function maskSensitiveData(text) {
  return String(text)
    // EMAIL
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, "[EMAIL_MASKED]")

    // IBAN BE
    .replace(/\bBE\d{2}(?:\s?\d{4}){3}\b/g, "[IBAN_MASKED]")

    // IBAN générique
    .replace(/\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}\b/g, "[IBAN_MASKED]");
}

// ========================
// 🎯 RISK ENGINE
// ========================
function calculateRiskScore(prompt) {
  const sensitivePattern =
    /iban|password|secret|token|api[_-]?key|email|@|client|confidentiel|salaire|contract/i;

  return sensitivePattern.test(prompt) ? "HIGH" : "LOW";
}

// ========================
// 🔐 LOGIN KEYCLOAK
// ========================
app.post("/login/keycloak", async (req, res) => {
  const { username, password } = req.body;

  try {
    const params = new URLSearchParams();
    params.append("grant_type", "password");
    params.append("client_id", KEYCLOAK_CLIENT_ID);
    params.append("client_secret", KEYCLOAK_CLIENT_SECRET);
    params.append("username", username);
    params.append("password", password);

    const response = await fetch(
      `${KEYCLOAK_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: params.toString(),
      }
    );

    const data = await response.json();

    if (!response.ok) {
      return res.status(response.status).json({
        ok: false,
        error: "keycloak_login_failed",
        details: data,
      });
    }

    res.json({
      ok: true,
      access_token: data.access_token,
    });
  } catch (err) {
    res.status(500).json({
      ok: false,
      error: "keycloak_unreachable",
      message: err.message,
    });
  }
});

// ========================
// 🚀 GATEWAY PRINCIPAL
// ========================
app.post("/v1/gateway/process", requireAuth, async (req, res) => {
  const prompt = req.body.prompt || "";
  const modelType = req.body.modelType || "public_llm";
  const user = readUserFromHeaders(req);

  const riskScore = calculateRiskScore(prompt);

  // 🔥 MASQUAGE SI RISQUE
  const maskedPrompt =
    riskScore === "HIGH" ? maskSensitiveData(prompt) : prompt;

  const llmResponse = await callLlmMock(maskedPrompt, modelType);

  res.json({
    ok: true,
    authenticated: true,
    user,
    riskScore,
    decision: riskScore === "HIGH" ? "MASK_OR_REVIEW" : "ALLOW",

    // 👉 IMPORTANT POUR DEBUG / DEMO
    originalPrompt: prompt,
    maskedPrompt: maskedPrompt,

    response: llmResponse,
  });
});

// ========================
// HEALTH
// ========================
app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log("API Gateway ready on port " + PORT);
});