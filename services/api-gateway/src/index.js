import multer from "multer";
import { protectUploadedFile } from "./fileProtectionEngine.js";
import cors from "cors"
import express from "express";
import { protectPrompt } from "./dataProtectionEngine.js";

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

const KEYCLOAK_URL = process.env.KEYCLOAK_URL || "http://keycloak:8080";
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || "aigw";
const KEYCLOAK_CLIENT_ID =
  process.env.KEYCLOAK_CLIENT_ID || "ai-secure-gateway";
const KEYCLOAK_CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET || "";

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
      body: JSON.stringify({ prompt, modelType }),
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
      answer: "LLM indisponible",
      warning: error.message,
    };
  }
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "api-gateway",
    message: "AI Secure Gateway API",
    availableRoutes: [
      "GET /",
      "GET /health",
      "POST /login/keycloak",
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
    keycloak: {
      url: KEYCLOAK_URL,
      realm: KEYCLOAK_REALM,
      clientId: KEYCLOAK_CLIENT_ID,
    },
  });
});

app.post("/login/keycloak", async (req, res) => {
  const username = req.body.username || req.body.email;
  const password = req.body.password;

  if (!username || !password) {
    return res.status(400).json({
      ok: false,
      error: "missing_credentials",
      message: "username/email and password are required",
    });
  }

  try {
    const params = new URLSearchParams();
    params.append("grant_type", "password");
    params.append("client_id", KEYCLOAK_CLIENT_ID);

    if (KEYCLOAK_CLIENT_SECRET) {
      params.append("client_secret", KEYCLOAK_CLIENT_SECRET);
    }

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

    return res.json({
      ok: true,
      access_token: data.access_token,
      refresh_token: data.refresh_token,
      token_type: data.token_type,
      expires_in: data.expires_in,
      refresh_expires_in: data.refresh_expires_in,
      scope: data.scope,
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      error: "keycloak_unreachable",
      message: error.message,
    });
  }
});

app.post("/generate", requireAuth, async (req, res) => {
  const prompt = req.body.prompt || "";
  const modelType = req.body.modelType || "public_llm";

  const protection = protectPrompt(prompt, {
    modelType,
    department: "Unknown",
    roles: "user",
    country: "BE",
    mfaVerified: "false",
  });

  const llmResponse = await callLlmMock(protection.protectedText, modelType);

  return res.json({
    ok: true,
    route: "/generate",
    authenticated: true,
    modelType,
    decision: protection.decision,
    riskScore: protection.score,
    riskLevel: protection.riskLevel,
    originalPrompt: protection.originalText,
    protectedPrompt: protection.protectedText,
    findings: protection.findings,
    tokenMap: protection.tokenMap,
    response: llmResponse,
  });
});

app.post("/gateway/process", requireAuth, async (req, res) => {
  return processGatewayRequest(req, res, "/gateway/process");
});

app.post("/v1/generate", requireAuth, async (req, res) => {
  const prompt = req.body.prompt || "";
  const modelType = req.body.modelType || "public_llm";

  const protection = protectPrompt(prompt, {
    modelType,
    department: "Unknown",
    roles: "user",
    country: "BE",
    mfaVerified: "false",
  });

  const llmResponse = await callLlmMock(protection.protectedText, modelType);

  return res.json({
    ok: true,
    route: "/v1/generate",
    authenticated: true,
    modelType,
    decision: protection.decision,
    riskScore: protection.score,
    riskLevel: protection.riskLevel,
    originalPrompt: protection.originalText,
    protectedPrompt: protection.protectedText,
    findings: protection.findings,
    tokenMap: protection.tokenMap,
    response: llmResponse,
  });
});

app.post("/v1/gateway/process", requireAuth, async (req, res) => {
  return processGatewayRequest(req, res, "/v1/gateway/process");
});

async function processGatewayRequest(req, res, routeName) {
  const prompt = req.body.prompt || "";
  const modelType = req.body.modelType || "public_llm";
  const frameworks = req.body.frameworks || ["NIS2", "GDPR", "ISO27001"];
  const user = readUserFromHeaders(req);

  const protection = protectPrompt(prompt, {
    modelType,
    department: user.department,
    roles: user.roles,
    country: user.country,
    mfaVerified: user.mfaVerified,
  });

  if (protection.decision === "BLOCK_OR_APPROVAL") {
    return res.status(403).json({
      ok: false,
      route: routeName,
      authenticated: true,
      user,
      frameworks,
      modelType,
      decision: protection.decision,
      riskScore: protection.score,
      riskLevel: protection.riskLevel,
      originalPrompt: protection.originalText,
      protectedPrompt: protection.protectedText,
      findings: protection.findings,
      businessHits: protection.businessHits,
      tokenMap: protection.tokenMap,
      message:
        "Prompt blocked or requires approval before being sent to a public LLM.",
      grc: {
        nis2: true,
        gdpr: true,
        iso27001: true,
        auditEvent: "AI_PROMPT_SECURITY_CHECK_BLOCKED",
      },
    });
  }

  const llmResponse = await callLlmMock(protection.protectedText, modelType);

  return res.json({
    ok: true,
    route: routeName,
    authenticated: true,
    user,
    frameworks,
    modelType,
    decision: protection.decision,
    riskScore: protection.score,
    riskLevel: protection.riskLevel,
    originalPrompt: protection.originalText,
    protectedPrompt: protection.protectedText,
    findings: protection.findings,
    businessHits: protection.businessHits,
    tokenMap: protection.tokenMap,
    stats: protection.stats,
    response: llmResponse,
    grc: {
      nis2: true,
      gdpr: true,
      iso27001: true,
      auditEvent: "AI_PROMPT_SECURITY_CHECK",
    },
  });
}

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: "not_found",
    method: req.method,
    path: req.originalUrl,
    availableRoutes: [
      "GET /",
      "GET /health",
      "POST /login/keycloak",
      "POST /generate",
      "POST /gateway/process",
      "POST /v1/generate",
      "POST /v1/gateway/process",
    ],
  });
});

app.listen(PORT, () => {
  console.log(`api-gateway ready on port ${PORT}`);
  console.log(`Keycloak URL: ${KEYCLOAK_URL}`);
  console.log(`Keycloak realm: ${KEYCLOAK_REALM}`);
  console.log(`Keycloak client: ${KEYCLOAK_CLIENT_ID}`);
});