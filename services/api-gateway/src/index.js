import OpenAI from "openai";
import express from "express";
import cors from "cors";
import multer from "multer";

import { protectPrompt } from "./dataProtectionEngine.js";
import { protectUploadedFile } from "./fileProtectionEngine.js";
import { analyzeAIResponse } from "./responseAnalyzer.js";
import { analyzePromptInjection } from "./promptInjectionGuard.js";
import { initDatabase } from "./db.js";
import { writeAuditEvent, getRiskSummary } from "./auditLogger.js";
import { routeLLM } from "./llmRouter.js";

const app = express();

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024,
  },
});

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

app.use(express.json({ limit: "2mb" }));

const PORT = process.env.PORT || 3000;

const KEYCLOAK_URL = process.env.KEYCLOAK_URL || "http://keycloak:8080";
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || "aigw";
const KEYCLOAK_CLIENT_ID =
  process.env.KEYCLOAK_CLIENT_ID || "ai-secure-gateway";
const KEYCLOAK_CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET || "";
const OPENAI_MODEL = process.env.OPENAI_MODEL || "gpt-4o-mini";

const availableRoutes = [
  "GET /",
  "GET /health",
  "POST /login/keycloak",
  "POST /generate",
  "POST /gateway/process",
  "POST /v1/generate",
  "POST /v1/gateway/process",
  "POST /v1/files/analyze",
  "GET /v1/dashboard/risk-summary",
];

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

function secureLLMResponse(llmResponse, user, modelType) {
  const answer = llmResponse?.answer || "";

  const analysis = analyzeAIResponse(answer, {
    modelType,
    department: user?.department || "Unknown",
    roles: user?.roles || "user",
    country: user?.country || "BE",
    mfaVerified: user?.mfaVerified || "false",
  });

  return {
    ...llmResponse,
    originalAnswer: analysis.originalResponse,
    answer:
      analysis.responseDecision === "BLOCK_RESPONSE_OR_REVIEW"
        ? "The AI response was blocked by AI Secure Gateway because it may contain sensitive information."
        : analysis.protectedResponse,
    responseSecurity: {
      decision: analysis.responseDecision,
      riskScore: analysis.responseRiskScore,
      riskLevel: analysis.responseRiskLevel,
      findings: analysis.responseFindings,
      businessHits: analysis.responseBusinessHits,
      policyHits: analysis.responsePolicyHits,
      tokenMap: analysis.responseTokenMap,
      stats: analysis.responseStats,
    },
  };
}

function injectionFindings(injection) {
  return injection.hits.map((h) => ({
    type: h.type,
    severity: h.severity,
    token: "[PROMPT_INJECTION]",
    originalLength: h.matched?.length || 0,
  }));
}

async function blockPromptInjection({
  res,
  route,
  user,
  frameworks,
  modelType,
  injection,
  originalPrompt,
  isFile = false,
  file = null,
}) {
  const grc = {
    nis2: true,
    gdpr: true,
    iso27001: true,
    auditEvent: isFile
      ? "AI_FILE_PROMPT_INJECTION_BLOCKED"
      : "AI_PROMPT_INJECTION_BLOCKED",
    responseAnalyzed: false,
  };

  await writeAuditEvent({
    eventType: grc.auditEvent,
    route,
    user,
    modelType,
    provider: "gateway-policy",
    frameworks,
    decision: "BLOCK",
    riskScore: injection.score,
    riskLevel: injection.riskLevel,
    findings: injectionFindings(injection),
    businessHits: [],
    originalPrompt,
    protectedPrompt: isFile
      ? "[BLOCKED_FILE_PROMPT_INJECTION]"
      : "[BLOCKED_PROMPT_INJECTION]",
    file,
    grc,
  });

  return res.status(403).json({
    ok: false,
    route,
    authenticated: true,
    user,
    frameworks,
    file,
    modelType,
    decision: "BLOCK",
    riskScore: injection.score,
    riskLevel: injection.riskLevel,
    injection,
    message: isFile
      ? "Uploaded file blocked by AI Secure Gateway because a prompt injection attempt was detected."
      : "Prompt blocked by AI Secure Gateway because a prompt injection attempt was detected.",
    grc,
  });
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "api-gateway",
    message: "AI Secure Gateway API",
    availableRoutes,
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
    openai: {
      configured: Boolean(process.env.OPENAI_API_KEY),
      model: OPENAI_MODEL,
    },
    audit: {
      postgres: true,
    },
    llmRouter: {
      enabled: true,
      supportedProviders: ["openai", "chatgpt", "mock", "public_llm"],
    },
    promptInjectionProtection: {
      enabled: true,
    },
    availableRoutes,
  });
});

app.get("/v1/dashboard/risk-summary", requireAuth, async (req, res) => {
  try {
    const data = await getRiskSummary();

    return res.json({
      ok: true,
      route: "/v1/dashboard/risk-summary",
      ...data,
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      error: "risk_summary_failed",
      message: error.message,
    });
  }
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
  return processGenerateRequest(req, res, "/generate");
});

app.post("/v1/generate", requireAuth, async (req, res) => {
  return processGenerateRequest(req, res, "/v1/generate");
});

app.post("/gateway/process", requireAuth, async (req, res) => {
  return processGatewayRequest(req, res, "/gateway/process");
});

app.post("/v1/gateway/process", requireAuth, async (req, res) => {
  return processGatewayRequest(req, res, "/v1/gateway/process");
});

app.post(
  "/v1/files/analyze",
  requireAuth,
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          ok: false,
          error: "missing_file",
          message: "No file uploaded. Use form-data field name: file",
        });
      }

      const modelType = req.body.modelType || "openai";
      const frameworks = req.body.frameworks
        ? String(req.body.frameworks).split(",").map((x) => x.trim())
        : ["NIS2", "GDPR", "ISO27001"];

      const user = readUserFromHeaders(req);

      const result = await protectUploadedFile(req.file, {
        modelType,
        department: user.department,
        roles: user.roles,
        country: user.country,
        mfaVerified: user.mfaVerified,
      });

      const fileInfo = {
        name: result.fileName,
        mimeType: result.mimeType,
        size: result.size,
        extractedTextLength: result.extractedTextLength,
      };

      const injection = analyzePromptInjection(result.originalText || "");

      if (injection.decision === "BLOCK") {
        return blockPromptInjection({
          res,
          route: "/v1/files/analyze",
          user,
          frameworks,
          modelType,
          injection,
          originalPrompt: result.originalText,
          isFile: true,
          file: fileInfo,
        });
      }

      const rawLlmResponse =
        result.decision === "BLOCK"
          ? {
              provider: "gateway-policy",
              routedTo: "none",
              routingDecision: "BLOCKED_BY_POLICY",
              answer:
                "File blocked by AI Secure Gateway policy and was not sent to any LLM.",
            }
          : await routeLLM({
              openai,
              prompt: result.protectedText,
              modelType,
              user,
              protection: {
                riskLevel: result.riskLevel,
                score: result.riskScore,
                decision: result.decision,
              },
            });

      const llmResponse = secureLLMResponse(rawLlmResponse, user, modelType);

      const grc = {
        nis2: true,
        gdpr: true,
        iso27001: true,
        auditEvent: "AI_FILE_SECURITY_CHECK",
        responseAnalyzed: true,
        promptInjectionChecked: true,
      };

      await writeAuditEvent({
        eventType: "AI_FILE_SECURITY_CHECK",
        route: "/v1/files/analyze",
        user,
        modelType,
        provider: llmResponse.provider,
        frameworks,
        decision: result.decision,
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        findings: result.findings,
        businessHits: result.businessHits,
        originalText: result.originalText,
        protectedText: result.protectedText,
        originalResponse: llmResponse.originalAnswer,
        protectedResponse: llmResponse.answer,
        responseDecision: llmResponse.responseSecurity?.decision,
        responseRiskScore: llmResponse.responseSecurity?.riskScore,
        responseRiskLevel: llmResponse.responseSecurity?.riskLevel,
        file: fileInfo,
        grc,
      });

      return res.json({
        ok: true,
        route: "/v1/files/analyze",
        authenticated: true,
        user,
        frameworks,
        file: fileInfo,
        modelType,
        decision: result.decision,
        riskScore: result.riskScore,
        riskLevel: result.riskLevel,
        originalText: result.originalText,
        protectedText: result.protectedText,
        findings: result.findings,
        businessHits: result.businessHits,
        tokenMap: result.tokenMap,
        stats: result.stats,
        injection,
        response: llmResponse,
        grc,
      });
    } catch (error) {
      return res.status(500).json({
        ok: false,
        error: "file_analysis_failed",
        message: error.message,
      });
    }
  }
);

async function processGenerateRequest(req, res, routeName) {
  const prompt = req.body.prompt || "";
  const modelType = req.body.modelType || "openai";
  const frameworks = ["NIS2", "GDPR", "ISO27001"];

  const user = {
    email: "unknown",
    department: "Unknown",
    roles: "user",
    country: "BE",
    mfaVerified: "false",
  };

  const injection = analyzePromptInjection(prompt);

  if (injection.decision === "BLOCK") {
    return blockPromptInjection({
      res,
      route: routeName,
      user,
      frameworks,
      modelType,
      injection,
      originalPrompt: prompt,
    });
  }

  const protection = protectPrompt(prompt, {
    modelType,
    department: user.department,
    roles: user.roles,
    country: user.country,
    mfaVerified: user.mfaVerified,
  });

  const rawLlmResponse =
    protection.decision === "BLOCK"
      ? {
          provider: "gateway-policy",
          routedTo: "none",
          routingDecision: "BLOCKED_BY_POLICY",
          answer:
            "Prompt blocked by AI Secure Gateway policy and was not sent to any LLM.",
        }
      : await routeLLM({
          openai,
          prompt: protection.protectedText,
          modelType,
          user,
          protection,
        });

  const llmResponse = secureLLMResponse(rawLlmResponse, user, modelType);

  const grc = {
    nis2: true,
    gdpr: true,
    iso27001: true,
    auditEvent: "AI_PROMPT_SECURITY_CHECK",
    responseAnalyzed: true,
    promptInjectionChecked: true,
  };

  await writeAuditEvent({
    eventType: "AI_PROMPT_SECURITY_CHECK",
    route: routeName,
    user,
    modelType,
    provider: llmResponse.provider,
    frameworks,
    decision: protection.decision,
    riskScore: protection.score,
    riskLevel: protection.riskLevel,
    findings: protection.findings,
    businessHits: protection.businessHits,
    originalPrompt: protection.originalText,
    protectedPrompt: protection.protectedText,
    originalResponse: llmResponse.originalAnswer,
    protectedResponse: llmResponse.answer,
    responseDecision: llmResponse.responseSecurity?.decision,
    responseRiskScore: llmResponse.responseSecurity?.riskScore,
    responseRiskLevel: llmResponse.responseSecurity?.riskLevel,
    grc,
  });

  return res.json({
    ok: true,
    route: routeName,
    authenticated: true,
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
    injection,
    response: llmResponse,
    grc,
  });
}

async function processGatewayRequest(req, res, routeName) {
  const prompt = req.body.prompt || "";
  const modelType = req.body.modelType || "openai";
  const frameworks = req.body.frameworks || ["NIS2", "GDPR", "ISO27001"];
  const user = readUserFromHeaders(req);

  const injection = analyzePromptInjection(prompt);

  if (injection.decision === "BLOCK") {
    return blockPromptInjection({
      res,
      route: routeName,
      user,
      frameworks,
      modelType,
      injection,
      originalPrompt: prompt,
    });
  }

  const protection = protectPrompt(prompt, {
    modelType,
    department: user.department,
    roles: user.roles,
    country: user.country,
    mfaVerified: user.mfaVerified,
  });

  if (protection.decision === "BLOCK") {
    const grc = {
      nis2: true,
      gdpr: true,
      iso27001: true,
      auditEvent: "AI_PROMPT_SECURITY_CHECK_BLOCKED",
      responseAnalyzed: false,
      promptInjectionChecked: true,
    };

    await writeAuditEvent({
      eventType: "AI_PROMPT_SECURITY_CHECK_BLOCKED",
      route: routeName,
      user,
      modelType,
      provider: "gateway-policy",
      frameworks,
      decision: protection.decision,
      riskScore: protection.score,
      riskLevel: protection.riskLevel,
      findings: protection.findings,
      businessHits: protection.businessHits,
      originalPrompt: protection.originalText,
      protectedPrompt: protection.protectedText,
      grc,
    });

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
      injection,
      message:
        "Prompt blocked by AI Secure Gateway policy and was not sent to any LLM.",
      grc,
    });
  }

  const rawLlmResponse = await routeLLM({
    openai,
    prompt: protection.protectedText,
    modelType,
    user,
    protection,
  });

  const llmResponse = secureLLMResponse(rawLlmResponse, user, modelType);

  const grc = {
    nis2: true,
    gdpr: true,
    iso27001: true,
    auditEvent: "AI_PROMPT_SECURITY_CHECK",
    responseAnalyzed: true,
    promptInjectionChecked: true,
  };

  await writeAuditEvent({
    eventType: "AI_PROMPT_SECURITY_CHECK",
    route: routeName,
    user,
    modelType,
    provider: llmResponse.provider,
    frameworks,
    decision: protection.decision,
    riskScore: protection.score,
    riskLevel: protection.riskLevel,
    findings: protection.findings,
    businessHits: protection.businessHits,
    originalPrompt: protection.originalText,
    protectedPrompt: protection.protectedText,
    originalResponse: llmResponse.originalAnswer,
    protectedResponse: llmResponse.answer,
    responseDecision: llmResponse.responseSecurity?.decision,
    responseRiskScore: llmResponse.responseSecurity?.riskScore,
    responseRiskLevel: llmResponse.responseSecurity?.riskLevel,
    grc,
  });

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
    injection,
    response: llmResponse,
    grc,
  });
}

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: "not_found",
    method: req.method,
    path: req.originalUrl,
    availableRoutes,
  });
});

initDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`api-gateway ready on port ${PORT}`);
      console.log(`Keycloak URL: ${KEYCLOAK_URL}`);
      console.log(`Keycloak realm: ${KEYCLOAK_REALM}`);
      console.log(`Keycloak client: ${KEYCLOAK_CLIENT_ID}`);
      console.log(`OpenAI configured: ${Boolean(process.env.OPENAI_API_KEY)}`);
      console.log(`OpenAI model: ${OPENAI_MODEL}`);
      console.log("PostgreSQL audit database initialized");
      console.log("Multi-LLM Router enabled");
      console.log("Prompt Injection Protection enabled");
    });
  })
  .catch((error) => {
    console.error("Failed to initialize PostgreSQL audit database", error);
    process.exit(1);
  });