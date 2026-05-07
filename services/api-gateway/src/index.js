import OpenAI from "openai";
import express from "express";
import cors from "cors";
import multer from "multer";

import { protectPrompt } from "./dataProtectionEngine.js";
import { protectUploadedFile } from "./fileProtectionEngine.js";

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

async function callOpenAI(prompt) {
  if (!process.env.OPENAI_API_KEY) {
    return {
      provider: "openai",
      error: true,
      message: "OPENAI_API_KEY is missing in .env or docker-compose environment.",
    };
  }

  try {
    const completion = await openai.chat.completions.create({
      model: OPENAI_MODEL,
      messages: [
        {
          role: "system",
          content:
            "You are a secure enterprise AI assistant operating behind an AI Secure Gateway. You are compliant with NIS2, ISO27001 and GDPR. You must never reconstruct, infer, or reveal masked sensitive data. Work only with protected/tokenized content.",
        },
        {
          role: "user",
          content: prompt,
        },
      ],
      temperature: 0.2,
    });

    return {
      provider: "openai",
      model: completion.model,
      answer: completion.choices?.[0]?.message?.content || "",
      usage: completion.usage,
    };
  } catch (error) {
    return {
      provider: "openai",
      error: true,
      message: error.message,
    };
  }
}

async function callSelectedLLM(prompt, modelType) {
  if (modelType === "openai" || modelType === "chatgpt") {
    return callOpenAI(prompt);
  }

  return callLlmMock(prompt, modelType);
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
    availableRoutes,
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

      const llmResponse =
        result.decision === "BLOCK"
          ? {
              provider: "gateway-policy",
              answer:
                "File blocked by AI Secure Gateway policy and was not sent to OpenAI.",
            }
          : await callSelectedLLM(result.protectedText, modelType);

      return res.json({
        ok: true,
        route: "/v1/files/analyze",
        authenticated: true,
        user,
        frameworks,
        file: {
          name: result.fileName,
          mimeType: result.mimeType,
          size: result.size,
          extractedTextLength: result.extractedTextLength,
        },
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
        response: llmResponse,
        grc: {
          nis2: true,
          gdpr: true,
          iso27001: true,
          auditEvent: "AI_FILE_SECURITY_CHECK",
        },
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

  const protection = protectPrompt(prompt, {
    modelType,
    department: "Unknown",
    roles: "user",
    country: "BE",
    mfaVerified: "false",
  });

  const llmResponse =
    protection.decision === "BLOCK"
      ? {
          provider: "gateway-policy",
          answer:
            "Prompt blocked by AI Secure Gateway policy and was not sent to OpenAI.",
        }
      : await callSelectedLLM(protection.protectedText, modelType);

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
    response: llmResponse,
  });
}

async function processGatewayRequest(req, res, routeName) {
  const prompt = req.body.prompt || "";
  const modelType = req.body.modelType || "openai";
  const frameworks = req.body.frameworks || ["NIS2", "GDPR", "ISO27001"];
  const user = readUserFromHeaders(req);

  const protection = protectPrompt(prompt, {
    modelType,
    department: user.department,
    roles: user.roles,
    country: user.country,
    mfaVerified: user.mfaVerified,
  });

  if (protection.decision === "BLOCK") {
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
        "Prompt blocked by AI Secure Gateway policy and was not sent to OpenAI.",
      grc: {
        nis2: true,
        gdpr: true,
        iso27001: true,
        auditEvent: "AI_PROMPT_SECURITY_CHECK_BLOCKED",
      },
    });
  }

  const llmResponse = await callSelectedLLM(protection.protectedText, modelType);

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
    availableRoutes,
  });
});

app.listen(PORT, () => {
  console.log(`api-gateway ready on port ${PORT}`);
  console.log(`Keycloak URL: ${KEYCLOAK_URL}`);
  console.log(`Keycloak realm: ${KEYCLOAK_REALM}`);
  console.log(`Keycloak client: ${KEYCLOAK_CLIENT_ID}`);
  console.log(`OpenAI configured: ${Boolean(process.env.OPENAI_API_KEY)}`);
  console.log(`OpenAI model: ${OPENAI_MODEL}`);
});