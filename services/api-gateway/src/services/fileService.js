import multer from "multer";

import { protectUploadedFile } from "../fileProtectionEngine.js";
import { routeLLM } from "../llmRouter.js";
import { writeAuditEvent } from "../auditLogger.js";
import { readUserFromHeaders } from "../middleware/auth.js";
import { secureLLMResponse } from "./responseSecurityService.js";
import {
  checkPromptInjection,
  blockPromptInjection,
} from "./promptInjectionService.js";

export const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024,
  },
});

function publicFindings(findings = []) {
  return findings.map((f) => ({
    type: f.type,
    token: f.token,
    severity: f.severity,
    originalLength: f.originalLength,
    encrypted: Boolean(f.encrypted),
  }));
}

function publicResponse(llmResponse = {}) {
  return {
    provider: llmResponse.provider,
    routedTo: llmResponse.routedTo,
    routingDecision: llmResponse.routingDecision,
    model: llmResponse.model,
    answer: llmResponse.answer,
    error: llmResponse.error,
    message: llmResponse.message,
    responseSecurity: llmResponse.responseSecurity,
  };
}

export async function processFileAnalyzeRequest(req, res, openai) {
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

    const injection = checkPromptInjection(result.originalText || "");

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
      sensitiveDataReturnedToFrontend: false,
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
      tokenMap: result.tokenMap,
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
      protectedText: result.protectedText,
      findings: publicFindings(result.findings),
      businessHits: result.businessHits,
      stats: result.stats,
      injection,
      response: publicResponse(llmResponse),
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