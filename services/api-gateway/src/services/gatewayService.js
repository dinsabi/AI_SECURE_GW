import { protectPrompt } from "../dataProtectionEngine.js";
import { routeLLM } from "../llmRouter.js";
import { writeAuditEvent } from "../auditLogger.js";
import { secureLLMResponse } from "./responseSecurityService.js";
import {
  checkPromptInjection,
  blockPromptInjection,
} from "./promptInjectionService.js";
import { readUserFromHeaders } from "../middleware/auth.js";

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

export async function processGenerateRequest(req, res, routeName, openai) {
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

  const injection = checkPromptInjection(prompt);

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
    sensitiveDataReturnedToFrontend: false,
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
    tokenMap: protection.tokenMap,
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
    protectedPrompt: protection.protectedText,
    findings: publicFindings(protection.findings),
    businessHits: protection.businessHits,
    stats: protection.stats,
    injection,
    response: publicResponse(llmResponse),
    grc,
  });
}

export async function processGatewayRequest(req, res, routeName, openai) {
  const prompt = req.body.prompt || "";
  const modelType = req.body.modelType || "openai";
  const frameworks = req.body.frameworks || ["NIS2", "GDPR", "ISO27001"];
  const user = readUserFromHeaders(req);

  const injection = checkPromptInjection(prompt);

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
      sensitiveDataReturnedToFrontend: false,
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
      tokenMap: protection.tokenMap,
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
      protectedPrompt: protection.protectedText,
      findings: publicFindings(protection.findings),
      businessHits: protection.businessHits,
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
    sensitiveDataReturnedToFrontend: false,
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
    tokenMap: protection.tokenMap,
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
    protectedPrompt: protection.protectedText,
    findings: publicFindings(protection.findings),
    businessHits: protection.businessHits,
    stats: protection.stats,
    injection,
    response: publicResponse(llmResponse),
    grc,
  });
}