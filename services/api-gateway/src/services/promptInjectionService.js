import { analyzePromptInjection } from "../promptInjectionGuard.js";
import { writeAuditEvent } from "../auditLogger.js";

export function checkPromptInjection(text) {
  return analyzePromptInjection(text || "");
}

function injectionFindings(injection) {
  return injection.hits.map((h) => ({
    type: h.type,
    severity: h.severity,
    token: "[PROMPT_INJECTION]",
    originalLength: h.matched?.length || 0,
  }));
}

export async function blockPromptInjection({
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
    promptInjectionChecked: true,
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