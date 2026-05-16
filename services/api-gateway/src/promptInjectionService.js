import { checkPromptInjection } from "./promptInjectionGuard.js";
import { writeAuditEvent } from "../auditLogger.js";

export { checkPromptInjection };

export async function blockPromptInjection({
  res,
  route,
  user,
  frameworks = ["NIS2", "GDPR", "ISO27001"],
  modelType = "openai",
  injection,
  originalPrompt = "",
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
    sensitiveDataReturnedToFrontend: false,
  };

  await writeAuditEvent({
    eventType: grc.auditEvent,
    route,
    user,
    modelType,
    provider: "gateway-policy",
    frameworks,
    decision: "BLOCK",
    riskScore: injection?.score || 100,
    riskLevel: injection?.riskLevel || "CRITICAL",
    findings: [],
    businessHits: [],
    originalPrompt: isFile ? undefined : originalPrompt,
    originalText: isFile ? originalPrompt : undefined,
    protectedPrompt: undefined,
    protectedText: undefined,
    injection,
    file,
    grc,
  });

  return res.status(403).json({
    ok: false,
    route,
    authenticated: true,
    user,
    frameworks,
    modelType,
    decision: "BLOCK",
    riskScore: injection?.score || 100,
    riskLevel: injection?.riskLevel || "CRITICAL",
    protectedPrompt: "",
    findings: [],
    businessHits: [],
    injection,
    message:
      "Prompt blocked by AI Prompt Firewall. Possible prompt injection, jailbreak or data exfiltration attempt detected.",
    grc,
  });
}