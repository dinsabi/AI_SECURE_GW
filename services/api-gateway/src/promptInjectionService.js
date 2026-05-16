import { checkPromptInjection as runPromptInjectionCheck } from "../promptInjectionGuard.js";

export function analyzePromptInjection(text = "") {
  return runPromptInjectionCheck(text || "");
}

export function checkInjection(text = "") {
  return runPromptInjectionCheck(text || "");
}

export async function blockPromptInjection({
  res,
  route,
  user,
  frameworks = ["NIS2", "GDPR", "ISO27001"],
  modelType = "mock",
  injection,
  originalPrompt = "",
}) {
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
    grc: {
      nis2: true,
      gdpr: true,
      iso27001: true,
      auditEvent: "AI_PROMPT_INJECTION_BLOCKED",
      responseAnalyzed: false,
      promptInjectionChecked: true,
    },
    originalPrompt,
  });
}