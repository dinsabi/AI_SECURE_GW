import { protectPrompt } from "./dataProtectionEngine.js";

export function analyzeAIResponse(responseText, context = {}) {
  const text = String(responseText || "");

  const protection = protectPrompt(text, {
    modelType: context.modelType || "ai_response",
    department: context.department || "Unknown",
    roles: context.roles || "user",
    country: context.country || "BE",
    mfaVerified: context.mfaVerified || "false",
  });

  const riskyPatterns = [
    /ignore previous instructions/i,
    /system prompt/i,
    /private key/i,
    /password/i,
    /api[_-]?key/i,
    /bearer\s+[a-z0-9._-]+/i,
    /jwt/i,
    /internal architecture/i,
    /confidential/i,
  ];

  const responsePolicyHits = riskyPatterns
    .filter((regex) => regex.test(text))
    .map((regex) => regex.toString());

  let responseDecision = "ALLOW_RESPONSE";

  if (protection.score >= 60 || responsePolicyHits.length > 0) {
    responseDecision = "MASK_RESPONSE";
  }

  if (protection.score >= 85) {
    responseDecision = "BLOCK_RESPONSE_OR_REVIEW";
  }

  return {
    originalResponse: text,
    protectedResponse: protection.protectedText,
    responseDecision,
    responseRiskScore: protection.score,
    responseRiskLevel: protection.riskLevel,
    responseFindings: protection.findings,
    responseBusinessHits: protection.businessHits,
    responseTokenMap: protection.tokenMap,
    responsePolicyHits,
    responseStats: protection.stats,
  };
}