import { analyzeAIResponse } from "../responseAnalyzer.js";

export function secureLLMResponse(llmResponse, user, modelType) {
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