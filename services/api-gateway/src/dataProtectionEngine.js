import { encryptValue } from "./cryptoService.js";
import { DLP_PATTERNS, BUSINESS_KEYWORDS } from "./dlpPatterns.js";

export function protectPrompt(input, context = {}) {
  const originalText = String(input || "");
  let protectedText = originalText;

  const tokenMap = {};
  const findings = [];
  const counters = {};

  function nextToken(type) {
    counters[type] = (counters[type] || 0) + 1;
    return `[${type}_${String(counters[type]).padStart(3, "0")}]`;
  }

  function register(type, value, severity = "MEDIUM", frameworks = []) {
    const token = nextToken(type);

    tokenMap[token] = encryptValue(value);

    findings.push({
      type,
      token,
      severity,
      frameworks,
      originalLength: value.length,
      encrypted: true,
    });

    return token;
  }

  function replacePattern(pattern) {
    protectedText = protectedText.replace(pattern.regex, (match) => {
      return register(
        pattern.type,
        match,
        pattern.severity,
        pattern.frameworks || []
      );
    });
  }

  // =========================
  // Apply all DLP patterns
  // =========================
  for (const pattern of DLP_PATTERNS) {
    replacePattern(pattern);
  }

  // =========================
  // Business sensitive keywords
  // =========================
  const businessHits = BUSINESS_KEYWORDS.filter((kw) =>
    originalText.toLowerCase().includes(kw.toLowerCase())
  );

  // =========================
  // Scoring
  // =========================
  let score = 0;

  for (const finding of findings) {
    if (finding.severity === "LOW") score += 5;
    if (finding.severity === "MEDIUM") score += 15;
    if (finding.severity === "HIGH") score += 30;
    if (finding.severity === "CRITICAL") score += 50;
  }

  score += businessHits.length * 10;

  if (
    context.modelType === "public_llm" ||
    context.modelType === "openai" ||
    context.modelType === "chatgpt"
  ) {
    score += 10;
  }

  if (context.mfaVerified === "false" || context.mfaVerified === false) {
    score += 15;
  }

  if (["Finance", "HR", "Legal", "Security"].includes(context.department)) {
    score += 10;
  }

  if (context.country && context.country !== "BE") {
    score += 5;
  }

  score = Math.min(score, 100);

  // =========================
  // Decision
  // =========================
  let riskLevel = "LOW";
  let decision = "ALLOW";

  const hasCritical = findings.some((f) => f.severity === "CRITICAL");
  const hasHigh = findings.some((f) => f.severity === "HIGH");

  if (score >= 30 || hasHigh) {
    riskLevel = "MEDIUM";
    decision = "MASK";
  }

  if (score >= 60 || hasHigh) {
    riskLevel = "HIGH";
    decision = "MASK_OR_REVIEW";
  }

  if (score >= 85 || hasCritical) {
    riskLevel = "CRITICAL";
    decision = "BLOCK";
  }

  return {
    originalText,
    protectedText,
    tokenMap,
    findings,
    businessHits,
    score,
    riskLevel,
    decision,
    stats: {
      totalFindings: findings.length,
      tokenTypes: [...new Set(findings.map((f) => f.type))],
      encryptedTokens: true,
      frameworks: [
        ...new Set(findings.flatMap((f) => f.frameworks || [])),
      ],
    },
  };
}