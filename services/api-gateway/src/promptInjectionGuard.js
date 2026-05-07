export function analyzePromptInjection(input = "") {
  const text = String(input || "");
  const lower = text.toLowerCase();

  const patterns = [
    {
      type: "IGNORE_INSTRUCTIONS",
      severity: "CRITICAL",
      regex: /ignore (all )?(previous|prior|above) instructions/i,
    },
    {
      type: "SYSTEM_PROMPT_EXTRACTION",
      severity: "CRITICAL",
      regex: /(show|reveal|print|display|dump).{0,40}(system prompt|hidden prompt|developer message|internal instructions)/i,
    },
    {
      type: "ROLE_OVERRIDE",
      severity: "HIGH",
      regex: /(you are now|act as|pretend to be).{0,50}(admin|root|developer|system|security officer)/i,
    },
    {
      type: "JAILBREAK",
      severity: "HIGH",
      regex: /(jailbreak|dan mode|developer mode|god mode|unrestricted mode)/i,
    },
    {
      type: "POLICY_BYPASS",
      severity: "HIGH",
      regex: /(bypass|disable|ignore).{0,40}(policy|safety|security|filter|guardrail|restriction)/i,
    },
    {
      type: "SECRET_EXFILTRATION",
      severity: "CRITICAL",
      regex: /(extract|exfiltrate|leak|steal|dump).{0,40}(secret|password|api key|token|credential|private key)/i,
    },
    {
      type: "ENCODED_BYPASS",
      severity: "MEDIUM",
      regex: /(base64|rot13|hex encode|obfuscate|encoded instruction)/i,
    },
    {
      type: "DATA_EXFILTRATION",
      severity: "HIGH",
      regex: /(send|post|upload|exfiltrate).{0,60}(data|file|database|customer list|credentials).{0,60}(external|webhook|url|http)/i,
    },
  ];

  const hits = [];

  for (const rule of patterns) {
    const match = text.match(rule.regex);
    if (match) {
      hits.push({
        type: rule.type,
        severity: rule.severity,
        matched: match[0].slice(0, 160),
      });
    }
  }

  let score = 0;

  for (const hit of hits) {
    if (hit.severity === "MEDIUM") score += 20;
    if (hit.severity === "HIGH") score += 40;
    if (hit.severity === "CRITICAL") score += 60;
  }

  if (lower.includes("ignore") && lower.includes("instructions")) score += 20;
  if (lower.includes("system") && lower.includes("prompt")) score += 20;

  score = Math.min(score, 100);

  let riskLevel = "LOW";
  let decision = "ALLOW";

  if (score >= 30) {
    riskLevel = "MEDIUM";
    decision = "REVIEW";
  }

  if (score >= 60) {
    riskLevel = "HIGH";
    decision = "BLOCK";
  }

  if (score >= 85) {
    riskLevel = "CRITICAL";
    decision = "BLOCK";
  }

  return {
    detected: hits.length > 0,
    score,
    riskLevel,
    decision,
    hits,
  };
}