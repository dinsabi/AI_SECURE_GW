const PROMPT_INJECTION_RULES = [
  {
    id: "IGNORE_PREVIOUS_INSTRUCTIONS",
    type: "PROMPT_INJECTION",
    severity: "CRITICAL",
    score: 40,
    pattern: /\b(ignore|forget|disregard|bypass|override)\b.{0,40}\b(previous|above|prior|system|developer)\b.{0,40}\b(instructions?|rules?|prompt|policy)\b/i,
    description: "Attempt to ignore or override previous/system instructions.",
  },
  {
    id: "SYSTEM_PROMPT_EXTRACTION",
    type: "SYSTEM_PROMPT_LEAK",
    severity: "CRITICAL",
    score: 40,
    pattern: /\b(show|reveal|print|display|expose|tell me|dump)\b.{0,50}\b(system prompt|developer prompt|hidden prompt|initial instructions|internal instructions)\b/i,
    description: "Attempt to reveal hidden/system/developer instructions.",
  },
  {
    id: "ROLE_OVERRIDE",
    type: "ROLE_OVERRIDE",
    severity: "HIGH",
    score: 30,
    pattern: /\b(you are now|act as|pretend to be|switch role|become)\b.{0,60}\b(admin|root|developer|system|security bypass|unrestricted|dan)\b/i,
    description: "Attempt to override the assistant role or privileges.",
  },
  {
    id: "JAILBREAK_DAN",
    type: "JAILBREAK",
    severity: "CRITICAL",
    score: 45,
    pattern: /\b(DAN|do anything now|jailbreak|unfiltered mode|developer mode|no restrictions|uncensored)\b/i,
    description: "Known jailbreak pattern detected.",
  },
  {
    id: "POLICY_BYPASS",
    type: "POLICY_BYPASS",
    severity: "HIGH",
    score: 30,
    pattern: /\b(disable|turn off|bypass|ignore)\b.{0,50}\b(safety|guardrails|policy|filters?|moderation|security controls?)\b/i,
    description: "Attempt to bypass safety, policy or security controls.",
  },
  {
    id: "DATA_EXFILTRATION",
    type: "DATA_EXFILTRATION",
    severity: "CRITICAL",
    score: 45,
    pattern: /\b(export|extract|exfiltrate|dump|send|list all|retrieve all)\b.{0,60}\b(secrets?|tokens?|passwords?|api keys?|credentials?|private keys?|customer data|database)\b/i,
    description: "Possible attempt to extract sensitive data.",
  },
  {
    id: "SECRET_DISCOVERY",
    type: "SECRET_DISCOVERY",
    severity: "CRITICAL",
    score: 40,
    pattern: /\b(find|search|scan|locate|discover)\b.{0,60}\b(secrets?|api keys?|tokens?|passwords?|private keys?|credentials?)\b/i,
    description: "Attempt to discover secrets or credentials.",
  },
  {
    id: "ENCODED_INSTRUCTION",
    type: "HIDDEN_INSTRUCTION",
    severity: "MEDIUM",
    score: 20,
    pattern: /\b(base64|rot13|hex encoded|encoded message|decode this|hidden instruction|invisible instruction)\b/i,
    description: "Possible hidden or encoded instruction attempt.",
  },
];

function normalizeSeverity(score) {
  if (score >= 80) return "CRITICAL";
  if (score >= 55) return "HIGH";
  if (score >= 25) return "MEDIUM";
  return "LOW";
}

function decisionFromScore(score, hits = []) {
  const hasCritical = hits.some((hit) => hit.severity === "CRITICAL");

  if (score >= 80 || hasCritical) return "BLOCK";
  if (score >= 55) return "REVIEW";
  if (score >= 25) return "WARN";
  return "ALLOW";
}

export function checkPromptInjection(input = "") {
  const text = String(input || "");
  const hits = [];

  for (const rule of PROMPT_INJECTION_RULES) {
    if (rule.pattern.test(text)) {
      hits.push({
        id: rule.id,
        type: rule.type,
        severity: rule.severity,
        score: rule.score,
        description: rule.description,
      });
    }
  }

  const score = Math.min(
    100,
    hits.reduce((total, hit) => total + hit.score, 0)
  );

  return {
    detected: hits.length > 0,
    score,
    riskLevel: normalizeSeverity(score),
    decision: decisionFromScore(score, hits),
    hits,
    stats: {
      totalHits: hits.length,
      types: [...new Set(hits.map((hit) => hit.type))],
    },
  };
}

export const analyzePromptInjection = checkPromptInjection;
