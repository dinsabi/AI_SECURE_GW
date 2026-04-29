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

  function register(type, value, severity = "MEDIUM") {
    const token = nextToken(type);
    tokenMap[token] = value;
    findings.push({
      type,
      token,
      severity,
      originalLength: value.length,
    });
    return token;
  }

  function replacePattern(type, regex, severity = "MEDIUM") {
    protectedText = protectedText.replace(regex, (match) => {
      return register(type, match, severity);
    });
  }

  // =========================
  // PII / GDPR
  // =========================
  replacePattern(
    "EMAIL",
    /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,
    "HIGH"
  );

  replacePattern(
    "PHONE",
    /(?:\+32|0032|0)\s?[1-9](?:[\s.-]?\d{2}){3,4}/g,
    "MEDIUM"
  );

  replacePattern(
    "NATIONAL_ID_BE",
    /\b\d{2}[.\s-]?\d{2}[.\s-]?\d{2}[.\s-]?\d{3}[.\s-]?\d{2}\b/g,
    "HIGH"
  );

  replacePattern(
    "DATE",
    /\b(?:\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4})\b/g,
    "LOW"
  );

  // Nom simple après mots déclencheurs
  replacePattern(
    "PERSON",
    /\b(?:Monsieur|Madame|Mr|Mrs|Mme|M\.|Client|Utilisateur)\s+[A-ZÀ-Ÿ][a-zà-ÿ'-]+(?:\s+[A-ZÀ-Ÿ][a-zà-ÿ'-]+)?\b/g,
    "MEDIUM"
  );

  // =========================
  // Financial
  // =========================
  replacePattern(
    "IBAN",
    /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}\b/g,
    "HIGH"
  );

  replacePattern(
    "VAT",
    /\b(?:BE|FR|NL|DE|LU)\s?\d{9,12}\b/gi,
    "MEDIUM"
  );

  replacePattern(
    "CREDIT_CARD",
    /\b(?:\d[ -]*?){13,19}\b/g,
    "CRITICAL"
  );

  // =========================
  // Secrets / Credentials
  // =========================
  replacePattern(
    "API_KEY",
    /\b(?:sk-[A-Za-z0-9]{20,}|pk-[A-Za-z0-9]{20,}|api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{12,})\b/gi,
    "CRITICAL"
  );

  replacePattern(
    "JWT",
    /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
    "CRITICAL"
  );

  replacePattern(
    "PASSWORD",
    /\b(?:password|passwd|pwd|motdepasse|secret)\s*[:=]\s*[^\s,;]+/gi,
    "CRITICAL"
  );

  replacePattern(
    "PRIVATE_KEY",
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    "CRITICAL"
  );

  replacePattern(
    "CONNECTION_STRING",
    /\b(?:mongodb|postgres|postgresql|mysql|redis):\/\/[^\s]+/gi,
    "CRITICAL"
  );

  // =========================
  // Technical Infrastructure
  // =========================
  replacePattern(
    "PRIVATE_IP",
    /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b/g,
    "HIGH"
  );

  replacePattern(
    "HOSTNAME",
    /\b[a-zA-Z0-9-]+(?:\.internal|\.local|\.corp|\.lan)\b/g,
    "MEDIUM"
  );

  replacePattern(
    "INTERNAL_URL",
    /\bhttps?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|[a-zA-Z0-9.-]+\.internal)[^\s]*/gi,
    "HIGH"
  );

  // =========================
  // Business sensitive keywords
  // =========================
  const businessKeywords = [
    "confidentiel",
    "contrat",
    "salaire",
    "salary",
    "licenciement",
    "client stratégique",
    "offre commerciale",
    "appel d'offre",
    "architecture interne",
    "incident sécurité",
    "vulnérabilité",
    "audit",
    "NIS2",
    "ISO27001",
  ];

  const businessHits = businessKeywords.filter((kw) =>
    originalText.toLowerCase().includes(kw.toLowerCase())
  );

  // =========================
  // Scoring dynamique
  // =========================
  let score = 0;

  for (const finding of findings) {
    if (finding.severity === "LOW") score += 5;
    if (finding.severity === "MEDIUM") score += 15;
    if (finding.severity === "HIGH") score += 30;
    if (finding.severity === "CRITICAL") score += 50;
  }

  score += businessHits.length * 10;

  if (context.modelType === "public_llm") score += 15;
  if (context.mfaVerified === "false" || context.mfaVerified === false) score += 15;
  if (["Finance", "HR", "Legal", "Security"].includes(context.department)) score += 10;
  if (context.country && context.country !== "BE") score += 5;

  score = Math.min(score, 100);

  let riskLevel = "LOW";
  let decision = "ALLOW";

  if (score >= 30) {
    riskLevel = "MEDIUM";
    decision = "MASK";
  }

  if (score >= 60) {
    riskLevel = "HIGH";
    decision = "MASK_OR_REVIEW";
  }

  if (score >= 85) {
    riskLevel = "CRITICAL";
    decision = "BLOCK_OR_APPROVAL";
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
    },
  };
}