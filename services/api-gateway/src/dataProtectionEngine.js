import { encryptValue } from "./cryptoService.js";

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

    tokenMap[token] = encryptValue(value);

    findings.push({
      type,
      token,
      severity,
      originalLength: value.length,
      encrypted: true,
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
    "DATE_OF_BIRTH",
    /\b(?:né le|née le|date de naissance|dob)\s*[:\-]?\s*\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}\b/gi,
    "HIGH"
  );

  replacePattern(
    "DATE",
    /\b\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}\b/g,
    "LOW"
  );

  replacePattern(
    "PASSPORT_NUMBER",
    /\b(?:passport|passeport)\s*[:\-]?\s*[A-Z0-9]{6,12}\b/gi,
    "HIGH"
  );

  replacePattern(
    "DRIVING_LICENSE",
    /\b(?:permis|driving licence|driver license)\s*[:\-]?\s*[A-Z0-9\-]{6,15}\b/gi,
    "HIGH"
  );

  replacePattern(
    "LICENSE_PLATE",
    /\b(?:[A-Z]{1,3}[-\s]?\d{3}[-\s]?[A-Z]{0,3}|\d[-\s]?[A-Z]{3}[-\s]?\d{3})\b/g,
    "MEDIUM"
  );

  replacePattern(
    "PERSON",
    /\b(?:Monsieur|Madame|Mr|Mrs|Mme|M\.|Client|Utilisateur)\s+[A-ZÀ-Ÿ][a-zà-ÿ'-]+(?:\s+[A-ZÀ-Ÿ][a-zà-ÿ'-]+)?\b/g,
    "MEDIUM"
  );

  replacePattern(
    "ADDRESS",
    /\b\d{1,4}\s+(?:rue|avenue|boulevard|chaussée|straat|laan|street|avenue|road)\s+[A-ZÀ-Ÿa-zà-ÿ0-9\s'-]{3,80}\b/gi,
    "HIGH"
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

  replacePattern(
    "SALARY",
    /\b(?:salaire|salary|rémunération)\s*[:\-]?\s*\d{2,7}(?:[,.]\d{2})?\s*(?:€|EUR|euros)?\b/gi,
    "HIGH"
  );

  replacePattern(
    "REVENUE",
    /\b(?:chiffre d'affaires|revenu|revenue|turnover)\s*[:\-]?\s*\d{3,12}(?:[,.]\d{2})?\s*(?:€|EUR|euros|k€|m€)?\b/gi,
    "HIGH"
  );

  replacePattern(
    "MARGIN",
    /\b(?:marge|margin)\s*[:\-]?\s*\d{1,3}(?:[,.]\d{1,2})?\s*%?\b/gi,
    "HIGH"
  );

  // =========================
  // Secrets / Credentials
  // =========================

  replacePattern(
    "API_KEY",
    /\b(?:sk-[A-Za-z0-9_-]{20,}|sk-proj-[A-Za-z0-9_-]{20,}|pk-[A-Za-z0-9_-]{20,}|api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{12,})\b/gi,
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
    "PUBLIC_IP",
    /\b(?!(?:10|127|169\.254|192\.168)\.)(?!(?:172\.(?:1[6-9]|2\d|3[0-1]))\.)(?:\d{1,3}\.){3}\d{1,3}\b/g,
    "MEDIUM"
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
  // Business sensitive
  // =========================

  replacePattern(
    "CONTRACT_NUMBER",
    /\b(?:contrat|contract|agreement)\s*[:#\-]?\s*[A-Z0-9\-]{5,30}\b/gi,
    "HIGH"
  );

  replacePattern(
    "CUSTOMER_NAME",
    /\b(?:client|customer)\s*[:\-]?\s+[A-ZÀ-Ÿ][A-Za-zÀ-ÿ0-9&.' -]{2,60}\b/g,
    "HIGH"
  );

  replacePattern(
    "SUPPLIER_NAME",
    /\b(?:fournisseur|supplier|vendor)\s*[:\-]?\s+[A-ZÀ-Ÿ][A-Za-zÀ-ÿ0-9&.' -]{2,60}\b/g,
    "HIGH"
  );

  const businessKeywords = [
    "confidentiel",
    "confidential",
    "contrat",
    "contract",
    "salaire",
    "salary",
    "licenciement",
    "client stratégique",
    "fournisseur",
    "supplier",
    "offre commerciale",
    "appel d'offre",
    "pricing",
    "roadmap",
    "stratégie",
    "strategy",
    "architecture interne",
    "incident sécurité",
    "vulnérabilité",
    "audit",
    "NIS2",
    "ISO27001",
    "DORA",
    "GDPR",
  ];

  const businessHits = businessKeywords.filter((kw) =>
    originalText.toLowerCase().includes(kw.toLowerCase())
  );

  // =========================
  // Dynamic scoring
  // =========================

  let score = 0;

  for (const finding of findings) {
    if (finding.severity === "LOW") score += 5;
    if (finding.severity === "MEDIUM") score += 15;
    if (finding.severity === "HIGH") score += 30;
    if (finding.severity === "CRITICAL") score += 50;
  }

  score += businessHits.length * 10;

  if (context.modelType === "public_llm" || context.modelType === "openai") {
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
    decision = "MASK_AND_SEND";
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
    },
  };
}