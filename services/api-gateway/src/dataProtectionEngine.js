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
  // PII / GDPR / NIS2
  // =========================

  replacePattern(
    "EMAIL",
    /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
    "HIGH"
  );

  replacePattern(
    "PHONE",
    /(?:\+32|0032|0)\s?[1-9](?:[\s.-]?\d{2}){3,4}/g,
    "MEDIUM"
  );

  replacePattern(
    "NISS_BE",
    /\b\d{2}[.\s-]?\d{2}[.\s-]?\d{2}[.\s-]?\d{3}[.\s-]?\d{2}\b/g,
    "HIGH"
  );

  replacePattern(
    "DATE_OF_BIRTH",
    /\b(?:né le|née le|date de naissance|birth date|dob)\s*[:\-]?\s*\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}\b/gi,
    "HIGH"
  );

  replacePattern(
    "DATE",
    /\b\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}\b/g,
    "LOW"
  );

  replacePattern(
    "PERSON",
    /\b(?:Monsieur|Madame|Mr|Mrs|Mme|M\.|Client|Utilisateur|Employé|Employee)\s+[A-ZÀ-Ÿ][a-zà-ÿ'-]+(?:\s+[A-ZÀ-Ÿ][a-zà-ÿ'-]+)?\b/g,
    "MEDIUM"
  );

  replacePattern(
    "PASSPORT",
    /\b(?:passport|passeport)\s*[:#-]?\s*[A-Z0-9]{6,12}\b/gi,
    "HIGH"
  );

  replacePattern(
    "DRIVING_LICENSE",
    /\b(?:permis|driving licence|driver license)\s*[:#-]?\s*[A-Z0-9-]{6,15}\b/gi,
    "HIGH"
  );

  replacePattern(
    "LICENSE_PLATE",
    /\b[1-9]-[A-Z]{3}-\d{3}\b/g,
    "MEDIUM"
  );

  replacePattern(
    "ADDRESS",
    /\b(?:rue|avenue|av\.|boulevard|bd|chaussée|straat|laan|road|street)\s+[A-ZÀ-Ÿa-zà-ÿ0-9' -]+(?:\s+\d{1,4})?\b/gi,
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

  replacePattern(
    "BANK_ACCOUNT",
    /\b(?:compte bancaire|bank account|account number|numero de compte|numéro de compte)\s*[:#-]?\s*[A-Z0-9\s-]{8,34}\b/gi,
    "HIGH"
  );

  replacePattern(
    "SALARY",
    /\b(?:salaire|salary|rémunération|remuneration)\s*[:=]?\s*\d+(?:[.,]\d+)?\s?(?:€|EUR|euro|euros)?\b/gi,
    "HIGH"
  );

  replacePattern(
    "REVENUE",
    /\b(?:chiffre d'affaires|revenue|turnover|CA)\s*[:=]?\s*\d+(?:[.,]\d+)?\s?(?:€|EUR|k€|M€|million|millions)?\b/gi,
    "HIGH"
  );

  replacePattern(
    "MARGIN",
    /\b(?:marge|margin|gross margin|net margin)\s*[:=]?\s*\d+(?:[.,]\d+)?\s?(?:%|€|EUR)?\b/gi,
    "HIGH"
  );

  // =========================
  // Business sensitive / NIS2
  // =========================

  replacePattern(
    "CLIENT_NAME",
    /\b(?:client|customer|fournisseur|supplier|partner|partenaire)\s*[:=]?\s+[A-ZÀ-Ÿ][A-Za-zÀ-ÿ0-9&' .-]{2,60}\b/g,
    "HIGH"
  );

  replacePattern(
    "CONTRACT_NUMBER",
    /\b(?:contrat|contract|agreement|marché|tender)\s*(?:n°|no|number|#|:)?\s*[A-Z0-9-]{4,30}\b/gi,
    "HIGH"
  );

  replacePattern(
    "PRICING",
    /\b(?:pricing|prix|tarif|tarification|price list|offre commerciale)\s*[:=]?\s*[A-Za-z0-9€%.,\s-]{3,80}\b/gi,
    "HIGH"
  );

  replacePattern(
    "ROADMAP",
    /\b(?:roadmap|feuille de route|stratégie|strategy|business plan|plan stratégique)\b[\s\S]{0,120}/gi,
    "HIGH"
  );

  // =========================
  // Secrets / Credentials / ISO27001
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
    "BEARER_TOKEN",
    /\bBearer\s+[A-Za-z0-9._-]{20,}\b/g,
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
  // Infrastructure / NIS2
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
// IPv4 Public
// =========================

replacePattern(
  "PUBLIC_IP",
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
  "HIGH"
);

// =========================
// Private IPv4
// =========================

replacePattern(
  "PRIVATE_IP",
  /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b/g,
  "CRITICAL"
);

// =========================
// IPv4 + Port
// =========================

replacePattern(
  "IP_PORT",
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d):\d{2,5}\b/g,
  "CRITICAL"
);

// =========================
// CIDR
// =========================

replacePattern(
  "CIDR",
  /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\/(?:[0-9]|[1-2][0-9]|3[0-2])\b/g,
  "HIGH"
);

// =========================
// IPv6
// =========================

replacePattern(
  "IPV6",
  /\b(?:[a-fA-F0-9]{1,4}:){2,7}[a-fA-F0-9]{1,4}\b/g,
  "HIGH"
);

// =========================
// Internal Hostnames
// =========================

replacePattern(
  "HOSTNAME",
  /\b[a-zA-Z0-9-]+(?:\.internal|\.local|\.corp|\.lan|\.priv)\b/g,
  "HIGH"
);

// =========================
// Internal URLs
// =========================

replacePattern(
  "INTERNAL_URL",
  /\bhttps?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+|[a-zA-Z0-9.-]+\.internal)[^\s]*/gi,
  "CRITICAL"
);

  // =========================
  // Business keywords
  // =========================

  const businessKeywords = [
    "confidentiel",
    "strictement confidentiel",
    "contrat",
    "salaire",
    "salary",
    "marge",
    "chiffre d'affaires",
    "pricing",
    "roadmap",
    "stratégie",
    "business plan",
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
    decision = ""MASK_AND_SEND"";
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