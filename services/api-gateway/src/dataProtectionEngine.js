import { DLP_PATTERNS, BUSINESS_KEYWORDS } from "./dlpPatterns.js";

const MASK_BY_TYPE = {
  "Nom complet": "[MASKED_FULL_NAME]",
  "Adresse email": "[MASKED_EMAIL]",
  "Téléphone": "[MASKED_PHONE]",
  "Adresse": "[MASKED_ADDRESS]",
  "Date de naissance": "[MASKED_DATE_OF_BIRTH]",
  "Registre national": "[MASKED_NATIONAL_ID]",
  "Passeport": "[MASKED_PASSPORT]",
  "IBAN": "[MASKED_IBAN]",
  "Carte bancaire": "[MASKED_CARD]",
  "CVV": "[MASKED_CVV]",
  "SWIFT/BIC": "[MASKED_BIC]",
  "Facture": "[MASKED_INVOICE]",
  "Salaire": "[MASKED_SALARY]",
  "API Key": "[MASKED_API_KEY]",
  "AWS Secret": "[MASKED_AWS_KEY]",
  "JWT Token": "[MASKED_JWT]",
  "Password": "[MASKED_PASSWORD]",
  "GitHub Token": "[MASKED_GITHUB_TOKEN]",
  "SSH Key": "[MASKED_SSH_PRIVATE_KEY]",
  "Kubernetes Secret": "[MASKED_K8S_SECRET]",
};

function severityScore(severity) {
  switch (severity) {
    case "CRITICAL":
      return 40;
    case "HIGH":
      return 25;
    case "MEDIUM":
      return 10;
    case "LOW":
      return 5;
    default:
      return 5;
  }
}

function normalizeType(type = "") {
  return String(type)
    .toUpperCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

export function analyzeDataProtection(input = "") {
  const text = String(input || "");
  const findings = [];
  let protectedContent = text;

  for (const pattern of DLP_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    const matches = [...text.matchAll(regex)];

    if (matches.length === 0) continue;

    for (const match of matches) {
      findings.push({
        type: pattern.type,
        severity: pattern.severity,
        frameworks: pattern.frameworks || [],
        value: match[0],
      });
    }

    const replacement =
      MASK_BY_TYPE[pattern.type] || `[MASKED_${normalizeType(pattern.type)}]`;

    protectedContent = protectedContent.replace(regex, replacement);
  }

  const businessFindings = BUSINESS_KEYWORDS.filter((keyword) =>
    text.toLowerCase().includes(keyword.toLowerCase())
  );

  for (const keyword of businessFindings) {
    findings.push({
      type: "Business Sensitive Keyword",
      severity: "HIGH",
      frameworks: ["NIS2", "ISO27001", "RGPD"],
      value: keyword,
    });
  }

  let riskScore = findings.reduce(
    (total, finding) => total + severityScore(finding.severity),
    0
  );

  riskScore = Math.min(riskScore, 100);

  const riskLevel =
    riskScore >= 80
      ? "CRITICAL"
      : riskScore >= 50
      ? "HIGH"
      : riskScore >= 20
      ? "MEDIUM"
      : "LOW";

  const decision =
    riskScore >= 70
      ? "BLOCK"
      : riskScore >= 20
      ? "SANITIZE"
      : "ALLOW";

  return {
    detected: findings.length > 0,
    decision,
    riskScore,
    riskLevel,
    dlpFindings: findings.length,
    findings,
    protectedContent,
    message:
      findings.length > 0
        ? "Sensitive data detected and protected before sending to the AI."
        : "No sensitive data or prompt injection detected. The request can be processed according to the current policy.",
  };
}