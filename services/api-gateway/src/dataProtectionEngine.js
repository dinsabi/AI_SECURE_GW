import { DLP_PATTERNS, BUSINESS_KEYWORDS } from "./dlpPatterns.js";

const MASK_BY_TYPE = {
  "Nom complet": "[MASKED_FULL_NAME]",
  "Adresse email": "[MASKED_EMAIL]",
  Téléphone: "[MASKED_PHONE]",
  Adresse: "[MASKED_ADDRESS]",
  "Date de naissance": "[MASKED_DATE_OF_BIRTH]",
  "Registre national": "[MASKED_NATIONAL_ID]",
  Passeport: "[MASKED_PASSPORT]",
  IBAN: "[MASKED_IBAN]",
  "Carte bancaire": "[MASKED_CARD]",
  CVV: "[MASKED_CVV]",
  "SWIFT/BIC": "[MASKED_BIC]",
  Facture: "[MASKED_INVOICE]",
  Salaire: "[MASKED_SALARY]",
  "API Key": "[MASKED_API_KEY]",
  "AWS Secret": "[MASKED_AWS_KEY]",
  "GitHub Token": "[MASKED_GITHUB_TOKEN]",
  "JWT Token": "[MASKED_JWT]",
  Password: "[MASKED_PASSWORD]",
  "SSH Key": "[MASKED_SSH_PRIVATE_KEY]",
  "Kubernetes Secret": "[MASKED_K8S_SECRET]",
  Firewall: "[MASKED_SECURITY_INFRA]",
  "Serveur critique": "[MASKED_CRITICAL_SERVER]",
  "SOC Incident": "[MASKED_SOC_INCIDENT]",
  "OT/SCADA": "[MASKED_OT_SCADA]",
  VPN: "[MASKED_VPN]",
  SIEM: "[MASKED_SIEM]",
  "Projet confidentiel": "[MASKED_CONFIDENTIAL_PROJECT]",
  "Code source": "[MASKED_SOURCE_CODE]",
  Architecture: "[MASKED_ARCHITECTURE]",
  Roadmap: "[MASKED_ROADMAP]",
  "Prompt Injection": "[BLOCKED_PROMPT_INJECTION]",
  Jailbreak: "[BLOCKED_JAILBREAK]",
  "Data Exfiltration": "[BLOCKED_DATA_EXFILTRATION]",
  "System Prompt Leak": "[BLOCKED_SYSTEM_PROMPT_LEAK]",
  "Role Override": "[BLOCKED_ROLE_OVERRIDE]",
};

function normalizeType(type = "") {
  return String(type)
    .toUpperCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

function scoreBySeverity(severity = "LOW") {
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

function classifyRisk(score) {
  if (score >= 80) return "CRITICAL";
  if (score >= 50) return "HIGH";
  if (score >= 20) return "MEDIUM";
  return "LOW";
}

function decide(score, findings = []) {
  const hasCritical = findings.some((f) => f.severity === "CRITICAL");

  if (score >= 70 || hasCritical) return "BLOCK";
  if (score >= 20) return "SANITIZE";
  return "ALLOW";
}

function getSafeRegex(pattern) {
  return new RegExp(pattern.regex.source, pattern.regex.flags);
}

export function analyzeDataProtection(input = "") {
  const text = String(input || "");
  const findings = [];
  let protectedContent = text;

  for (const pattern of DLP_PATTERNS) {
    const regexForMatch = getSafeRegex(pattern);
    const matches = [...text.matchAll(regexForMatch)];

    if (matches.length === 0) continue;

    for (const match of matches) {
      findings.push({
        type: pattern.type,
        severity: pattern.severity,
        frameworks: pattern.frameworks || [],
        value: match[0],
      });
    }

    const regexForReplace = getSafeRegex(pattern);
    const replacement =
      MASK_BY_TYPE[pattern.type] || `[MASKED_${normalizeType(pattern.type)}]`;

    protectedContent = protectedContent.replace(regexForReplace, replacement);
  }

  const loweredText = text.toLowerCase();

  for (const keyword of BUSINESS_KEYWORDS) {
    if (loweredText.includes(keyword.toLowerCase())) {
      findings.push({
        type: "Business Sensitive Keyword",
        severity: "HIGH",
        frameworks: ["NIS2", "ISO27001", "RGPD"],
        value: keyword,
      });
    }
  }

  const rawScore = findings.reduce(
    (total, finding) => total + scoreBySeverity(finding.severity),
    0
  );

  const riskScore = Math.min(rawScore, 100);
  const riskLevel = classifyRisk(riskScore);
  const decision = decide(riskScore, findings);

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
        ? "Sensitive data or prompt security risk detected and protected by AI Secure Gateway."
        : "No sensitive data or prompt injection detected. The request can be processed according to the current policy.",
  };
}