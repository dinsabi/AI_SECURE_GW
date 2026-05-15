export const DLP_PATTERNS = [
  // =========================
  // GDPR / PII
  // =========================
  {
    type: "EMAIL",
    severity: "HIGH",
    frameworks: ["GDPR", "NIS2", "ISO27001"],
    regex: /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi,
  },
  {
    type: "PHONE",
    severity: "MEDIUM",
    frameworks: ["GDPR"],
    regex: /(?:\+32|0032|0)\s?[1-9](?:[\s.-]?\d{2}){3,4}/g,
  },
  {
    type: "NATIONAL_ID_BE",
    severity: "HIGH",
    frameworks: ["GDPR", "NIS2"],
    regex: /\b\d{2}[.\s-]?\d{2}[.\s-]?\d{2}[.\s-]?\d{3}[.\s-]?\d{2}\b/g,
  },
  {
    type: "DATE_OF_BIRTH",
    severity: "HIGH",
    frameworks: ["GDPR"],
    regex:
      /\b(?:né le|née le|date de naissance|dob|birth date)\s*[:\-]?\s*\d{1,2}[\/.-]\d{1,2}[\/.-]\d{2,4}\b/gi,
  },
  {
    type: "ADDRESS",
    severity: "HIGH",
    frameworks: ["GDPR"],
    regex:
      /\b\d{1,4}\s+(?:rue|avenue|boulevard|chaussée|straat|laan|street|road|square|place)\s+[A-ZÀ-Ÿa-zà-ÿ0-9\s'-]{3,80}\b/gi,
  },
  {
    type: "PASSPORT_NUMBER",
    severity: "HIGH",
    frameworks: ["GDPR", "NIS2"],
    regex: /\b(?:passport|passeport)\s*[:\-]?\s*[A-Z0-9]{6,12}\b/gi,
  },
  {
    type: "DRIVING_LICENSE",
    severity: "HIGH",
    frameworks: ["GDPR"],
    regex:
      /\b(?:permis|driving licence|driver license)\s*[:\-]?\s*[A-Z0-9\-]{6,15}\b/gi,
  },
  {
    type: "LICENSE_PLATE",
    severity: "MEDIUM",
    frameworks: ["GDPR"],
    regex: /\b(?:[A-Z]{1,3}[-\s]?\d{3}[-\s]?[A-Z]{0,3}|\d[-\s]?[A-Z]{3}[-\s]?\d{3})\b/g,
  },

  // =========================
  // Financial
  // =========================
  {
    type: "IBAN",
    severity: "HIGH",
    frameworks: ["GDPR", "NIS2", "ISO27001"],
    regex: /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]{4}){2,7}\b/g,
  },
  {
    type: "CREDIT_CARD",
    severity: "CRITICAL",
    frameworks: ["PCI-DSS", "GDPR", "ISO27001"],
    regex: /\b(?:\d[ -]*?){13,19}\b/g,
  },
  {
    type: "VAT",
    severity: "MEDIUM",
    frameworks: ["GDPR", "ISO27001"],
    regex: /\b(?:BE|FR|NL|DE|LU)\s?\d{9,12}\b/gi,
  },
  {
    type: "SALARY",
    severity: "HIGH",
    frameworks: ["GDPR", "ISO27001"],
    regex:
      /\b(?:salaire|salary|rémunération|remuneration)\s*[:\-]?\s*\d{2,7}(?:[,.]\d{2})?\s*(?:€|EUR|euros)?\b/gi,
  },
  {
    type: "REVENUE",
    severity: "HIGH",
    frameworks: ["NIS2", "ISO27001"],
    regex:
      /\b(?:chiffre d'affaires|revenu|revenue|turnover)\s*[:\-]?\s*\d{3,12}(?:[,.]\d{2})?\s*(?:€|EUR|euros|k€|m€)?\b/gi,
  },
  {
    type: "MARGIN",
    severity: "HIGH",
    frameworks: ["NIS2", "ISO27001"],
    regex: /\b(?:marge|margin)\s*[:\-]?\s*\d{1,3}(?:[,.]\d{1,2})?\s*%?\b/gi,
  },

  // =========================
  // Secrets / Credentials
  // =========================
  {
    type: "OPENAI_API_KEY",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    type: "API_KEY",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex:
      /\b(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret)\s*[:=]\s*["']?[A-Za-z0-9_\-./=]{12,}["']?/gi,
  },
  {
    type: "JWT_TOKEN",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
  },
  {
    type: "BEARER_TOKEN",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex: /\bBearer\s+[A-Za-z0-9._\-+/=]{20,}\b/g,
  },
  {
    type: "PASSWORD",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex:
      /\b(?:password|passwd|pwd|motdepasse|mot_de_passe|secret)\s*[:=]\s*["']?[^\s,;"]+["']?/gi,
  },
  {
    type: "PRIVATE_KEY",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex:
      /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
  },
  {
    type: "AWS_ACCESS_KEY",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    type: "AWS_SECRET_KEY",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex:
      /\b(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?/g,
  },
  {
    type: "GITHUB_TOKEN",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b/g,
  },
  {
    type: "AZURE_SECRET",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex:
      /\b(?:AZURE_CLIENT_SECRET|azure_client_secret|client_secret)\s*[:=]\s*["']?[A-Za-z0-9_\-~.]{20,}["']?/g,
  },
  {
    type: "CONNECTION_STRING",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex: /\b(?:mongodb|postgres|postgresql|mysql|redis):\/\/[^\s]+/gi,
  },

  // =========================
  // Infrastructure / Technical
  // =========================
  {
    type: "PRIVATE_IP",
    severity: "HIGH",
    frameworks: ["NIS2", "ISO27001"],
    regex:
      /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b/g,
  },
  {
    type: "PUBLIC_IP",
    severity: "MEDIUM",
    frameworks: ["NIS2", "ISO27001"],
    regex:
      /\b(?!(?:10|127|169\.254|192\.168)\.)(?!(?:172\.(?:1[6-9]|2\d|3[0-1]))\.)(?:\d{1,3}\.){3}\d{1,3}\b/g,
  },
  {
    type: "HOSTNAME",
    severity: "MEDIUM",
    frameworks: ["NIS2", "ISO27001"],
    regex: /\b[a-zA-Z0-9-]+(?:\.internal|\.local|\.corp|\.lan)\b/g,
  },
  {
    type: "INTERNAL_URL",
    severity: "HIGH",
    frameworks: ["NIS2", "ISO27001"],
    regex:
      /\bhttps?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|[a-zA-Z0-9.-]+\.internal)[^\s]*/gi,
  },

  // =========================
  // Business Sensitive
  // =========================
  {
    type: "CONTRACT_NUMBER",
    severity: "HIGH",
    frameworks: ["NIS2", "ISO27001"],
    regex:
      /\b(?:contrat|contract|agreement)\s*[:#\-]?\s*[A-Z0-9\-]{5,30}\b/gi,
  },
  {
    type: "CUSTOMER_NAME",
    severity: "HIGH",
    frameworks: ["GDPR", "NIS2", "ISO27001"],
    regex:
      /\b(?:client|customer)\s*[:\-]?\s+[A-ZÀ-Ÿ][A-Za-zÀ-ÿ0-9&.' -]{2,60}\b/g,
  },
  {
    type: "SUPPLIER_NAME",
    severity: "HIGH",
    frameworks: ["NIS2", "ISO27001"],
    regex:
      /\b(?:fournisseur|supplier|vendor)\s*[:\-]?\s+[A-ZÀ-Ÿ][A-Za-zÀ-ÿ0-9&.' -]{2,60}\b/g,
  },
];

export const BUSINESS_KEYWORDS = [
  "confidentiel",
  "confidential",
  "strictement confidentiel",
  "internal only",
  "restricted",
  "secret",
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
  "security incident",
  "vulnérabilité",
  "vulnerability",
  "audit",
  "NIS2",
  "ISO27001",
  "DORA",
  "GDPR",
  "RGPD",
  "EU AI Act",
];