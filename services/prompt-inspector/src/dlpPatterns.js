export const DLP_PATTERNS = [
  {
    type: "EMAIL",
    severity: "MEDIUM",
    frameworks: ["GDPR", "NIS2"],
    regex: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i,
  },

  {
    type: "IBAN",
    severity: "HIGH",
    frameworks: ["GDPR", "NIS2"],
    regex: /\b[A-Z]{2}[0-9]{2}[ ]?[0-9A-Z]{4}[ ]?[0-9A-Z]{4}[ ]?[0-9A-Z]{4}[ ]?[0-9A-Z]{0,4}\b/i,
  },

  {
    type: "JWT_TOKEN",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex: /eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/,
  },

  {
    type: "AWS_ACCESS_KEY",
    severity: "CRITICAL",
    frameworks: ["ISO27001", "NIS2"],
    regex: /\bAKIA[0-9A-Z]{16}\b/,
  },

  {
    type: "GITHUB_TOKEN",
    severity: "CRITICAL",
    frameworks: ["ISO27001"],
    regex: /\bghp_[A-Za-z0-9]{36,}\b/,
  },

  {
    type: "OPENAI_API_KEY",
    severity: "CRITICAL",
    frameworks: ["ISO27001"],
    regex: /\bsk-[A-Za-z0-9]{20,}\b/,
  },

  {
    type: "PRIVATE_KEY",
    severity: "CRITICAL",
    frameworks: ["ISO27001"],
    regex: /-----BEGIN PRIVATE KEY-----/,
  },

  {
    type: "PASSWORD_REFERENCE",
    severity: "HIGH",
    frameworks: ["ISO27001"],
    regex: /\b(password|passwd|pwd)\s*[:=]\s*.+/i,
  },

  {
    type: "CREDIT_CARD",
    severity: "HIGH",
    frameworks: ["PCI-DSS", "GDPR"],
    regex: /\b(?:\d[ -]*?){13,16}\b/,
  },

  {
    type: "PHONE_NUMBER",
    severity: "MEDIUM",
    frameworks: ["GDPR"],
    regex: /\+?[0-9][0-9\s\-]{7,15}/,
  },
];