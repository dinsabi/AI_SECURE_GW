export const env = {
  PORT: process.env.PORT || 3000,

  KEYCLOAK_URL: process.env.KEYCLOAK_URL || "http://keycloak:8080",
  KEYCLOAK_REALM: process.env.KEYCLOAK_REALM || "aigw",
  KEYCLOAK_CLIENT_ID:
    process.env.KEYCLOAK_CLIENT_ID || "ai-secure-gateway",
  KEYCLOAK_CLIENT_SECRET: process.env.KEYCLOAK_CLIENT_SECRET || "",

  OPENAI_API_KEY: process.env.OPENAI_API_KEY || "",
  OPENAI_MODEL: process.env.OPENAI_MODEL || "gpt-4o-mini",

  LLM_URL: process.env.LLM_URL || "http://llm-mock:3006",
};