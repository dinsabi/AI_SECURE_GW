import express from "express";
import { env } from "../config/env.js";
import { availableRoutes } from "../config/routes.js";

export const healthRoutes = express.Router();

healthRoutes.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "api-gateway",
    message: "AI Secure Gateway API",
    availableRoutes,
  });
});

healthRoutes.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "api-gateway",
    status: "UP",
    keycloak: {
      url: env.KEYCLOAK_URL,
      realm: env.KEYCLOAK_REALM,
      clientId: env.KEYCLOAK_CLIENT_ID,
    },
    openai: {
      configured: Boolean(env.OPENAI_API_KEY),
      model: env.OPENAI_MODEL,
    },
    audit: {
      postgres: true,
    },
    llmRouter: {
      enabled: true,
      supportedProviders: ["openai", "chatgpt", "mock", "public_llm"],
    },
    promptInjectionProtection: {
      enabled: true,
    },
    availableRoutes,
  });
});