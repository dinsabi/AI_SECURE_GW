import OpenAI from "openai";
import express from "express";
import cors from "cors";
import { DLP_PATTERNS } from "./dlpPatterns.js";
import { env } from "./config/env.js";
import { initDatabase } from "./db.js";
import { healthRoutes } from "./routes/healthRoutes.js";
import { authRoutes } from "./routes/authRoutes.js";
import { dashboardRoutes } from "./routes/dashboardRoutes.js";
import { gatewayRoutes } from "./routes/gatewayRoutes.js";
import { fileRoutes } from "./routes/fileRoutes.js";
import { availableRoutes } from "./config/routes.js";

const app = express();

const openai = new OpenAI({
  apiKey: env.OPENAI_API_KEY,
});

app.use(
  cors({
    origin: true,
    credentials: true,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-User-Email",
      "X-User-Department",
      "X-User-Roles",
      "X-User-Country",
      "X-MFA-Verified",
    ],
  })
);

app.use(express.json({ limit: "2mb" }));

app.use("/", healthRoutes);
app.use("/", authRoutes);
app.use("/", dashboardRoutes);
app.use("/", gatewayRoutes(openai));
app.use("/", fileRoutes(openai));

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: "not_found",
    method: req.method,
    path: req.originalUrl,
    availableRoutes,
  });
});

initDatabase()
  .then(() => {
    app.listen(env.PORT, () => {
      console.log(`api-gateway ready on port ${env.PORT}`);
      console.log(`Keycloak URL: ${env.KEYCLOAK_URL}`);
      console.log(`Keycloak realm: ${env.KEYCLOAK_REALM}`);
      console.log(`Keycloak client: ${env.KEYCLOAK_CLIENT_ID}`);
      console.log(`OpenAI configured: ${Boolean(env.OPENAI_API_KEY)}`);
      console.log(`OpenAI model: ${env.OPENAI_MODEL}`);
      console.log("PostgreSQL audit database initialized");
      console.log("Multi-LLM Router enabled");
      console.log("Prompt Injection Protection enabled");
      console.log("API Gateway modular structure enabled");
    });
  })
  .catch((error) => {
    console.error("Failed to initialize PostgreSQL audit database", error);
    process.exit(1);
  });