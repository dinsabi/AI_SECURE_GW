import express from "express";
import cors from "cors";
import OpenAI from "openai";

import { env } from "./config/env.js";
import { initDatabase } from "./db.js";
import { healthRoutes } from "./routes/healthRoutes.js";
import { authRoutes } from "./routes/authRoutes.js";
import { dashboardRoutes } from "./routes/dashboardRoutes.js";
import { gatewayRoutes } from "./routes/gatewayRoutes.js";
import { fileRoutes } from "./routes/fileRoutes.js";
import { availableRoutes } from "./config/routes.js";

const app = express();

app.use(
  cors({
    origin: true,
    credentials: true,
  })
);

app.use(express.json({ limit: "25mb" }));
app.use(express.urlencoded({ extended: true, limit: "25mb" }));

const openai = env.OPENAI_API_KEY
  ? new OpenAI({
      apiKey: env.OPENAI_API_KEY,
    })
  : null;

app.locals.openai = openai;
app.locals.env = env;

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "api-gateway",
    status: "UP",
    message: "AI Secure Gateway API is running",
    availableRoutes,
  });
});

app.use("/", healthRoutes);
app.use("/", authRoutes);

app.use("/dashboard", dashboardRoutes);
app.use("/v1/dashboard", dashboardRoutes);

app.use("/gateway", gatewayRoutes);
app.use("/v1/gateway", gatewayRoutes);

app.use("/files", fileRoutes);
app.use("/v1/files", fileRoutes);

app.use((req, res) => {
  res.status(404).json({
    ok: false,
    error: "Route not found",
    method: req.method,
    path: req.originalUrl,
    availableRoutes,
  });
});

app.use((err, req, res, next) => {
  console.error("Unhandled API error:", err);

  res.status(500).json({
    ok: false,
    error: "Internal server error",
    details: err.message,
  });
});

const PORT = env.PORT || process.env.PORT || 3000;

async function startServer() {
  try {
    try {
      await initDatabase();
      console.log("Database initialized");
    } catch (dbError) {
      console.warn("Database initialization failed:", dbError.message);
    }

    app.listen(PORT, () => {
      console.log(`api-gateway ready on port ${PORT}`);
      console.log("Available routes:", availableRoutes);
    });
  } catch (error) {
    console.error("Failed to start api-gateway:", error);
    process.exit(1);
  }
}

startServer();