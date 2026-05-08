import express from "express";
import { requireAuth } from "../middleware/auth.js";
import { getRiskSummary } from "../auditLogger.js";

export const dashboardRoutes = express.Router();

dashboardRoutes.get("/v1/dashboard/risk-summary", requireAuth, async (req, res) => {
  try {
    const data = await getRiskSummary();

    return res.json({
      ok: true,
      route: "/v1/dashboard/risk-summary",
      ...data,
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      error: "risk_summary_failed",
      message: error.message,
    });
  }
});