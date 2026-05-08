import express from "express";
import { requireAuth } from "../middleware/auth.js";
import {
  processGenerateRequest,
  processGatewayRequest,
} from "../services/gatewayService.js";

export function gatewayRoutes(openai) {
  const router = express.Router();

  router.post("/generate", requireAuth, async (req, res) => {
    return processGenerateRequest(req, res, "/generate", openai);
  });

  router.post("/v1/generate", requireAuth, async (req, res) => {
    return processGenerateRequest(req, res, "/v1/generate", openai);
  });

  router.post("/gateway/process", requireAuth, async (req, res) => {
    return processGatewayRequest(req, res, "/gateway/process", openai);
  });

  router.post("/v1/gateway/process", requireAuth, async (req, res) => {
    return processGatewayRequest(req, res, "/v1/gateway/process", openai);
  });

  return router;
}