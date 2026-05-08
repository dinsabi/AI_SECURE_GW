import express from "express";
import { requireAuth } from "../middleware/auth.js";
import {
  upload,
  processFileAnalyzeRequest,
} from "../services/fileService.js";

export function fileRoutes(openai) {
  const router = express.Router();

  router.post(
    "/v1/files/analyze",
    requireAuth,
    upload.single("file"),
    async (req, res) => {
      return processFileAnalyzeRequest(req, res, openai);
    }
  );

  return router;
}