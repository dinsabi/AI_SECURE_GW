import express from "express";
import multer from "multer";
import { analyzeDataProtection } from "../dataProtectionEngine.js";

export const fileRoutes = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024,
  },
});

function isSupportedTextFile(fileName = "", mimeType = "") {
  const lowerName = fileName.toLowerCase();
  const lowerMime = mimeType.toLowerCase();

  return (
    lowerMime.includes("text") ||
    lowerName.endsWith(".txt") ||
    lowerName.endsWith(".csv") ||
    lowerName.endsWith(".json") ||
    lowerName.endsWith(".log") ||
    lowerName.endsWith(".md") ||
    lowerName.endsWith(".yaml") ||
    lowerName.endsWith(".yml") ||
    lowerName.endsWith(".env")
  );
}

function extractTextFromBuffer(file) {
  const fileName = file.originalname || "";
  const mimeType = file.mimetype || "";

  if (!isSupportedTextFile(fileName, mimeType)) {
    return {
      supported: false,
      text: "",
      error:
        "File type not supported yet. Supported: txt, csv, json, log, md, yaml, yml, env.",
    };
  }

  return {
    supported: true,
    text: file.buffer.toString("utf8"),
    error: null,
  };
}

fileRoutes.post("/analyze", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        ok: false,
        error: "No file uploaded",
      });
    }

    const fileName = req.file.originalname;
    const mimeType = req.file.mimetype;
    const size = req.file.size;

    const extraction = extractTextFromBuffer(req.file);

    if (!extraction.supported) {
      return res.status(415).json({
        ok: false,
        error: extraction.error,
        fileName,
        mimeType,
        size,
      });
    }

    const result = analyzeDataProtection(extraction.text);

    return res.json({
      ok: true,
      fileName,
      mimeType,
      size,
      extractedCharacters: extraction.text.length,
      ...result,
    });
  } catch (error) {
    console.error("File analyze error:", error);

    return res.status(500).json({
      ok: false,
      error: "File analysis failed",
      details: error.message,
    });
  }
});

fileRoutes.post("/inspect", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        ok: false,
        error: "No file uploaded",
      });
    }

    const fileName = req.file.originalname;
    const mimeType = req.file.mimetype;
    const size = req.file.size;

    const extraction = extractTextFromBuffer(req.file);

    if (!extraction.supported) {
      return res.status(415).json({
        ok: false,
        error: extraction.error,
        fileName,
        mimeType,
        size,
      });
    }

    const result = analyzeDataProtection(extraction.text);

    return res.json({
      ok: true,
      fileName,
      mimeType,
      size,
      extractedCharacters: extraction.text.length,
      preview: extraction.text.slice(0, 500),
      ...result,
    });
  } catch (error) {
    console.error("File inspect error:", error);

    return res.status(500).json({
      ok: false,
      error: "File inspection failed",
      details: error.message,
    });
  }
});

export default fileRoutes;