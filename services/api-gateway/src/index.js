import express from "express";
import cors from "cors";
import multer from "multer";
import { analyzeDataProtection } from "./dataProtectionEngine.js";

const app = express();
const upload = multer({ storage: multer.memoryStorage() });

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "api-gateway",
    message: "AI Secure Gateway API is running",
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "api-gateway",
    status: "UP",
    availableRoutes: [
      "GET /",
      "GET /health",
      "POST /generate",
      "POST /gateway/process",
      "POST /v1/generate",
      "POST /v1/gateway/process",
      "POST /v1/files/analyze",
    ],
  });
});

app.post("/gateway/process", async (req, res) => {
  try {
    const prompt = String(
      req.body.prompt || req.body.text || req.body.message || ""
    );

    console.log("PROMPT RECEIVED:", prompt);

    const result = analyzeDataProtection(prompt);

    res.json({
      ok: true,
      ...result,
    });
  } catch (error) {
    console.error("Gateway process error:", error);
    res.status(500).json({
      ok: false,
      error: "Gateway processing failed",
    });
  }
});

app.post("/v1/gateway/process", async (req, res) => {
  try {
    const prompt = String(
      req.body.prompt || req.body.text || req.body.message || ""
    );

    console.log("V1 PROMPT RECEIVED:", prompt);

    const result = analyzeDataProtection(prompt);

    res.json({
      ok: true,
      ...result,
    });
  } catch (error) {
    console.error("V1 Gateway process error:", error);
    res.status(500).json({
      ok: false,
      error: "Gateway processing failed",
    });
  }
});

app.post("/generate", async (req, res) => {
  try {
    const prompt = String(req.body.prompt || "");
    const result = analyzeDataProtection(prompt);

    if (result.decision === "BLOCK") {
      return res.json({
        ok: true,
        blocked: true,
        ...result,
        answer: "Request blocked by AI Secure Gateway policy.",
      });
    }

    res.json({
      ok: true,
      blocked: false,
      ...result,
      answer: `Mock LLM response for protected prompt: ${result.protectedContent}`,
    });
  } catch (error) {
    console.error("Generate error:", error);
    res.status(500).json({
      ok: false,
      error: "Generate failed",
    });
  }
});

app.post("/v1/generate", async (req, res) => {
  try {
    const prompt = String(req.body.prompt || "");
    const result = analyzeDataProtection(prompt);

    if (result.decision === "BLOCK") {
      return res.json({
        ok: true,
        blocked: true,
        ...result,
        answer: "Request blocked by AI Secure Gateway policy.",
      });
    }

    res.json({
      ok: true,
      blocked: false,
      ...result,
      answer: `Mock LLM response for protected prompt: ${result.protectedContent}`,
    });
  } catch (error) {
    console.error("V1 Generate error:", error);
    res.status(500).json({
      ok: false,
      error: "Generate failed",
    });
  }
});

app.post("/v1/files/analyze", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({
        ok: false,
        error: "No file uploaded",
      });
    }

    const fileName = req.file.originalname;
    const mimeType = req.file.mimetype;
    const buffer = req.file.buffer;

    let extractedText = "";

    if (
      mimeType.includes("text") ||
      fileName.endsWith(".txt") ||
      fileName.endsWith(".csv") ||
      fileName.endsWith(".json") ||
      fileName.endsWith(".log")
    ) {
      extractedText = buffer.toString("utf8");
    } else {
      return res.status(415).json({
        ok: false,
        error:
          "File type not yet supported for text extraction. Start with txt, csv, json or log.",
        fileName,
        mimeType,
      });
    }

    const result = analyzeDataProtection(extractedText);

    res.json({
      ok: true,
      fileName,
      mimeType,
      size: req.file.size,
      ...result,
    });
  } catch (error) {
    console.error("File analyze error:", error);
    res.status(500).json({
      ok: false,
      error: "File analysis failed",
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`api-gateway ready on port ${PORT}`);
});