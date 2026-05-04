import mammoth from "mammoth";
import { protectPrompt } from "./dataProtectionEngine.js";

export async function extractTextFromFile(file) {
  const fileName = file.originalname || "unknown";
  const mimeType = file.mimetype || "";
  const buffer = file.buffer;

  if (!buffer) {
    throw new Error("File buffer is empty.");
  }

  if (
    mimeType.includes("text") ||
    fileName.endsWith(".txt") ||
    fileName.endsWith(".csv") ||
    fileName.endsWith(".json")
  ) {
    return buffer.toString("utf-8");
  }

  if (
    mimeType.includes("wordprocessingml.document") ||
    fileName.endsWith(".docx")
  ) {
    const result = await mammoth.extractRawText({ buffer });
    return result.value || "";
  }

  throw new Error(
    `Unsupported file type: ${mimeType || fileName}. Supported: txt, csv, json, docx`
  );
}

export async function protectUploadedFile(file, context = {}) {
  const extractedText = await extractTextFromFile(file);

  const protection = protectPrompt(extractedText, context);

  return {
    fileName: file.originalname,
    mimeType: file.mimetype,
    size: file.size,
    extractedTextLength: extractedText.length,
    originalText: protection.originalText,
    protectedText: protection.protectedText,
    decision: protection.decision,
    riskScore: protection.score,
    riskLevel: protection.riskLevel,
    findings: protection.findings,
    businessHits: protection.businessHits,
    tokenMap: protection.tokenMap,
    stats: protection.stats,
  };
}