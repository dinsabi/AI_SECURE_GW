import crypto from "crypto";
import { pool } from "./db.js";

function sha256(value) {
  return crypto.createHash("sha256").update(String(value || "")).digest("hex");
}

function normalizeBool(value) {
  return value === true || value === "true";
}

export async function writeAuditEvent(event) {
  const findings = event.findings || [];
  const findingTypes = [...new Set(findings.map((f) => f.type))];

  const query = `
    INSERT INTO audit_events (
      event_type,
      route,
      user_email,
      department,
      roles,
      country,
      mfa_verified,
      model_type,
      provider,
      frameworks,
      decision,
      risk_score,
      risk_level,
      response_decision,
      response_risk_score,
      response_risk_level,
      finding_types,
      findings,
      business_hits,
      prompt_hash,
      protected_prompt,
      response_hash,
      protected_response,
      file_name,
      file_mime_type,
      file_size,
      extracted_text_length,
      grc
    )
    VALUES (
      $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
      $11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
      $21,$22,$23,$24,$25,$26,$27,$28
    )
  `;

  const values = [
    event.eventType,
    event.route,
    event.user?.email || "unknown",
    event.user?.department || "unknown",
    event.user?.roles || "unknown",
    event.user?.country || "unknown",
    normalizeBool(event.user?.mfaVerified),
    event.modelType || "unknown",
    event.provider || "unknown",
    JSON.stringify(event.frameworks || []),
    event.decision || "UNKNOWN",
    Number(event.riskScore || 0),
    event.riskLevel || "UNKNOWN",
    event.responseDecision || null,
    event.responseRiskScore ?? null,
    event.responseRiskLevel || null,
    JSON.stringify(findingTypes),
    JSON.stringify(findings),
    JSON.stringify(event.businessHits || []),
    sha256(event.originalPrompt || event.originalText || ""),
    event.protectedPrompt || event.protectedText || null,
    sha256(event.originalResponse || ""),
    event.protectedResponse || null,
    event.file?.name || null,
    event.file?.mimeType || null,
    event.file?.size || null,
    event.file?.extractedTextLength || null,
    JSON.stringify(event.grc || {}),
  ];

  await pool.query(query, values);
}

export async function getRiskSummary() {
  const summary = await pool.query(`
    SELECT
      COUNT(*)::int AS total_events,
      COALESCE(AVG(risk_score)::int, 0) AS average_risk_score,
      COUNT(*) FILTER (WHERE risk_level = 'CRITICAL')::int AS critical_events,
      COUNT(*) FILTER (WHERE risk_level = 'HIGH')::int AS high_events,
      COUNT(*) FILTER (WHERE decision IN ('BLOCK', 'BLOCK_OR_APPROVAL'))::int AS blocked_events,
      COUNT(*) FILTER (WHERE event_type = 'AI_PROMPT_SECURITY_CHECK')::int AS prompt_events,
      COUNT(*) FILTER (WHERE event_type = 'AI_FILE_SECURITY_CHECK')::int AS file_events
    FROM audit_events
  `);

  const recentEvents = await pool.query(`
    SELECT
      id,
      event_type,
      route,
      user_email,
      department,
      model_type,
      provider,
      decision,
      risk_score,
      risk_level,
      response_decision,
      response_risk_score,
      response_risk_level,
      finding_types,
      file_name,
      created_at
    FROM audit_events
    ORDER BY created_at DESC
    LIMIT 30
  `);

  const topFindingTypes = await pool.query(`
    SELECT value AS finding_type, COUNT(*)::int AS count
    FROM audit_events,
    LATERAL jsonb_array_elements_text(finding_types) AS value
    GROUP BY value
    ORDER BY count DESC
    LIMIT 10
  `);

  return {
    summary: summary.rows[0],
    recentEvents: recentEvents.rows,
    topFindingTypes: topFindingTypes.rows,
  };
}