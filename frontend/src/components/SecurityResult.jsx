export default function SecurityResult({ data }) {
  if (!data) {
    return null;
  }

  const findings = data.findings || [];
  const responseSecurity = data.response?.responseSecurity || {};
  const injection = data.injection || {};

  const getRiskColor = (level) => {
    switch (level) {
      case "LOW":
        return "#00c853";

      case "MEDIUM":
        return "#ff9800";

      case "HIGH":
        return "#ff5252";

      default:
        return "#999";
    }
  };

  return (
    <div
      style={{
        marginTop: 30,
        background: "#161b22",
        color: "#fff",
        padding: 25,
        borderRadius: 12,
        border: "1px solid #30363d",
      }}
    >
      <h2 style={{ marginTop: 0 }}>AI Security Analysis</h2>

      {/* Decision */}
      <div style={{ marginBottom: 20 }}>
        <strong>Decision:</strong>{" "}
        <span
          style={{
            color: getRiskColor(data.riskLevel),
            fontWeight: "bold",
          }}
        >
          {data.decision}
        </span>
      </div>

      {/* Risk */}
      <div style={{ marginBottom: 20 }}>
        <strong>Risk Level:</strong>{" "}
        <span
          style={{
            color: getRiskColor(data.riskLevel),
            fontWeight: "bold",
          }}
        >
          {data.riskLevel}
        </span>
      </div>

      <div style={{ marginBottom: 20 }}>
        <strong>Risk Score:</strong> {data.riskScore}
      </div>

      {/* Provider */}
      <div style={{ marginBottom: 20 }}>
        <strong>LLM Provider:</strong>{" "}
        {data.response?.provider || "unknown"}
      </div>

      {/* Routing */}
      <div style={{ marginBottom: 20 }}>
        <strong>Routing Decision:</strong>{" "}
        {data.response?.routingDecision || "N/A"}
      </div>

      {/* Protected Prompt */}
      <div style={{ marginBottom: 20 }}>
        <strong>Protected Prompt:</strong>

        <div
          style={{
            marginTop: 10,
            padding: 15,
            background: "#0d1117",
            borderRadius: 8,
            border: "1px solid #30363d",
            whiteSpace: "pre-wrap",
          }}
        >
          {data.protectedPrompt ||
            data.protectedText ||
            "No protected content"}
        </div>
      </div>

      {/* Findings */}
      <div style={{ marginBottom: 20 }}>
        <strong>Sensitive Data Findings:</strong>

        {findings.length === 0 ? (
          <p>No sensitive data detected.</p>
        ) : (
          <ul>
            {findings.map((f, index) => (
              <li key={index}>
                <strong>{f.type}</strong> — Severity: {f.severity}
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Prompt Injection */}
      <div style={{ marginBottom: 20 }}>
        <strong>Prompt Injection Protection:</strong>

        <div
          style={{
            marginTop: 10,
            color: getRiskColor(injection.riskLevel),
            fontWeight: "bold",
          }}
        >
          {injection.decision}
        </div>

        {injection.hits?.length > 0 && (
          <ul>
            {injection.hits.map((hit, index) => (
              <li key={index}>{hit}</li>
            ))}
          </ul>
        )}
      </div>

      {/* AI Response */}
      <div style={{ marginBottom: 20 }}>
        <strong>AI Response:</strong>

        <div
          style={{
            marginTop: 10,
            padding: 15,
            background: "#0d1117",
            borderRadius: 8,
            border: "1px solid #30363d",
            whiteSpace: "pre-wrap",
          }}
        >
          {data.response?.answer ||
            data.response?.message ||
            "No AI response"}
        </div>
      </div>

      {/* Response Security */}
      <div style={{ marginBottom: 20 }}>
        <strong>Response Security:</strong>

        <div
          style={{
            marginTop: 10,
            color: getRiskColor(responseSecurity.riskLevel),
          }}
        >
          {responseSecurity.decision}
        </div>
      </div>

      {/* Compliance */}
      <div style={{ marginBottom: 20 }}>
        <strong>Compliance:</strong>

        <div style={{ marginTop: 10 }}>
          ✅ NIS2 <br />
          ✅ GDPR <br />
          ✅ ISO27001
        </div>
      </div>

      {/* Raw JSON */}
      <details style={{ marginTop: 30 }}>
        <summary style={{ cursor: "pointer" }}>
          View technical JSON
        </summary>

        <pre
          style={{
            marginTop: 15,
            background: "#000",
            color: "#0f0",
            padding: 20,
            borderRadius: 8,
            overflow: "auto",
            maxHeight: 500,
          }}
        >
          {JSON.stringify(
            {
              ...data,
              originalPrompt: undefined,
              originalText: undefined,
              originalAnswer: undefined,
              tokenMap: undefined,
            },
            null,
            2
          )}
        </pre>
      </details>
    </div>
  );
}