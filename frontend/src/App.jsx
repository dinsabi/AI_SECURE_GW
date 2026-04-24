import React, { useState } from 'react';

export default function App() {
  const [prompt, setPrompt] = useState('');
  const [token, setToken] = useState('');
  const [result, setResult] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);

  const login = async () => {
    const res = await fetch('/api/login/mock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@cidns.eu', roles: ['admin'] })
    });

    const data = await res.json();
    setToken(data.token);
    setResult({ message: 'Login successful. Token received.' });
  };

  const sendPrompt = async () => {
    const res = await fetch('/api/v1/generate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        'X-MFA-Verified': 'true'
      },
      body: JSON.stringify({
        prompt,
        modelType: 'public_llm'
      })
    });

    const data = await res.json();
    setResult(data);
    loadAuditLogs();
  };

  const loadAuditLogs = async () => {
    const res = await fetch('/api/audit');
    const data = await res.json();
    setAuditLogs(data.logs || []);
  };

  const risk = result?.security?.risk;
  const policy = result?.security?.policy;
  const findings = result?.security?.findings || [];

  const riskColors = {
    LOW: { background: '#d1fae5', color: '#065f46' },
    MEDIUM: { background: '#fef3c7', color: '#92400e' },
    HIGH: { background: '#fee2e2', color: '#991b1b' }
  };

  const actionColors = {
    allowed: { background: '#d1fae5', color: '#065f46' },
    masked: { background: '#dbeafe', color: '#1e40af' },
    blocked: { background: '#fee2e2', color: '#991b1b' },
    approval_required: { background: '#fef3c7', color: '#92400e' }
  };

  const badge = (label, style) => (
    <span
      style={{
        padding: '6px 14px',
        borderRadius: 999,
        fontWeight: 'bold',
        display: 'inline-block',
        ...style
      }}
    >
      {label}
    </span>
  );

  return (
    <div style={{ padding: 40, fontFamily: 'Arial', maxWidth: 1200 }}>
      <h1>AI Secure Gateway</h1>
      <p>Secure AI access with IAM, RBAC, MFA, risk scoring, policy enforcement and audit trail.</p>

      <button onClick={login}>Login Mock</button>
      <button onClick={loadAuditLogs} style={{ marginLeft: 10 }}>
        Load Audit Logs
      </button>

      {token && (
        <span style={{ marginLeft: 12, color: '#065f46', fontWeight: 'bold' }}>
          Authenticated
        </span>
      )}

      <div style={{ marginTop: 25 }}>
        <textarea
          rows="7"
          style={{
            width: '100%',
            padding: 12,
            fontSize: 15,
            borderRadius: 8,
            border: '1px solid #ccc'
          }}
          placeholder="Example: Bonjour, mon email est jean.dupont@cidns.eu et mon IBAN est BE68539007547034"
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
        />
      </div>

      <button onClick={sendPrompt} style={{ marginTop: 12 }}>
        Analyze & Send Prompt
      </button>

      {risk && policy && (
        <div style={{ marginTop: 25, padding: 20, border: '1px solid #ddd', borderRadius: 12, background: '#fafafa' }}>
          <h2>Security Decision</h2>

          <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
            <strong>Risk:</strong>
            {badge(risk.level, riskColors[risk.level])}

            <strong>Score:</strong>
            <span>{risk.score}/100</span>

            <strong>Action:</strong>
            {badge(policy.action, actionColors[policy.action])}
          </div>

          <p><strong>Findings:</strong> {findings.length > 0 ? findings.join(', ') : 'None'}</p>
          <p><strong>Policy:</strong> {policy.policy}</p>
          <p><strong>Decision reason:</strong> {policy.reason}</p>
          <p><strong>Recommendation:</strong> {risk.recommendation}</p>
        </div>
      )}

      {result?.provider_response && (
        <div style={{ marginTop: 25, padding: 20, border: '1px solid #ddd', borderRadius: 12 }}>
          <h2>LLM Response</h2>
          <p>{result.provider_response.answer}</p>
        </div>
      )}

      {result?.status === 'blocked' || result?.status === 'approval_required' ? (
        <div style={{ marginTop: 25, padding: 20, border: '1px solid #fca5a5', borderRadius: 12, background: '#fee2e2', color: '#991b1b' }}>
          <h2>Request Not Sent to LLM</h2>
          <p>{result.message}</p>
        </div>
      ) : null}

      {auditLogs.length > 0 && (
        <div style={{ marginTop: 30 }}>
          <h2>Audit Trail</h2>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr>
                <th style={th}>Time</th>
                <th style={th}>User</th>
                <th style={th}>Findings</th>
                <th style={th}>Risk</th>
                <th style={th}>Action</th>
                <th style={th}>Status</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.map((log) => (
                <tr key={log.id}>
                  <td style={td}>{new Date(log.timestamp).toLocaleString()}</td>
                  <td style={td}>{log.user_email}</td>
                  <td style={td}>{log.findings || '-'}</td>
                  <td style={td}>{log.risk_level} ({log.risk_score})</td>
                  <td style={td}>{log.policy_action}</td>
                  <td style={td}>{log.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {result && (
        <pre style={{ marginTop: 25, background: '#eee', padding: 15, overflow: 'auto' }}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  );
}

const th = {
  border: '1px solid #ddd',
  padding: 8,
  background: '#f3f4f6',
  textAlign: 'left'
};

const td = {
  border: '1px solid #ddd',
  padding: 8
};