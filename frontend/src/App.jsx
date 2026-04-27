import { useState } from "react";

const API_BASE = window.location.origin.replace("-5173", "-8080");

export default function App() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [token, setToken] = useState("");
  const [prompt, setPrompt] = useState("");
  const [result, setResult] = useState("");

  // ========================
  // LOGIN KEYCLOAK
  // ========================
  const handleLogin = async () => {
    try {
      const res = await fetch(`${API_BASE}/login/keycloak`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username,
          password,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        alert("Login failed: " + JSON.stringify(data));
        return;
      }

      setToken(data.access_token);
      alert("Login OK ✅");
    } catch (err) {
      console.error(err);
      alert("Erreur connexion API");
    }
  };

  // ========================
  // ANALYSE PROMPT
  // ========================
  const handleAnalyze = async () => {
    if (!token) {
      alert("Login first !");
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/v1/gateway/process`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
          "X-User-Email": username,
          "X-User-Department": "Finance",
          "X-User-Roles": "admin,finance_manager",
          "X-User-Country": "BE",
          "X-MFA-Verified": "true",
        },
        body: JSON.stringify({
          prompt,
          modelType: "public_llm",
          frameworks: ["NIS2", "GDPR", "ISO27001"],
        }),
      });

      const data = await res.json();

      setResult(JSON.stringify(data, null, 2));
    } catch (err) {
      console.error(err);
      alert("Erreur analyse");
    }
  };

  return (
    <div style={{ padding: 40, fontFamily: "Arial" }}>
      <h1>AI Secure Gateway</h1>

      <p>
        Secure AI access with Keycloak IAM, RBAC, MFA header, risk scoring,
        policy enforcement and audit trail.
      </p>

      {/* LOGIN */}
      <div style={{ marginTop: 30 }}>
        <h2>Keycloak Login</h2>

        <input
          placeholder="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={{ display: "block", marginBottom: 10, width: 300 }}
        />

        <input
          type="password"
          placeholder="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{ display: "block", marginBottom: 10, width: 300 }}
        />

        <button onClick={handleLogin}>Login with Keycloak</button>
      </div>

      {/* PROMPT */}
      <div style={{ marginTop: 30 }}>
        <textarea
          rows="6"
          style={{ width: "100%" }}
          placeholder="Enter your prompt..."
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
        />
      </div>

      <button style={{ marginTop: 10 }} onClick={handleAnalyze}>
        Analyze & Send Prompt
      </button>

      {/* RESULT */}
      <pre
        style={{
          marginTop: 20,
          background: "#111",
          color: "#0f0",
          padding: 20,
          whiteSpace: "pre-wrap",
        }}
      >
        {result}
      </pre>
    </div>
  );
}