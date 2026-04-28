import { useState } from "react";

function getApiBase() {
  const origin = window.location.origin;

  // GitHub Codespaces: ...-5173.app.github.dev -> ...-8080.app.github.dev
  if (origin.includes("-5173.app.github.dev")) {
    return origin.replace("-5173.app.github.dev", "-8080.app.github.dev");
  }

  // Local dev fallback
  if (origin.includes(":5173")) {
    return origin.replace(":5173", ":8080");
  }

  return "http://localhost:8080";
}

const API_BASE = getApiBase();
console.log("API_BASE =", API_BASE);

export default function App() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [token, setToken] = useState("");
  const [prompt, setPrompt] = useState(
    "Bonjour mon ami s'appelle Jean-Paul avec l'email jp.dupont@cidns.eu et son numero de compte est BE80 2666 4888 5225"
  );
  const [result, setResult] = useState("");
  const [status, setStatus] = useState("");

  const handleLogin = async () => {
    setStatus("Connexion à Keycloak...");
    setResult("");

    try {
      const res = await fetch(`${API_BASE}/login/keycloak`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        mode: "cors",
        body: JSON.stringify({
          username,
          password,
        }),
      });

      const text = await res.text();
      let data;

      try {
        data = text ? JSON.parse(text) : {};
      } catch {
        data = { raw: text };
      }

      if (!res.ok) {
        setStatus("Login failed");
        setResult(JSON.stringify(data, null, 2));
        alert("Login failed: " + JSON.stringify(data));
        return;
      }

      setToken(data.access_token);
      setStatus("Login OK ✅");
      setResult(JSON.stringify({ ok: true, message: "Login OK", api: API_BASE }, null, 2));
    } catch (err) {
      console.error("LOGIN ERROR:", err);
      setStatus("Erreur connexion API");
      setResult(
        JSON.stringify(
          {
            ok: false,
            error: "Erreur connexion API",
            message: err.message,
            api: API_BASE,
          },
          null,
          2
        )
      );
      alert("Erreur connexion API: " + err.message + "\nAPI_BASE=" + API_BASE);
    }
  };

  const handleAnalyze = async () => {
    if (!token) {
      alert("Login first !");
      return;
    }

    setStatus("Analyse en cours...");

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
        mode: "cors",
        body: JSON.stringify({
          prompt,
          modelType: "public_llm",
          frameworks: ["NIS2", "GDPR", "ISO27001"],
        }),
      });

      const text = await res.text();
      let data;

      try {
        data = text ? JSON.parse(text) : {};
      } catch {
        data = { raw: text };
      }

      setStatus(res.ok ? "Analyse OK ✅" : "Analyse failed");
      setResult(JSON.stringify(data, null, 2));
    } catch (err) {
      console.error("ANALYZE ERROR:", err);
      setStatus("Erreur analyse");
      setResult(
        JSON.stringify(
          {
            ok: false,
            error: "Erreur analyse",
            message: err.message,
            api: API_BASE,
          },
          null,
          2
        )
      );
    }
  };

  return (
    <div style={{ padding: 40, fontFamily: "Arial" }}>
      <h1>AI Secure Gateway</h1>

      <p>
        Secure AI access with Keycloak IAM, RBAC, MFA header, risk scoring,
        policy enforcement and audit trail.
      </p>

      <p>
        <strong>API:</strong> {API_BASE}
      </p>

      <p>
        <strong>Status:</strong> {status || "Ready"}
      </p>

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