import { useState } from "react";
import SocDashboard from "./components/SocDashboard.jsx";

function getApiBase() {
  const origin = window.location.origin;

  if (origin.includes("-5173.app.github.dev")) {
    return origin.replace("-5173.app.github.dev", "-8080.app.github.dev");
  }

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

  const [file, setFile] = useState(null);
  const [result, setResult] = useState("");
  const [status, setStatus] = useState("")
  const [dashboard, setDashboard] = useState(null);

  const parseResponse = async (res) => {
    const text = await res.text();

    try {
      return text ? JSON.parse(text) : {};
    } catch {
      return { raw: text };
    }
  };

  const getAuthHeaders = () => ({
    Authorization: `Bearer ${token}`,
    "X-User-Email": username,
    "X-User-Department": "Finance",
    "X-User-Roles": "admin,finance_manager",
    "X-User-Country": "BE",
    "X-MFA-Verified": "true",
  });

  const handleLogin = async () => {
    setStatus("Connexion à Keycloak...");
    setResult("");
    setDashboard(null);

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

      const data = await parseResponse(res);

      if (!res.ok) {
        setStatus("Login failed");
        setResult(JSON.stringify(data, null, 2));
        alert("Login failed: " + JSON.stringify(data));
        return;
      }

      setToken(data.access_token);
      setStatus("Login OK ✅");
      setResult(
        JSON.stringify(
          {
            ok: true,
            message: "Login OK",
            api: API_BASE,
          },
          null,
          2
        )
      );
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

  const handleAnalyzePrompt = async () => {
    if (!token) {
      alert("Login first !");
      return;
    }

    setStatus("Analyse du prompt en cours...");
    setResult("");
    setDashboard(null);

    try {
      const res = await fetch(`${API_BASE}/v1/gateway/process`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...getAuthHeaders(),
        },
        mode: "cors",
        body: JSON.stringify({
          prompt,
          modelType: "mock",
          frameworks: ["NIS2", "GDPR", "ISO27001"],
        }),
      });

      const data = await parseResponse(res);

      setStatus(res.ok ? "Analyse prompt OK ✅" : "Analyse prompt failed");
      setResult(JSON.stringify(data, null, 2));
    } catch (err) {
      console.error("PROMPT ANALYZE ERROR:", err);
      setStatus("Erreur analyse prompt");
      setResult(
        JSON.stringify(
          {
            ok: false,
            error: "Erreur analyse prompt",
            message: err.message,
            api: API_BASE,
          },
          null,
          2
        )
      );
    }
  };

  const handleAnalyzeFile = async () => {
    if (!token) {
      alert("Login first !");
      return;
    }

    if (!file) {
      alert("Sélectionne d’abord un fichier.");
      return;
    }

    setStatus("Analyse du fichier uploadé en cours...");
    setResult("");
    setDashboard(null);

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("modelType", "openai");
      formData.append("frameworks", "NIS2,GDPR,ISO27001");

      const res = await fetch(`${API_BASE}/v1/files/analyze`, {
        method: "POST",
        headers: {
          ...getAuthHeaders(),
        },
        mode: "cors",
        body: formData,
      });

      const data = await parseResponse(res);

      setStatus(res.ok ? "Analyse fichier OK ✅" : "Analyse fichier failed");
      setResult(JSON.stringify(data, null, 2));
    } catch (err) {
      console.error("FILE ANALYZE ERROR:", err);
      setStatus("Erreur analyse fichier");
      setResult(
        JSON.stringify(
          {
            ok: false,
            error: "Erreur analyse fichier",
            message: err.message,
            api: API_BASE,
          },
          null,
          2
        )
      );
    }
  };

  const handleLoadDashboard = async () => {
    if (!token) {
      alert("Login first !");
      return;
    }

    setStatus("Chargement du dashboard SOC / GRC...");
    setResult("");

    try {
      const res = await fetch(`${API_BASE}/v1/dashboard/risk-summary`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        mode: "cors",
      });

      const data = await parseResponse(res);

      if (!res.ok) {
        setStatus("Erreur dashboard SOC");
        setDashboard(null);
        setResult(JSON.stringify(data, null, 2));
        return;
      }

      setDashboard(data);
      setStatus("Dashboard SOC / GRC chargé ✅");
      setResult(JSON.stringify(data, null, 2));
    } catch (err) {
      console.error("DASHBOARD ERROR:", err);
      setStatus("Erreur dashboard SOC");
      setDashboard(null);
      setResult(
        JSON.stringify(
          {
            ok: false,
            error: "Erreur dashboard SOC",
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
        policy enforcement, response analysis, file protection and audit trail
        for NIS2 / GDPR / ISO27001.
      </p>

      <p>
        <strong>API:</strong> {API_BASE}
      </p>

      <p>
        <strong>Status:</strong> {status || "Ready"}
      </p>

      <hr />

      <div style={{ marginTop: 30 }}>
        <h2>1. Keycloak Login</h2>

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

      <hr style={{ marginTop: 30 }} />

      <div style={{ marginTop: 30 }}>
        <h2>2. Prompt Protection</h2>

        <p>
          Détection et tokenisation des emails, IBAN, mots de passe, clés API,
          IP internes, secrets et données sensibles avant envoi vers OpenAI.
        </p>

        <textarea
          rows="6"
          style={{ width: "100%" }}
          placeholder="Enter your prompt..."
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
        />

        <br />

        <button style={{ marginTop: 10 }} onClick={handleAnalyzePrompt}>
          Analyze & Protect Prompt
        </button>
      </div>

      <hr style={{ marginTop: 30 }} />

      <div style={{ marginTop: 30 }}>
        <h2>3. File Protection</h2>

        <p>
          Upload d’un fichier pour analyse NIS2 / GDPR / ISO27001 avant usage
          avec une IA. Formats MVP supportés :{" "}
          <strong>.txt, .csv, .json, .docx</strong>.
        </p>

        <input
          type="file"
          accept=".txt,.csv,.json,.docx"
          onChange={(e) => setFile(e.target.files?.[0] || null)}
        />

        {file && (
          <p>
            <strong>Fichier sélectionné :</strong> {file.name} —{" "}
            {(file.size / 1024).toFixed(2)} KB
          </p>
        )}

        <button style={{ marginTop: 10 }} onClick={handleAnalyzeFile}>
          Analyze Uploaded File
        </button>
      </div>

      <hr style={{ marginTop: 30 }} />

      <div style={{ marginTop: 30 }}>
        <h2>4. SOC / GRC Dashboard</h2>

        <p>
          Charge les événements PostgreSQL : prompts analysés, fichiers analysés,
          risques critiques, décisions et types de données détectées.
        </p>

        <button onClick={handleLoadDashboard}>Load SOC Dashboard</button>
      </div>

      <SocDashboard dashboard={dashboard} />

      <hr style={{ marginTop: 30 }} />

      <h2>Raw JSON Result</h2>

      <pre
        style={{
          marginTop: 20,
          background: "#111",
          color: "#0f0",
          padding: 20,
          whiteSpace: "pre-wrap",
          maxHeight: 600,
          overflow: "auto",
        }}
      >
        {result}
      </pre>
    </div>
  );
}cd 