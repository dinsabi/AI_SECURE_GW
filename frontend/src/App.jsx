import { useState } from "react";
import MainLayout from "./layout/MainLayout.jsx";
import SocDashboard from "./components/SocDashboard.jsx";
import SecurityResult from "./components/SecurityResult.jsx";

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

export default function App() {
  const [activePage, setActivePage] = useState("dashboard");

  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [token, setToken] = useState("");

  const [modelType, setModelType] = useState("mock");

  const [prompt, setPrompt] = useState(
    "Bonjour mon ami s'appelle Jean-Paul avec l'email jp.dupont@cidns.eu et son numero de compte est BE80 2666 4888 5225"
  );

  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState("");
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
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/login/keycloak`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        mode: "cors",
        body: JSON.stringify({ username, password }),
      });

      const data = await parseResponse(res);

      if (!res.ok) {
        setStatus("Login failed");
        setResult(data);
        return;
      }

      setToken(data.access_token);
      setStatus("Login OK ✅");
      setResult({ ok: true, message: "Login OK", api: API_BASE });
    } catch (err) {
      setStatus("Erreur connexion API");
      setResult({
        ok: false,
        error: "Erreur connexion API",
        message: err.message,
        api: API_BASE,
      });
    }
  };

  const handleAnalyzePrompt = async () => {
    if (!token) {
      alert("Login first !");
      return;
    }

    setStatus("Analyse du prompt en cours...");
    setResult(null);

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
          modelType,
          frameworks: ["NIS2", "GDPR", "ISO27001"],
        }),
      });

      const data = await parseResponse(res);
      setStatus(res.ok ? "Analyse prompt OK ✅" : "Analyse prompt failed");
      setResult(data);
    } catch (err) {
      setStatus("Erreur analyse prompt");
      setResult({
        ok: false,
        error: "Erreur analyse prompt",
        message: err.message,
        api: API_BASE,
      });
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
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("modelType", modelType);
      formData.append("frameworks", "NIS2,GDPR,ISO27001");

      const res = await fetch(`${API_BASE}/v1/files/analyze`, {
        method: "POST",
        headers: { ...getAuthHeaders() },
        mode: "cors",
        body: formData,
      });

      const data = await parseResponse(res);
      setStatus(res.ok ? "Analyse fichier OK ✅" : "Analyse fichier failed");
      setResult(data);
    } catch (err) {
      setStatus("Erreur analyse fichier");
      setResult({
        ok: false,
        error: "Erreur analyse fichier",
        message: err.message,
        api: API_BASE,
      });
    }
  };

  const handleLoadDashboard = async () => {
    if (!token) {
      alert("Login first !");
      return;
    }

    setStatus("Chargement du dashboard SOC / GRC...");
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/v1/dashboard/risk-summary`, {
        method: "GET",
        headers: { Authorization: `Bearer ${token}` },
        mode: "cors",
      });

      const data = await parseResponse(res);

      if (!res.ok) {
        setStatus("Erreur dashboard SOC");
        setDashboard(null);
        setResult(data);
        return;
      }

      setDashboard(data);
      setStatus("Dashboard SOC / GRC chargé ✅");
      setResult(data);
    } catch (err) {
      setStatus("Erreur dashboard SOC");
      setDashboard(null);
      setResult({
        ok: false,
        error: "Erreur dashboard SOC",
        message: err.message,
        api: API_BASE,
      });
    }
  };

  return (
    <MainLayout activePage={activePage} setActivePage={setActivePage}>
      <div>
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

        {activePage === "dashboard" && (
          <>
            <h2>Dashboard SOC / GRC</h2>
            <button onClick={handleLoadDashboard}>Load SOC Dashboard</button>
            <SocDashboard dashboard={dashboard} />
          </>
        )}

        {activePage === "playground" && (
          <>
            <h2>AI Playground sécurisé</h2>

            <h3>1. Keycloak Login</h3>

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

            <h3 style={{ marginTop: 30 }}>2. AI Provider</h3>

            <select
              value={modelType}
              onChange={(e) => setModelType(e.target.value)}
              style={{ width: 300, padding: 6 }}
            >
              <option value="mock">Mock LLM</option>
              <option value="openai">OpenAI / ChatGPT</option>
            </select>

            <h3 style={{ marginTop: 30 }}>3. Prompt Protection</h3>

            <textarea
              rows="7"
              style={{ width: "100%" }}
              value={prompt}
              onChange={(e) => setPrompt(e.target.value)}
            />

            <br />

            <button style={{ marginTop: 10 }} onClick={handleAnalyzePrompt}>
              Analyze & Protect Prompt
            </button>

            <SecurityResult data={result} />
          </>
        )}

        {activePage === "files" && (
          <>
            <h2>File Protection</h2>

            <p>
              Formats supportés :{" "}
              <strong>.txt, .csv, .json, .log, .docx, .pdf, .xlsx, .xls</strong>
            </p>

            <input
              type="file"
              accept=".txt,.csv,.json,.log,.docx,.pdf,.xlsx,.xls"
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

            <SecurityResult data={result} />
          </>
        )}

        {activePage === "audit" && (
          <>
            <h2>Audit Logs</h2>
            <p>Charge le dashboard SOC pour voir les événements audités.</p>
            <button onClick={handleLoadDashboard}>Load Audit Logs</button>
            <SocDashboard dashboard={dashboard} />
          </>
        )}

        {activePage === "policies" && (
          <>
            <h2>Policies</h2>
            <p>
              Prochaine étape : interface de gestion des règles NIS2 / GDPR /
              ISO27001.
            </p>
          </>
        )}

        {activePage === "settings" && (
          <>
            <h2>Settings</h2>
            <p>
              Configuration future : providers IA, tenants, secrets, policies,
              SIEM.
            </p>
          </>
        )}
      </div>
    </MainLayout>
  );
}