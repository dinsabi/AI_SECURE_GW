import { useState } from "react";

import MainLayout from "./layout/MainLayout.jsx";

import LoginPage from "./pages/LoginPage.jsx";
import SecurityConsolePage from "./pages/SecurityConsolePage.jsx";
import DashboardPage from "./pages/DashboardPage.jsx";

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
  const [activePage, setActivePage] = useState("security");

  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [token, setToken] = useState("");

  const [modelType, setModelType] = useState("mock");

  const [prompt, setPrompt] = useState(
    "Bonjour mon ami s'appelle Jean-Paul avec l'email jp.dupont@cidns.eu et son numero de compte est BE80 2666 4888 5225, Voici une clé AWS AKIAIOSFODNN7EXAMPLE, un JWT eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.signature, un password=SuperSecret123 et un GitHub token ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"
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
        setResult(data);
        return;
      }

      setToken(data.access_token);
      setStatus("Login OK ✅");
      setResult(null);
      setActivePage("security");
    } catch (err) {
      console.error("LOGIN ERROR:", err);
      setStatus("Erreur connexion API");
      setResult({
        ok: false,
        error: "Erreur connexion API",
        message: err.message,
        name: err.name,
        api: API_BASE,
        origin: window.location.origin,
      });
    }
  };

  const handleLogout = () => {
    setToken("");
    setResult(null);
    setDashboard(null);
    setStatus("Déconnecté");
    setActivePage("security");
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
      console.error("PROMPT ANALYZE ERROR:", err);
      setStatus("Erreur analyse prompt");
      setResult({
        ok: false,
        error: "Erreur connexion API",
        message: err.message,
        name: err.name,
        api: API_BASE,
        origin: window.location.origin,
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
        headers: {
          ...getAuthHeaders(),
        },
        mode: "cors",
        body: formData,
      });

      const data = await parseResponse(res);

      setStatus(res.ok ? "Analyse fichier OK ✅" : "Analyse fichier failed");
      setResult(data);
    } catch (err) {
      console.error("FILE ANALYZE ERROR:", err);
      setStatus("Erreur analyse fichier");
      setResult({
        ok: false,
        error: "Erreur connexion API",
        message: err.message,
        name: err.name,
        api: API_BASE,
        origin: window.location.origin,
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
        headers: {
          Authorization: `Bearer ${token}`,
        },
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
    } catch (err) {
      console.error("DASHBOARD ERROR:", err);
      setStatus("Erreur dashboard SOC");
      setDashboard(null);
      setResult({
        ok: false,
        error: "Erreur connexion API",
        message: err.message,
        name: err.name,
        api: API_BASE,
        origin: window.location.origin,
      });
    }
  };

  if (!token) {
    return (
      <LoginPage
        username={username}
        setUsername={setUsername}
        password={password}
        setPassword={setPassword}
        status={status}
        result={result}
        onLogin={handleLogin}
      />
    );
  }

  function renderPage() {
    if (activePage === "security") {
      return (
        <SecurityConsolePage
          modelType={modelType}
          setModelType={setModelType}
          prompt={prompt}
          setPrompt={setPrompt}
          file={file}
          setFile={setFile}
          result={result}
          status={status}
          onAnalyzePrompt={handleAnalyzePrompt}
          onAnalyzeFile={handleAnalyzeFile}
        />
      );
    }

    if (activePage === "dashboard") {
      return (
        <DashboardPage
          dashboard={dashboard}
          onLoadDashboard={handleLoadDashboard}
        />
      );
    }

    return (
      <SecurityConsolePage
        modelType={modelType}
        setModelType={setModelType}
        prompt={prompt}
        setPrompt={setPrompt}
        file={file}
        setFile={setFile}
        result={result}
        status={status}
        onAnalyzePrompt={handleAnalyzePrompt}
        onAnalyzeFile={handleAnalyzeFile}
      />
    );
  }

  return (
    <MainLayout
      activePage={activePage}
      setActivePage={setActivePage}
      username={username}
      onLogout={handleLogout}
    >
      {renderPage()}
    </MainLayout>
  );

}