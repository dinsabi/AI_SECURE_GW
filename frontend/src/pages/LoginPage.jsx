import { useState } from "react";
import { Alert, Snackbar } from "@mui/material";

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

export default function App() {
  const [activePage, setActivePage] = useState("security");

  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [token, setToken] = useState("");

  const [modelType, setModelType] = useState("mock");

  const [prompt, setPrompt] = useState(
    "Bonjour mon ami s'appelle Jean-Paul avec l'email jp.dupont@cidns.eu et son numero de compte est BE80 2666 4888 5225"
  );

  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState("Ready");
  const [dashboard, setDashboard] = useState(null);

  const [loading, setLoading] = useState(false);

  const [notification, setNotification] = useState({
    open: false,
    type: "info",
    message: "",
  });

  const notify = (type, message) => {
    setNotification({
      open: true,
      type,
      message,
    });
  };

  const closeNotification = () => {
    setNotification((prev) => ({
      ...prev,
      open: false,
    }));
  };

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
    setLoading(true);
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
        notify("error", "Login failed. Vérifie Keycloak ou les credentials.");
        return;
      }

      setToken(data.access_token);
      setStatus("Login OK ✅");
      setResult(null);
      setActivePage("security");
      notify("success", "Connexion réussie avec Keycloak.");
    } catch (err) {
      console.error("LOGIN ERROR:", err);
      setStatus("Erreur connexion API");
      setResult({
        ok: false,
        error: "Erreur connexion API",
        message: err.message,
        api: API_BASE,
      });
      notify("error", `Erreur connexion API : ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    setToken("");
    setResult(null);
    setDashboard(null);
    setStatus("Déconnecté");
    setActivePage("security");
    notify("info", "Déconnexion effectuée.");
  };

  const handleAnalyzePrompt = async () => {
    if (!token) {
      notify("warning", "Login first !");
      return;
    }

    setLoading(true);
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

      if (res.ok) {
        notify("success", "Prompt analysé et protégé avec succès.");
      } else {
        notify("warning", "Le prompt a été bloqué ou nécessite une revue.");
      }
    } catch (err) {
      console.error("PROMPT ANALYZE ERROR:", err);
      setStatus("Erreur analyse prompt");
      setResult({
        ok: false,
        error: "Erreur analyse prompt",
        message: err.message,
        api: API_BASE,
      });
      notify("error", `Erreur analyse prompt : ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleAnalyzeFile = async () => {
    if (!token) {
      notify("warning", "Login first !");
      return;
    }

    if (!file) {
      notify("warning", "Sélectionne d’abord un fichier.");
      return;
    }

    setLoading(true);
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

      if (res.ok) {
        notify("success", "Fichier analysé et protégé avec succès.");
      } else {
        notify("warning", "Le fichier a été bloqué ou nécessite une revue.");
      }
    } catch (err) {
      console.error("FILE ANALYZE ERROR:", err);
      setStatus("Erreur analyse fichier");
      setResult({
        ok: false,
        error: "Erreur analyse fichier",
        message: err.message,
        api: API_BASE,
      });
      notify("error", `Erreur analyse fichier : ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleLoadDashboard = async () => {
    if (!token) {
      notify("warning", "Login first !");
      return;
    }

    setLoading(true);
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
        notify("error", "Erreur lors du chargement du dashboard.");
        return;
      }

      setDashboard(data);
      setStatus("Dashboard SOC / GRC chargé ✅");
      notify("success", "Dashboard SOC / GRC chargé.");
    } catch (err) {
      console.error("DASHBOARD ERROR:", err);
      setStatus("Erreur dashboard SOC");
      setDashboard(null);
      setResult({
        ok: false,
        error: "Erreur dashboard SOC",
        message: err.message,
        api: API_BASE,
      });
      notify("error", `Erreur dashboard : ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  if (!token) {
    return (
      <>
        <LoginPage
          username={username}
          setUsername={setUsername}
          password={password}
          setPassword={setPassword}
          status={status}
          loading={loading}
          onLogin={handleLogin}
        />

        <Snackbar
          open={notification.open}
          autoHideDuration={5000}
          onClose={closeNotification}
          anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
        >
          <Alert
            onClose={closeNotification}
            severity={notification.type}
            variant="filled"
            sx={{ width: "100%" }}
          >
            {notification.message}
          </Alert>
        </Snackbar>
      </>
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
          loading={loading}
          onAnalyzePrompt={handleAnalyzePrompt}
          onAnalyzeFile={handleAnalyzeFile}
        />
      );
    }

    if (activePage === "dashboard") {
      return (
        <DashboardPage
          dashboard={dashboard}
          loading={loading}
          onLoadDashboard={handleLoadDashboard}
        />
      );
    }

    return null;
  }

  return (
    <>
      <MainLayout
        activePage={activePage}
        setActivePage={setActivePage}
        username={username}
        onLogout={handleLogout}
      >
        {renderPage()}
      </MainLayout>

      <Snackbar
        open={notification.open}
        autoHideDuration={5000}
        onClose={closeNotification}
        anchorOrigin={{ vertical: "bottom", horizontal: "right" }}
      >
        <Alert
          onClose={closeNotification}
          severity={notification.type}
          variant="filled"
          sx={{ width: "100%" }}
        >
          {notification.message}
        </Alert>
      </Snackbar>
    </>
  );
}