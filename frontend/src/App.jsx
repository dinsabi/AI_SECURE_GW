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

export default function App() {
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin");
  const [token, setToken] = useState("");

  const [prompt, setPrompt] = useState(
    "Bonjour mon email est jp.dupont@cidns.eu, mon IBAN est BE80 2666 4888 5225, ma clé AWS est AKIAIOSFODNN7EXAMPLE, password=SuperSecret123 et token GitHub ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"
  );

  const [modelType, setModelType] = useState("mock_llm");
  const [result, setResult] = useState(null);
  const [status, setStatus] = useState("");
  const [file, setFile] = useState(null);
  const [fileResult, setFileResult] = useState(null);

  async function handleLogin(e) {
    e.preventDefault();
    setStatus("Login en cours...");

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

      console.log("LOGIN RESULT =", data);

      if (!res.ok || !data.ok) {
        throw new Error(data.error || "Login failed");
      }

      setToken(data.access_token || data.token || "demo-token");
      setStatus("Login réussi");
    } catch (error) {
      console.error("Login error:", error);
      setStatus(`Login failed: ${error.message}`);
    }
  }

  async function handleAnalyzePrompt() {
    setStatus("Analyse du prompt en cours...");
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/v1/gateway/process`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          prompt,
          modelType,
        }),
      });

      const data = await res.json();

      console.log("ANALYZE RESULT =", data);
      console.log("PROTECTED CONTENT =", data.protectedContent);

      if (!res.ok || !data.ok) {
        throw new Error(data.error || "Analyse failed");
      }

      setResult(data);
      setStatus("Analyse terminée");
    } catch (error) {
      console.error("Analyze prompt error:", error);
      setStatus(`Analyse failed: ${error.message}`);
    }
  }

  async function handleGenerate() {
    setStatus("Génération en cours...");
    setResult(null);

    try {
      const res = await fetch(`${API_BASE}/v1/gateway/generate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          prompt,
          modelType,
        }),
      });

      const data = await res.json();

      console.log("GENERATE RESULT =", data);

      if (!res.ok || !data.ok) {
        throw new Error(data.error || "Generate failed");
      }

      setResult(data);
      setStatus("Génération terminée");
    } catch (error) {
      console.error("Generate error:", error);
      setStatus(`Generate failed: ${error.message}`);
    }
  }

  async function handleAnalyzeFile() {
    if (!file) {
      setStatus("Sélectionne d’abord un fichier");
      return;
    }

    setStatus("Analyse fichier en cours...");
    setFileResult(null);

    try {
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch(`${API_BASE}/v1/files/analyze`, {
        method: "POST",
        headers: {
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: formData,
      });

      const data = await res.json();

      console.log("FILE ANALYZE RESULT =", data);

      if (!res.ok || !data.ok) {
        throw new Error(data.error || "Analyse fichier failed");
      }

      setFileResult(data);
      setStatus("Analyse fichier terminée");
    } catch (error) {
      console.error("File analyze error:", error);
      setStatus(`Analyse fichier failed: ${error.message}`);
    }
  }

  const activeResult = result || fileResult;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-7xl px-6 py-8">
        <header className="mb-8 rounded-2xl border border-cyan-500/30 bg-slate-900 p-6 shadow-lg shadow-cyan-900/20">
          <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between">
            <div>
              <h1 className="text-3xl font-bold text-cyan-300">
                AI Secure Gateway
              </h1>
              <p className="text-sm text-slate-400">
                Zero Trust AI Prompt Firewall · DLP · NIS2 · ISO27001 · RGPD
              </p>
            </div>

            <div className="rounded-xl bg-slate-800 px-4 py-2 text-sm text-slate-300">
              API: <span className="text-cyan-300">{API_BASE}</span>
            </div>
          </div>
        </header>

        <main className="grid gap-6 lg:grid-cols-3">
          <section className="space-y-6 lg:col-span-1">
            <div className="rounded-2xl border border-slate-700 bg-slate-900 p-5">
              <h2 className="mb-4 text-xl font-semibold text-cyan-300">
                Login
              </h2>

              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="mb-1 block text-sm text-slate-400">
                    Username
                  </label>
                  <input
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-cyan-400"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>

                <div>
                  <label className="mb-1 block text-sm text-slate-400">
                    Password
                  </label>
                  <input
                    type="password"
                    className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-cyan-400"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </div>

                <button
                  type="submit"
                  className="w-full rounded-xl bg-cyan-500 px-4 py-2 font-semibold text-slate-950 hover:bg-cyan-400"
                >
                  Login
                </button>
              </form>

              <div className="mt-4 text-sm">
                Token:{" "}
                {token ? (
                  <span className="text-emerald-400">Connected</span>
                ) : (
                  <span className="text-red-400">Not connected</span>
                )}
              </div>
            </div>

            <div className="rounded-2xl border border-slate-700 bg-slate-900 p-5">
              <h2 className="mb-4 text-xl font-semibold text-cyan-300">
                Analyse fichier
              </h2>

              <input
                type="file"
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-sm"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
              />

              <button
                onClick={handleAnalyzeFile}
                className="mt-4 w-full rounded-xl bg-indigo-500 px-4 py-2 font-semibold text-white hover:bg-indigo-400"
              >
                Analyze File
              </button>
            </div>

            <div className="rounded-2xl border border-slate-700 bg-slate-900 p-5">
              <h2 className="mb-2 text-xl font-semibold text-cyan-300">
                Status
              </h2>
              <p className="text-sm text-slate-300">{status || "Idle"}</p>
            </div>
          </section>

          <section className="space-y-6 lg:col-span-2">
            <div className="rounded-2xl border border-slate-700 bg-slate-900 p-5">
              <h2 className="mb-4 text-xl font-semibold text-cyan-300">
                Prompt Inspection
              </h2>

              <label className="mb-1 block text-sm text-slate-400">
                Model Type
              </label>
              <select
                className="mb-4 w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-cyan-400"
                value={modelType}
                onChange={(e) => setModelType(e.target.value)}
              >
                <option value="mock_llm">Mock LLM</option>
                <option value="openai">OpenAI</option>
                <option value="public_llm">Public LLM</option>
                <option value="private_llm">Private LLM</option>
              </select>

              <label className="mb-1 block text-sm text-slate-400">
                Prompt
              </label>
              <textarea
                rows={8}
                className="w-full rounded-xl border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-cyan-400"
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
              />

              <div className="mt-4 flex flex-col gap-3 md:flex-row">
                <button
                  onClick={handleAnalyzePrompt}
                  className="rounded-xl bg-cyan-500 px-4 py-2 font-semibold text-slate-950 hover:bg-cyan-400"
                >
                  Analyze Prompt
                </button>

                <button
                  onClick={handleGenerate}
                  className="rounded-xl bg-emerald-500 px-4 py-2 font-semibold text-slate-950 hover:bg-emerald-400"
                >
                  Generate via Gateway
                </button>
              </div>
            </div>

            {activeResult && (
              <div className="rounded-2xl border border-slate-700 bg-slate-900 p-5">
                <h2 className="mb-4 text-xl font-semibold text-cyan-300">
                  Security Result
                </h2>

                <div className="grid gap-4 md:grid-cols-4">
                  <div className="rounded-xl bg-slate-950 p-4">
                    <div className="text-xs uppercase text-slate-500">
                      Decision
                    </div>
                    <div className="mt-1 text-lg font-bold text-cyan-300">
                      {activeResult.decision || "UNKNOWN"}
                    </div>
                  </div>

                  <div className="rounded-xl bg-slate-950 p-4">
                    <div className="text-xs uppercase text-slate-500">
                      Risk Score
                    </div>
                    <div className="mt-1 text-lg font-bold text-cyan-300">
                      {activeResult.riskScore ?? 0}
                    </div>
                  </div>

                  <div className="rounded-xl bg-slate-950 p-4">
                    <div className="text-xs uppercase text-slate-500">
                      Risk Level
                    </div>
                    <div className="mt-1 text-lg font-bold text-cyan-300">
                      {activeResult.riskLevel || "LOW"}
                    </div>
                  </div>

                  <div className="rounded-xl bg-slate-950 p-4">
                    <div className="text-xs uppercase text-slate-500">
                      DLP Findings
                    </div>
                    <div className="mt-1 text-lg font-bold text-cyan-300">
                      {activeResult.dlpFindings ?? 0}
                    </div>
                  </div>
                </div>

                <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950 p-4">
                  <h3 className="mb-2 font-semibold text-cyan-300">
                    Protected Content
                  </h3>

                  <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-slate-900 p-3 text-sm text-slate-200">
                    {activeResult.protectedContent &&
                    activeResult.protectedContent.trim()
                      ? activeResult.protectedContent
                      : "No protected content"}
                  </pre>
                </div>

                {activeResult.answer && (
                  <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950 p-4">
                    <h3 className="mb-2 font-semibold text-cyan-300">
                      LLM Answer
                    </h3>
                    <pre className="whitespace-pre-wrap break-words rounded-lg bg-slate-900 p-3 text-sm text-slate-200">
                      {activeResult.answer}
                    </pre>
                  </div>
                )}

                {activeResult.message && (
                  <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950 p-4">
                    <h3 className="mb-2 font-semibold text-cyan-300">
                      Message
                    </h3>
                    <p className="text-sm text-slate-300">
                      {activeResult.message}
                    </p>
                  </div>
                )}

                {Array.isArray(activeResult.findings) &&
                  activeResult.findings.length > 0 && (
                    <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950 p-4">
                      <h3 className="mb-3 font-semibold text-cyan-300">
                        Findings
                      </h3>

                      <div className="overflow-auto">
                        <table className="w-full text-left text-sm">
                          <thead className="text-slate-400">
                            <tr>
                              <th className="border-b border-slate-700 py-2">
                                Type
                              </th>
                              <th className="border-b border-slate-700 py-2">
                                Severity
                              </th>
                              <th className="border-b border-slate-700 py-2">
                                Frameworks
                              </th>
                              <th className="border-b border-slate-700 py-2">
                                Value
                              </th>
                            </tr>
                          </thead>
                          <tbody>
                            {activeResult.findings.map((finding, index) => (
                              <tr key={`${finding.type}-${index}`}>
                                <td className="border-b border-slate-800 py-2 text-slate-200">
                                  {finding.type}
                                </td>
                                <td className="border-b border-slate-800 py-2 text-slate-200">
                                  {finding.severity}
                                </td>
                                <td className="border-b border-slate-800 py-2 text-slate-300">
                                  {Array.isArray(finding.frameworks)
                                    ? finding.frameworks.join(", ")
                                    : ""}
                                </td>
                                <td className="border-b border-slate-800 py-2 text-slate-400">
                                  {String(finding.value || "").slice(0, 80)}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}

                <details className="mt-5 rounded-xl border border-slate-700 bg-slate-950 p-4">
                  <summary className="cursor-pointer font-semibold text-cyan-300">
                    Raw JSON Debug
                  </summary>
                  <pre className="mt-3 max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-slate-900 p-3 text-xs text-slate-300">
                    {JSON.stringify(activeResult, null, 2)}
                  </pre>
                </details>
              </div>
            )}

            <SocDashboard data={activeResult} />
          </section>
        </main>
      </div>
    </div>
  );
}