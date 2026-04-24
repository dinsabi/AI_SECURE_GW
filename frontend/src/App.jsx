import React, { useState } from "react";

export default function App() {
  const [prompt, setPrompt] = useState("");
  const [response, setResponse] = useState("");
  const [token, setToken] = useState("");

  const API_URL = "/api"; // passe par nginx

  const login = async () => {
    const res = await fetch(`${API_URL}/login/mock`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      }
    });

    const data = await res.json();
    setToken(data.token);
  };

  const sendPrompt = async () => {
    const res = await fetch(`${API_URL}/v1/generate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        "X-MFA-Verified": "true"
      },
      body: JSON.stringify({
        prompt,
        modelType: "public_llm"
      })
    });

    const data = await res.json();
    setResponse(JSON.stringify(data, null, 2));
  };

  return (
    <div style={{ padding: 30, fontFamily: "Arial" }}>
      <h1>AI Secure Gateway</h1>

      <button onClick={login}>Login (Mock)</button>

      <div style={{ marginTop: 20 }}>
        <textarea
          rows="5"
          cols="60"
          placeholder="Enter your prompt..."
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
        />
      </div>

      <div style={{ marginTop: 10 }}>
        <button onClick={sendPrompt}>Send Prompt</button>
      </div>

      <pre style={{ marginTop: 20, background: "#eee", padding: 10 }}>
        {response}
      </pre>
    </div>
  );
}