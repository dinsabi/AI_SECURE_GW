import React, { useState } from 'react';

export default function App() {
  const [prompt, setPrompt] = useState('');
  const [token, setToken] = useState('');
  const [response, setResponse] = useState('');

  const login = async () => {
    const res = await fetch('/api/login/mock', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'admin@cidns.eu', roles: ['admin'] })
    });

    const data = await res.json();
    setToken(data.token);
    setResponse('Login OK - token received');
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
    setResponse(JSON.stringify(data, null, 2));
  };

  return (
    <div style={{ padding: '40px', fontFamily: 'Arial', maxWidth: '900px' }}>
      <h1>AI Secure Gateway</h1>
      <p>Secure prompt gateway with JWT, RBAC and MFA header.</p>

      <button onClick={login}>Login Mock</button>

      <div style={{ marginTop: '20px' }}>
        <textarea
          rows="6"
          style={{ width: '100%' }}
          placeholder="Enter your prompt..."
          value={prompt}
          onChange={(e) => setPrompt(e.target.value)}
        />
      </div>

      <button onClick={sendPrompt} style={{ marginTop: '10px' }}>
        Send Prompt
      </button>

      <pre style={{ marginTop: '20px', background: '#eee', padding: '15px' }}>
        {response}
      </pre>
    </div>
  );
}