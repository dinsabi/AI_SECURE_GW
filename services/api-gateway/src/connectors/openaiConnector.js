const OPENAI_API_KEY = process.env.OPENAI_API_KEY;

export async function callOpenAI(prompt) {
  if (!OPENAI_API_KEY) {
    throw new Error("OPENAI_API_KEY missing");
  }

  const response = await fetch(
    "https://api.openai.com/v1/chat/completions",
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model: "gpt-4.1-mini",
        messages: [
          {
            role: "system",
            content:
              "You are a secure enterprise AI assistant operating behind a Zero Trust AI Gateway.",
          },
          {
            role: "user",
            content: prompt,
          },
        ],
        temperature: 0.2,
      }),
    }
  );

  const data = await response.json();

  if (!response.ok) {
    throw new Error(JSON.stringify(data));
  }

  return {
    provider: "openai",
    model: data.model,
    answer: data.choices?.[0]?.message?.content || "",
    usage: data.usage,
  };
}