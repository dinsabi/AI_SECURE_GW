export async function callOpenAI({ openai, model, prompt }) {
  if (!process.env.OPENAI_API_KEY) {
    return {
      provider: "openai",
      error: true,
      message: "OPENAI_API_KEY is missing.",
    };
  }

  try {
    const completion = await openai.chat.completions.create({
      model,
      messages: [
        {
          role: "system",
          content:
            "You are a secure enterprise AI assistant operating behind an AI Secure Gateway. Never reveal sensitive data. Work only with protected/tokenized content.",
        },
        {
          role: "user",
          content: prompt,
        },
      ],
      temperature: 0.2,
    });

    return {
      provider: "openai",
      model: completion.model,
      answer: completion.choices?.[0]?.message?.content || "",
      usage: completion.usage,
    };
  } catch (error) {
    return {
      provider: "openai",
      error: true,
      message: error.message,
    };
  }
}

export async function callMockLLM({ prompt, modelType }) {
  const llmUrl = process.env.LLM_URL || "http://llm-mock:3006";

  try {
    const response = await fetch(`${llmUrl}/generate`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ prompt, modelType }),
    });

    if (!response.ok) {
      return {
        provider: "mock-llm",
        error: true,
        answer: `LLM mock returned HTTP ${response.status}`,
      };
    }

    return await response.json();
  } catch (error) {
    return {
      provider: "mock-llm",
      error: true,
      answer: "LLM mock indisponible",
      warning: error.message,
    };
  }
}

export async function routeLLM({
  openai,
  prompt,
  modelType,
  user,
  protection,
}) {
  const requestedModel = String(modelType || "openai").toLowerCase();

  if (
    protection?.riskLevel === "CRITICAL" &&
    requestedModel === "openai" &&
    user?.department === "Finance"
  ) {
    return {
      provider: "gateway-policy",
      routedTo: "none",
      answer:
        "Request requires review before sending critical Finance content to OpenAI.",
      routingDecision: "REVIEW_REQUIRED",
    };
  }

  if (requestedModel === "openai" || requestedModel === "chatgpt") {
    const result = await callOpenAI({
      openai,
      model: process.env.OPENAI_MODEL || "gpt-4o-mini",
      prompt,
    });

    return {
      ...result,
      routedTo: "openai",
      routingDecision: "ROUTE_TO_OPENAI",
    };
  }

  if (requestedModel === "mock" || requestedModel === "public_llm") {
    const result = await callMockLLM({
      prompt,
      modelType,
    });

    return {
      ...result,
      routedTo: "mock",
      routingDecision: "ROUTE_TO_MOCK",
    };
  }

  return {
    provider: "gateway-policy",
    routedTo: "none",
    error: true,
    answer: `Unsupported modelType: ${modelType}`,
    routingDecision: "UNSUPPORTED_MODEL",
  };
}