import { checkPromptInjection } from "./promptInjectionGuard.js";

export function analyzePrompt(text = "") {
  return checkPromptInjection(text);
}