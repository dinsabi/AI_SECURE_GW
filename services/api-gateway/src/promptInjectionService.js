import { checkPromptInjection as runPromptInjectionCheck } from "./services/promptInjectionGuard.js";

export function analyzePromptInjection(text = "") {
  return runPromptInjectionCheck(text || "");
}

export function checkInjection(text = "") {
  return runPromptInjectionCheck(text || "");
}