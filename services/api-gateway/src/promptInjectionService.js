import { checkPromptInjection as runPromptInjectionCheck } from "./promptInjectionGuard.js";

export function analyzePromptInjection(text = "") {
  return runPromptInjectionCheck(text || "");
}

export function checkInjection(text = "") {
  return runPromptInjectionCheck(text || "");
}