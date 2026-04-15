<?php
declare(strict_types=1);
namespace App\Infrastructure;
final class LlmConnector {
    public function __construct(private readonly string $endpoint, private readonly string $apiKey) {}
    public function send(string $prompt, string $provider, string $modelType): array {
        if (str_contains($this->endpoint, 'example-llm-gateway.local')) {
            return ['ok' => true, 'simulated' => true, 'provider' => $provider, 'model_type' => $modelType, 'answer' => 'Réponse simulée du LLM pour le prompt sécurisé.'];
        }
        return ['ok' => false, 'error' => 'Configure a real LLM endpoint'];
    }
}
