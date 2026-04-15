<?php
declare(strict_types=1);
namespace App\Domain;
final class GatewayRequest {
    public function __construct(
        public readonly UserContext $user,
        public readonly string $prompt,
        public readonly string $modelType,
        public readonly array $frameworks,
        public readonly bool $callLlm,
        public readonly array $documentIds,
    ) {}
    public static function fromArray(array $payload): self {
        $r = $payload['request'] ?? [];
        return new self(
            UserContext::fromArray($payload['user'] ?? []),
            trim((string)($r['prompt'] ?? '')),
            strtolower((string)($r['model_type'] ?? 'private_llm')),
            array_values(array_map('strtoupper', $r['frameworks'] ?? [])),
            (bool)($r['call_llm'] ?? false),
            array_values($r['document_ids'] ?? [])
        );
    }
}
