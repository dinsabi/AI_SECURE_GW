<?php
declare(strict_types=1);
namespace App\Infrastructure;
final class AuditLogger {
    public function __construct(private readonly string $file) {
        $dir = dirname($this->file); if (!is_dir($dir)) mkdir($dir, 0777, true);
    }
    public function record(string $event, array $context = []): array {
        $entry = ['timestamp' => date('c'), 'event' => $event, 'context' => $context];
        file_put_contents($this->file, json_encode($entry, JSON_UNESCAPED_UNICODE) . PHP_EOL, FILE_APPEND);
        return $entry;
    }
}
