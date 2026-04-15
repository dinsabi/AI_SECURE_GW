<?php
declare(strict_types=1);
namespace App\Infrastructure;
final class JsonStore {
    public function __construct(private readonly string $file) {
        $dir = dirname($this->file); if (!is_dir($dir)) mkdir($dir, 0777, true);
        if (!file_exists($this->file)) file_put_contents($this->file, json_encode(new \stdClass()));
    }
    public function read(): array { $d = json_decode(file_get_contents($this->file) ?: '{}', true); return is_array($d) ? $d : []; }
    public function write(array $data): void { file_put_contents($this->file, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); }
}
