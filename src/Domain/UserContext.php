<?php
declare(strict_types=1);
namespace App\Domain;
final class UserContext {
    public function __construct(
        public readonly string $email,
        public readonly array $roles,
        public readonly string $department,
        public readonly string $country,
        public readonly bool $mfaVerified,
        public readonly string $deviceTrust,
        public readonly string $location,
    ) {}
    public static function fromArray(array $d): self {
        return new self((string)($d['email'] ?? ''), array_values($d['roles'] ?? []), (string)($d['department'] ?? 'General'), strtoupper((string)($d['country'] ?? 'BE')), (bool)($d['mfa_verified'] ?? false), strtolower((string)($d['device_trust'] ?? 'unknown')), (string)($d['location'] ?? 'unknown'));
    }
}
