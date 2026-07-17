<?php

namespace Finext\LicenseClient\Services;

/**
 * Mirrors app/Services/Security/HmacSigner.php on the license server
 * byte-for-byte — any divergence here produces a canonical string that
 * doesn't match what the server recomputes, and every signed request would
 * fail with `invalid_signature`. If you change one side, change both.
 */
class HmacSigner
{
    public static function canonicalString(string $method, string $path, array $body, string $timestamp, string $nonce): string
    {
        return implode("\n", [
            strtoupper($method),
            $path,
            static::canonicalJson($body),
            $timestamp,
            $nonce,
        ]);
    }

    public static function canonicalJson(array $data): string
    {
        return json_encode(static::sortRecursively($data), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    protected static function sortRecursively(array $data): array
    {
        ksort($data);

        foreach ($data as $key => $value) {
            if (is_array($value)) {
                $data[$key] = static::sortRecursively($value);
            }
        }

        return $data;
    }

    public static function sign(string $canonicalString, string $secret): string
    {
        return hash_hmac('sha256', $canonicalString, $secret);
    }

    public static function verify(string $canonicalString, string $secret, string $signature): bool
    {
        return hash_equals(static::sign($canonicalString, $secret), $signature);
    }

    /**
     * Generate a random hex nonce suitable for the X-Nonce header.
     */
    public static function generateNonce(): string
    {
        return bin2hex(random_bytes(16));
    }
}
