<?php

namespace Finext\LicenseClient\Services;

/**
 * Persists the last known-good signed response for the offline grace
 * period. Two independent properties, deliberately combined:
 *
 *  - The envelope itself is Ed25519-signed by the server (see
 *    ResponseVerifier) — that's what proves *authenticity*: it can't be
 *    fabricated even by someone who fully reverse-engineers this package.
 *  - This file is additionally encrypted with a key derived from
 *    (product_id, activation_secret) — values that exist only on *this*
 *    installation and are never shipped in source. That's what prevents
 *    someone from trivially copying a "still valid" cache file from one
 *    server to another. It is deterrence, not DRM — a sufficiently
 *    motivated customer with root on their own box can still find the
 *    activation_secret in memory/config and decrypt their own cache.
 */
class EncryptedLocalCache
{
    public function __construct(private string $path)
    {
    }

    public function store(array $envelope, string $productId, string $activationSecret, \DateTimeInterface $verifiedAt): void
    {
        $key = $this->deriveKey($productId, $activationSecret);
        $payload = json_encode([
            'envelope' => $envelope,
            'verified_at' => $verifiedAt->format(DATE_ATOM),
        ]);

        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = sodium_crypto_secretbox($payload, $nonce, $key);

        $this->ensureDirectoryExists(dirname($this->path));
        file_put_contents($this->path, base64_encode($nonce.$ciphertext));
        @chmod($this->path, 0600);
    }

    /**
     * Returns null on any failure — missing file, wrong
     * product/activation-secret, or tampered ciphertext (the secretbox MAC
     * check fails closed) — never a partially-trusted result.
     */
    public function retrieve(string $productId, string $activationSecret): ?array
    {
        if (! file_exists($this->path)) {
            return null;
        }

        $raw = base64_decode(file_get_contents($this->path), true);

        if ($raw === false || strlen($raw) <= SODIUM_CRYPTO_SECRETBOX_NONCEBYTES) {
            return null;
        }

        $nonce = substr($raw, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $ciphertext = substr($raw, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);
        $key = $this->deriveKey($productId, $activationSecret);

        $payload = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);

        if ($payload === false) {
            return null;
        }

        $decoded = json_decode($payload, true);

        return is_array($decoded) ? $decoded : null;
    }

    public function clear(): void
    {
        if (file_exists($this->path)) {
            unlink($this->path);
        }
    }

    private function deriveKey(string $productId, string $activationSecret): string
    {
        return sodium_crypto_generichash($productId.'|'.$activationSecret, '', SODIUM_CRYPTO_SECRETBOX_KEYBYTES);
    }

    private function ensureDirectoryExists(string $directory): void
    {
        if (! is_dir($directory)) {
            mkdir($directory, 0755, true);
        }
    }
}
