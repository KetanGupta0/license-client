<?php

namespace Finext\LicenseClient\Services;

use Illuminate\Support\Facades\Http;

/**
 * Verifies the {data, signature, key_id} envelope every license-server
 * response is wrapped in. Signature = authenticity: the server never
 * discloses its private key, so a verified response genuinely came from it —
 * even a customer who fully decompiles this package cannot forge one.
 */
class ResponseVerifier
{
    public function __construct(private array $config)
    {
    }

    /**
     * @param  array{data?: array, signature?: string, key_id?: string}  $envelope
     */
    public function verify(array $envelope): bool
    {
        if (! isset($envelope['data'], $envelope['signature'], $envelope['key_id']) || ! is_array($envelope['data'])) {
            return false;
        }

        $publicKey = $this->resolvePublicKey($envelope['key_id']);

        if (! $publicKey) {
            return false;
        }

        $decodedKey = base64_decode($publicKey, true);
        $signatureBytes = base64_decode($envelope['signature'], true);

        if ($decodedKey === false || $signatureBytes === false) {
            return false;
        }

        $canonical = HmacSigner::canonicalJson($envelope['data']);

        try {
            return sodium_crypto_sign_verify_detached($signatureBytes, $canonical, $decodedKey);
        } catch (\SodiumException) {
            return false;
        }
    }

    /**
     * Refresh the locally cached public key(s) from the server. Safe to call
     * opportunistically (e.g. once a day) — never trusted blindly, only ever
     * used to *supplement* the pinned key, and every response is still
     * verified byte-for-byte regardless of where its key came from.
     */
    public function fetchAndCachePublicKey(): bool
    {
        try {
            $response = Http::timeout($this->config['timeout_seconds'])
                ->get(rtrim($this->config['server_url'], '/').'/api/v1/license/public-key');
        } catch (\Throwable) {
            return false;
        }

        if (! $response->successful()) {
            return false;
        }

        $body = $response->json();

        if (! isset($body['key_id'], $body['public_key'])) {
            return false;
        }

        $cached = $this->loadCachedKeys();
        $cached[$body['key_id']] = $body['public_key'];

        $directory = dirname($this->config['public_key_cache_path']);

        if (! is_dir($directory)) {
            mkdir($directory, 0755, true);
        }

        file_put_contents($this->config['public_key_cache_path'], json_encode($cached));

        return true;
    }

    private function resolvePublicKey(string $keyId): ?string
    {
        if ($keyId === $this->config['pinned_key_id'] && $this->config['pinned_public_key']) {
            return $this->config['pinned_public_key'];
        }

        return $this->loadCachedKeys()[$keyId] ?? null;
    }

    private function loadCachedKeys(): array
    {
        $path = $this->config['public_key_cache_path'];

        if (! is_string($path) || ! file_exists($path)) {
            return [];
        }

        $data = json_decode(file_get_contents($path), true);

        return is_array($data) ? $data : [];
    }
}
