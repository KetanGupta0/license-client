<?php

namespace Finext\LicenseClient;

use Finext\LicenseClient\Services\EncryptedLocalCache;
use Finext\LicenseClient\Services\GracePeriodPolicy;
use Finext\LicenseClient\Services\HmacSigner;
use Finext\LicenseClient\Services\ResponseVerifier;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class LicenseManager
{
    private ?string $installationId = null;

    public function __construct(
        private array $config,
        private ResponseVerifier $verifier,
        private EncryptedLocalCache $cache,
        private GracePeriodPolicy $gracePeriod,
    ) {
    }

    public function installationId(): string
    {
        if ($this->installationId !== null) {
            return $this->installationId;
        }

        $path = $this->config['installation_id_path'];

        if (file_exists($path)) {
            return $this->installationId = trim(file_get_contents($path));
        }

        $id = (string) Str::uuid();
        $this->ensureDirectoryExists(dirname($path));
        file_put_contents($path, $id);
        @chmod($path, 0600);

        return $this->installationId = $id;
    }

    public function isActivated(): bool
    {
        return $this->activationSecret() !== null;
    }

    /**
     * First-time (or re-sync) activation, signed with the product's shared
     * bootstrap secret. See HmacSigner/ResponseVerifier docblocks — this is
     * the one call that does *not* prove license ownership on its own.
     */
    public function activate(?string $licenseKey = null, ?string $domain = null, ?string $serverIp = null, ?string $label = null, ?string $appVersion = null): array
    {
        $body = array_filter([
            'license_key' => $licenseKey ?? $this->config['license_key'],
            'installation_id' => $this->installationId(),
            'domain' => $domain ?? request()?->getHost(),
            'server_ip' => $serverIp,
            'label' => $label,
            'app_version' => $appVersion,
        ], fn ($value) => $value !== null);

        $result = $this->signedRequest('/api/v1/license/activate', $body, $this->config['bootstrap_secret'], [
            'X-Product-Id' => (string) $this->config['product_id'],
            'X-Key-Id' => $this->config['bootstrap_key_id'],
        ]);

        if ($result['ok'] && isset($result['envelope']['data']['installation']['activation_secret'])) {
            $this->storeActivationSecret($result['envelope']['data']['installation']['activation_secret']);
        }

        if ($result['ok']) {
            $this->rememberGoodResponse($result['envelope']);
        }

        return $this->toResult($result);
    }

    public function verify(?string $domain = null, ?string $appVersion = null): array
    {
        return $this->activationSignedCall('/api/v1/license/verify', array_filter([
            'license_key' => $this->config['license_key'],
            'domain' => $domain ?? request()?->getHost(),
            'app_version' => $appVersion,
        ], fn ($value) => $value !== null));
    }

    public function heartbeat(?string $appVersion = null): array
    {
        return $this->activationSignedCall('/api/v1/license/heartbeat', array_filter([
            'license_key' => $this->config['license_key'],
            'app_version' => $appVersion,
        ], fn ($value) => $value !== null));
    }

    public function deactivate(): array
    {
        $result = $this->activationSignedCall('/api/v1/license/deactivate', [
            'license_key' => $this->config['license_key'],
        ]);

        $this->forget();

        return $result;
    }

    /**
     * The entry point host apps/middleware should actually call: verify
     * live when possible, otherwise fall back to the signed local cache and
     * the offline grace period. Never throws — always returns a definitive
     * valid/invalid answer plus the reason, so a middleware can act on it.
     */
    public function check(): array
    {
        if (! $this->isActivated()) {
            return ['valid' => false, 'status' => 'not_activated', 'source' => null, 'days_remaining' => null];
        }

        $live = $this->verify();

        if ($live['ok']) {
            return [
                'valid' => $live['data']['status'] === 'active',
                'status' => $live['data']['status'],
                'source' => 'live',
                'days_remaining' => $live['data']['license']['days_remaining'] ?? null,
                'data' => $live['data'],
            ];
        }

        // The offline grace period exists for genuine connectivity failure
        // (couldn't reach the server at all) — a status_code of null is the
        // only case that means that. Any actual HTTP response — even an
        // error one like domain_mismatch/ip_mismatch/activation_not_found —
        // means the server was reached and gave a definitive answer, which
        // must not be papered over by falling back to a stale cached
        // "valid" result from before the rejection (this was exactly the
        // gap that let an install keep running on a de-whitelisted domain
        // for up to the grace period after being explicitly rejected).
        if ($live['status_code'] !== null) {
            return [
                'valid' => false,
                'status' => $live['error'] ?? 'rejected',
                'source' => 'live',
                'days_remaining' => null,
                'data' => null,
            ];
        }

        $cached = $this->cache->retrieve((string) $this->config['product_id'], (string) $this->activationSecret());

        if (! $cached) {
            return ['valid' => false, 'status' => 'unreachable_no_cache', 'source' => null, 'days_remaining' => null];
        }

        $verifiedAt = Carbon::parse($cached['verified_at']);
        $gracePeriodDays = $cached['envelope']['data']['installation']['grace_period_days'] ?? $this->config['default_grace_period_days'];
        $withinGrace = $this->gracePeriod->isWithinGrace($verifiedAt, $gracePeriodDays);

        return [
            'valid' => $withinGrace && ($cached['envelope']['data']['status'] ?? null) === 'active',
            'status' => $withinGrace ? 'grace_period' : 'grace_period_expired',
            'source' => 'cache',
            'days_remaining' => $this->gracePeriod->daysRemaining($verifiedAt, $gracePeriodDays),
            'data' => $cached['envelope']['data'],
        ];
    }

    /**
     * Clears all local state (installation ID kept, activation secret and
     * cache removed) — used after a successful /deactivate call, or if the
     * host app wants to force a fresh activation.
     */
    public function forget(): void
    {
        $path = $this->config['activation_secret_path'];

        if (file_exists($path)) {
            unlink($path);
        }

        $this->cache->clear();
    }

    private function activationSignedCall(string $path, array $body): array
    {
        $secret = $this->activationSecret();

        if (! $secret) {
            return ['ok' => false, 'error' => 'not_activated', 'status_code' => null, 'data' => null];
        }

        $result = $this->signedRequest($path, $body, $secret, [
            'X-Product-Id' => (string) $this->config['product_id'],
            'X-Installation-Id' => $this->installationId(),
        ]);

        if ($result['ok']) {
            $this->rememberGoodResponse($result['envelope']);
        }

        return $this->toResult($result);
    }

    private function toResult(array $result): array
    {
        return [
            'ok' => $result['ok'],
            'data' => $result['envelope']['data'] ?? null,
            'error' => $result['error'] ?? null,
            'status_code' => $result['status_code'],
        ];
    }

    private function rememberGoodResponse(array $envelope): void
    {
        $secret = $this->activationSecret();

        if (! $secret) {
            return;
        }

        $this->cache->store($envelope, (string) $this->config['product_id'], $secret, Carbon::now());
    }

    /**
     * Signs and sends one request, verifying the response envelope before
     * trusting anything in it. A response that fails signature verification
     * is treated identically to a network failure — never surfaced as if
     * it were a real server answer.
     */
    private function signedRequest(string $path, array $body, string $secret, array $extraHeaders): array
    {
        $timestamp = (string) time();
        $nonce = HmacSigner::generateNonce();
        $canonical = HmacSigner::canonicalString('POST', ltrim($path, '/'), $body, $timestamp, $nonce);
        $signature = HmacSigner::sign($canonical, $secret);

        try {
            $response = Http::timeout($this->config['timeout_seconds'])
                ->withHeaders(array_merge($extraHeaders, [
                    'X-Timestamp' => $timestamp,
                    'X-Nonce' => $nonce,
                    'X-Signature' => $signature,
                ]))
                ->post(rtrim($this->config['server_url'], '/').$path, $body);
        } catch (\Throwable $e) {
            return ['ok' => false, 'error' => 'network_error', 'status_code' => null, 'envelope' => null];
        }

        $json = $response->json();

        if (! $response->successful()) {
            return ['ok' => false, 'error' => $json['error'] ?? 'http_error', 'status_code' => $response->status(), 'envelope' => null];
        }

        if (! is_array($json) || ! $this->verifier->verify($json)) {
            return ['ok' => false, 'error' => 'response_signature_invalid', 'status_code' => $response->status(), 'envelope' => null];
        }

        return ['ok' => true, 'error' => null, 'status_code' => $response->status(), 'envelope' => $json];
    }

    private function activationSecret(): ?string
    {
        $path = $this->config['activation_secret_path'];

        return file_exists($path) ? trim(file_get_contents($path)) : null;
    }

    private function storeActivationSecret(string $secret): void
    {
        $path = $this->config['activation_secret_path'];
        $this->ensureDirectoryExists(dirname($path));
        file_put_contents($path, $secret);
        @chmod($path, 0600);
    }

    private function ensureDirectoryExists(string $directory): void
    {
        if (! is_dir($directory)) {
            mkdir($directory, 0755, true);
        }
    }
}
