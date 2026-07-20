<?php

namespace Finext\LicenseClient\Tests;

use Finext\LicenseClient\LicenseClientServiceProvider;
use Finext\LicenseClient\LicenseManager;
use Finext\LicenseClient\Services\EncryptedLocalCache;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase;

/**
 * Regression coverage for check()'s cache-fallback rule: only a genuine
 * connectivity failure (no HTTP response at all) should fall back to the
 * offline grace period. A response that actually reached the server — even
 * a rejection like domain_mismatch — must be treated as authoritative and
 * never papered over by a stale cached "valid" result.
 */
class LicenseManagerCheckTest extends TestCase
{
    private string $tempDir;

    protected function getPackageProviders($app): array
    {
        return [LicenseClientServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $this->tempDir = sys_get_temp_dir().'/license-client-manager-test-'.bin2hex(random_bytes(4));
        mkdir($this->tempDir, 0755, true);

        $app['config']->set('license-client.server_url', 'https://license.test');
        $app['config']->set('license-client.product_id', 1);
        $app['config']->set('license-client.license_key', 'TEST-KEY');
        $app['config']->set('license-client.installation_id_path', $this->tempDir.'/installation-id');
        $app['config']->set('license-client.activation_secret_path', $this->tempDir.'/activation-secret');
        $app['config']->set('license-client.cache_path', $this->tempDir.'/cache.dat');
        $app['config']->set('license-client.public_key_cache_path', $this->tempDir.'/public-key.json');
        $app['config']->set('license-client.default_grace_period_days', 3);
        $app['config']->set('license-client.timeout_seconds', 5);
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tempDir)) {
            array_map('unlink', glob("{$this->tempDir}/*"));
            rmdir($this->tempDir);
        }

        parent::tearDown();
    }

    private function activate(): void
    {
        file_put_contents(config('license-client.activation_secret_path'), 'test-activation-secret');
    }

    /** Seed the cache with a "known good" prior verification, without needing a real Ed25519 signature — retrieve() never re-checks that, only the cache's own AES-GCM authentication does. */
    private function seedCache(): void
    {
        app(EncryptedLocalCache::class)->store(
            ['data' => ['status' => 'active', 'installation' => ['grace_period_days' => 3]]],
            '1',
            'test-activation-secret',
            new \DateTimeImmutable,
        );
    }

    public function test_domain_mismatch_is_reported_invalid_immediately_not_masked_by_cache(): void
    {
        $this->activate();
        $this->seedCache();

        Http::fake([
            'license.test/*' => Http::response(['error' => 'domain_mismatch'], 409),
        ]);

        $result = app(LicenseManager::class)->check();

        $this->assertFalse($result['valid']);
        $this->assertSame('domain_mismatch', $result['status']);
        $this->assertSame('live', $result['source']);
    }

    public function test_genuine_network_failure_still_falls_back_to_cached_grace_period(): void
    {
        $this->activate();
        $this->seedCache();

        Http::fake(function () {
            throw new \Illuminate\Http\Client\ConnectionException('Could not resolve host');
        });

        $result = app(LicenseManager::class)->check();

        $this->assertTrue($result['valid']);
        $this->assertSame('grace_period', $result['status']);
        $this->assertSame('cache', $result['source']);
    }
}
