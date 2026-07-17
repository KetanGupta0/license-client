<?php

namespace Finext\LicenseClient\Tests;

use Finext\LicenseClient\Services\EncryptedLocalCache;
use PHPUnit\Framework\TestCase;

class EncryptedLocalCacheTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = sys_get_temp_dir().'/license-client-test-'.bin2hex(random_bytes(4)).'/cache.dat';
    }

    protected function tearDown(): void
    {
        if (file_exists($this->path)) {
            unlink($this->path);
        }

        if (is_dir(dirname($this->path))) {
            rmdir(dirname($this->path));
        }
    }

    public function test_store_and_retrieve_round_trip(): void
    {
        $cache = new EncryptedLocalCache($this->path);
        $envelope = ['data' => ['status' => 'active'], 'signature' => 'sig', 'key_id' => 'v1'];

        $cache->store($envelope, 'product-1', 'activation-secret-abc', new \DateTimeImmutable('2026-01-01T00:00:00Z'));

        $result = $cache->retrieve('product-1', 'activation-secret-abc');

        $this->assertNotNull($result);
        $this->assertSame($envelope, $result['envelope']);
        $this->assertSame('2026-01-01T00:00:00+00:00', $result['verified_at']);
    }

    public function test_retrieve_fails_closed_with_wrong_activation_secret(): void
    {
        $cache = new EncryptedLocalCache($this->path);
        $cache->store(['data' => ['status' => 'active']], 'product-1', 'correct-secret', new \DateTimeImmutable);

        $this->assertNull($cache->retrieve('product-1', 'wrong-secret'));
    }

    public function test_retrieve_fails_closed_with_wrong_product_id(): void
    {
        $cache = new EncryptedLocalCache($this->path);
        $cache->store(['data' => ['status' => 'active']], 'product-1', 'secret', new \DateTimeImmutable);

        $this->assertNull($cache->retrieve('product-2', 'secret'));
    }

    public function test_retrieve_fails_closed_on_tampered_ciphertext(): void
    {
        $cache = new EncryptedLocalCache($this->path);
        $cache->store(['data' => ['status' => 'active']], 'product-1', 'secret', new \DateTimeImmutable);

        // Flip a byte in the middle of the stored (base64) ciphertext.
        $raw = file_get_contents($this->path);
        $raw[10] = $raw[10] === 'A' ? 'B' : 'A';
        file_put_contents($this->path, $raw);

        $this->assertNull($cache->retrieve('product-1', 'secret'));
    }

    public function test_retrieve_returns_null_when_file_missing(): void
    {
        $cache = new EncryptedLocalCache($this->path);

        $this->assertNull($cache->retrieve('product-1', 'secret'));
    }

    public function test_clear_removes_the_file(): void
    {
        $cache = new EncryptedLocalCache($this->path);
        $cache->store(['data' => []], 'product-1', 'secret', new \DateTimeImmutable);

        $this->assertFileExists($this->path);

        $cache->clear();

        $this->assertFileDoesNotExist($this->path);
    }
}
