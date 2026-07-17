<?php

namespace Finext\LicenseClient\Tests;

use Finext\LicenseClient\Services\HmacSigner;
use PHPUnit\Framework\TestCase;

class HmacSignerTest extends TestCase
{
    /**
     * Golden vector cross-checked against the license-server's own
     * HmacSigner (same body, same output) — if this ever fails, the two
     * implementations have drifted and every signed request will start
     * failing with invalid_signature.
     */
    public function test_canonical_json_matches_server_golden_vector(): void
    {
        $body = ['b' => 2, 'a' => 1, 'nested' => ['z' => 1, 'y' => 2]];

        $this->assertSame(
            '{"a":1,"b":2,"nested":{"y":2,"z":1}}',
            HmacSigner::canonicalJson($body),
        );
    }

    public function test_canonical_string_matches_server_golden_vector(): void
    {
        $body = ['b' => 2, 'a' => 1, 'nested' => ['z' => 1, 'y' => 2]];

        $canonical = HmacSigner::canonicalString('POST', 'api/v1/license/verify', $body, '1700000000', 'abc123');

        $this->assertSame(
            "POST\napi/v1/license/verify\n{\"a\":1,\"b\":2,\"nested\":{\"y\":2,\"z\":1}}\n1700000000\nabc123",
            $canonical,
        );

        $this->assertSame(
            'd709c6b6b7c8ba4ead6569a79d4f0a6c8a685996525901c303d9aef638f5603d',
            HmacSigner::sign($canonical, 'supersecret'),
        );
    }

    public function test_verify_accepts_matching_signature(): void
    {
        $canonical = HmacSigner::canonicalString('POST', 'api/v1/license/activate', ['x' => 1], '123', 'nonce');
        $signature = HmacSigner::sign($canonical, 'secret');

        $this->assertTrue(HmacSigner::verify($canonical, 'secret', $signature));
    }

    public function test_verify_rejects_wrong_secret(): void
    {
        $canonical = HmacSigner::canonicalString('POST', 'api/v1/license/activate', ['x' => 1], '123', 'nonce');
        $signature = HmacSigner::sign($canonical, 'secret');

        $this->assertFalse(HmacSigner::verify($canonical, 'wrong-secret', $signature));
    }

    public function test_verify_rejects_tampered_body(): void
    {
        $secret = 'secret';
        $originalCanonical = HmacSigner::canonicalString('POST', 'api/v1/license/activate', ['amount' => 100], '123', 'nonce');
        $signature = HmacSigner::sign($originalCanonical, $secret);

        $tamperedCanonical = HmacSigner::canonicalString('POST', 'api/v1/license/activate', ['amount' => 999], '123', 'nonce');

        $this->assertFalse(HmacSigner::verify($tamperedCanonical, $secret, $signature));
    }

    public function test_generate_nonce_produces_unique_hex_strings(): void
    {
        $a = HmacSigner::generateNonce();
        $b = HmacSigner::generateNonce();

        $this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $a);
        $this->assertNotSame($a, $b);
    }
}
