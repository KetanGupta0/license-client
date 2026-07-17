<?php

namespace Finext\LicenseClient\Tests;

use Finext\LicenseClient\Services\HmacSigner;
use Finext\LicenseClient\Services\ResponseVerifier;
use PHPUnit\Framework\TestCase;

class ResponseVerifierTest extends TestCase
{
    private string $publicKey;

    private string $privateKey;

    protected function setUp(): void
    {
        $keypair = sodium_crypto_sign_keypair();
        $this->publicKey = base64_encode(sodium_crypto_sign_publickey($keypair));
        $this->privateKey = sodium_crypto_sign_secretkey($keypair);
    }

    private function config(): array
    {
        return [
            'pinned_key_id' => 'v1',
            'pinned_public_key' => $this->publicKey,
            'public_key_cache_path' => sys_get_temp_dir().'/license-client-nonexistent-'.bin2hex(random_bytes(4)).'.json',
        ];
    }

    private function sign(array $data): array
    {
        $canonical = HmacSigner::canonicalJson($data);
        $signature = base64_encode(sodium_crypto_sign_detached($canonical, $this->privateKey));

        return ['data' => $data, 'signature' => $signature, 'key_id' => 'v1'];
    }

    public function test_verifies_a_genuinely_signed_envelope(): void
    {
        $verifier = new ResponseVerifier($this->config());
        $envelope = $this->sign(['status' => 'active', 'license' => ['key' => 'ABC-123']]);

        $this->assertTrue($verifier->verify($envelope));
    }

    public function test_rejects_tampered_data_after_signing(): void
    {
        $verifier = new ResponseVerifier($this->config());
        $envelope = $this->sign(['status' => 'active']);

        $envelope['data']['status'] = 'revoked';

        $this->assertFalse($verifier->verify($envelope));
    }

    public function test_rejects_signature_from_a_different_keypair(): void
    {
        $verifier = new ResponseVerifier($this->config());
        $envelope = $this->sign(['status' => 'active']);

        $otherKeypair = sodium_crypto_sign_keypair();
        $envelope['signature'] = base64_encode(sodium_crypto_sign_detached(
            HmacSigner::canonicalJson($envelope['data']),
            sodium_crypto_sign_secretkey($otherKeypair),
        ));

        $this->assertFalse($verifier->verify($envelope));
    }

    public function test_rejects_unknown_key_id(): void
    {
        $verifier = new ResponseVerifier($this->config());
        $envelope = $this->sign(['status' => 'active']);
        $envelope['key_id'] = 'v2-never-fetched';

        $this->assertFalse($verifier->verify($envelope));
    }

    public function test_rejects_envelope_missing_required_fields(): void
    {
        $verifier = new ResponseVerifier($this->config());

        $this->assertFalse($verifier->verify(['data' => ['status' => 'active']]));
        $this->assertFalse($verifier->verify(['signature' => 'x', 'key_id' => 'v1']));
    }
}
