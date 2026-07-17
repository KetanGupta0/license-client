<?php

namespace Finext\LicenseClient\Tests;

use Finext\LicenseClient\Services\GracePeriodPolicy;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\TestCase;

class GracePeriodPolicyTest extends TestCase
{
    protected function setUp(): void
    {
        Carbon::setTestNow('2026-01-10 00:00:00');
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();
    }

    public function test_within_grace_period(): void
    {
        $policy = new GracePeriodPolicy;
        $lastVerified = new \DateTimeImmutable('2026-01-08 00:00:00');

        $this->assertTrue($policy->isWithinGrace($lastVerified, 7));
    }

    public function test_exactly_at_grace_period_boundary_is_still_valid(): void
    {
        $policy = new GracePeriodPolicy;
        $lastVerified = new \DateTimeImmutable('2026-01-03 00:00:00');

        $this->assertTrue($policy->isWithinGrace($lastVerified, 7));
    }

    public function test_past_grace_period_is_invalid(): void
    {
        $policy = new GracePeriodPolicy;
        $lastVerified = new \DateTimeImmutable('2026-01-01 00:00:00');

        $this->assertFalse($policy->isWithinGrace($lastVerified, 7));
    }

    public function test_days_remaining_counts_down(): void
    {
        $policy = new GracePeriodPolicy;
        $lastVerified = new \DateTimeImmutable('2026-01-08 00:00:00');

        $this->assertSame(5, $policy->daysRemaining($lastVerified, 7));
    }

    public function test_days_remaining_is_zero_once_expired(): void
    {
        $policy = new GracePeriodPolicy;
        $lastVerified = new \DateTimeImmutable('2025-12-01 00:00:00');

        $this->assertSame(0, $policy->daysRemaining($lastVerified, 7));
    }
}
