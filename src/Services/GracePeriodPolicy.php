<?php

namespace Finext\LicenseClient\Services;

use Illuminate\Support\Carbon;

/**
 * Decides whether the host app may keep running while the license server is
 * unreachable, based on the grace period the server itself returned on the
 * last successful verification (not a value the client can inflate).
 */
class GracePeriodPolicy
{
    public function isWithinGrace(\DateTimeInterface $lastVerifiedAt, int $gracePeriodDays): bool
    {
        return Carbon::now()->lessThanOrEqualTo(
            Carbon::instance($lastVerifiedAt)->addDays($gracePeriodDays),
        );
    }

    public function daysRemaining(\DateTimeInterface $lastVerifiedAt, int $gracePeriodDays): int
    {
        $deadline = Carbon::instance($lastVerifiedAt)->addDays($gracePeriodDays);

        if (Carbon::now()->greaterThan($deadline)) {
            return 0;
        }

        return (int) ceil(Carbon::now()->floatDiffInDays($deadline, false));
    }
}
