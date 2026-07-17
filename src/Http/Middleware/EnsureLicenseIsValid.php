<?php

namespace Finext\LicenseClient\Http\Middleware;

use Closure;
use Finext\LicenseClient\LicenseManager;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureLicenseIsValid
{
    public function __construct(private LicenseManager $license)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $result = $this->license->check();

        if (! $result['valid']) {
            abort(403, "License check failed ({$result['status']}). Please contact support to resolve your license.");
        }

        return $next($request);
    }
}
