<?php

namespace Finext\LicenseClient\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static array activate(?string $licenseKey = null, ?string $domain = null, ?string $serverIp = null, ?string $label = null, ?string $appVersion = null)
 * @method static array verify(?string $domain = null, ?string $appVersion = null)
 * @method static array heartbeat(?string $appVersion = null)
 * @method static array deactivate()
 * @method static array check()
 * @method static bool isActivated()
 * @method static string installationId()
 * @method static void forget()
 *
 * @see \Finext\LicenseClient\LicenseManager
 */
class License extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return \Finext\LicenseClient\LicenseManager::class;
    }
}
