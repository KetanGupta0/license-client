<?php

namespace Finext\LicenseClient;

use Finext\LicenseClient\Console\Commands\ActivateLicense;
use Finext\LicenseClient\Http\Middleware\EnsureLicenseIsValid;
use Finext\LicenseClient\Services\EncryptedLocalCache;
use Finext\LicenseClient\Services\GracePeriodPolicy;
use Finext\LicenseClient\Services\ResponseVerifier;
use Illuminate\Support\ServiceProvider;

class LicenseClientServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/license-client.php', 'license-client');

        $this->app->singleton(ResponseVerifier::class, fn ($app) => new ResponseVerifier($app['config']['license-client']));

        $this->app->singleton(EncryptedLocalCache::class, fn ($app) => new EncryptedLocalCache(
            $app['config']['license-client']['cache_path'],
        ));

        $this->app->singleton(LicenseManager::class, fn ($app) => new LicenseManager(
            $app['config']['license-client'],
            $app->make(ResponseVerifier::class),
            $app->make(EncryptedLocalCache::class),
            new GracePeriodPolicy,
        ));
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/license-client.php' => config_path('license-client.php'),
            ], 'license-client-config');

            $this->commands([
                ActivateLicense::class,
            ]);
        }

        $this->app['router']->aliasMiddleware('license.valid', EnsureLicenseIsValid::class);
    }
}
