<?php

namespace Finext\LicenseClient\Console\Commands;

use Finext\LicenseClient\LicenseManager;
use Illuminate\Console\Command;

class ActivateLicense extends Command
{
    protected $signature = 'license:activate
        {key? : License key (prompts if omitted)}
        {--domain= : Domain to bind this installation to (defaults to APP_URL host)}
        {--label= : A human-readable label for this installation}';

    protected $description = 'Activate this installation against the Finext License Server';

    public function handle(LicenseManager $license): int
    {
        if ($license->isActivated()) {
            if (! $this->confirm('This installation already has an activation secret stored. Re-activate anyway?')) {
                return self::SUCCESS;
            }
        }

        $key = $this->argument('key') ?? config('license-client.license_key') ?? $this->ask('Enter your license key');
        $domain = $this->option('domain') ?? parse_url(config('app.url'), PHP_URL_HOST);

        $this->info("Activating installation {$license->installationId()}...");

        $result = $license->activate($key, $domain, null, $this->option('label'));

        if (! $result['ok']) {
            $this->error('Activation failed: '.($result['error'] ?? 'unknown_error'));

            return self::FAILURE;
        }

        $this->info('✔ Activated successfully.');
        $this->line('  Status:  '.$result['data']['status']);
        $this->line('  Expires: '.($result['data']['license']['expires_at'] ?? 'never'));

        return self::SUCCESS;
    }
}
