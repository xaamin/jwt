<?php

namespace Xaamin\Jwt\Console;

use Illuminate\Support\Str;
use Illuminate\Console\Command;

class GenerateSecretCommand extends Command
{
    /**
     * The console command signature.
     *
     * @var string
     */
    protected $signature = 'jwt:secret
        {--f|force : Skip confirmation when overwriting an existing key.}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Set the JWTAuth secret key used to sign the tokens';

    /**
     * Execute the console command.
     *
     * @return void
     */
    public function handle()
    {
        $path = base_path('.env');
        $key = Str::random(64);

        if (Str::contains(file_get_contents($path), 'JWT_SECRET') === false) {
            file_put_contents($path, PHP_EOL . "JWT_SECRET=$key" . PHP_EOL, FILE_APPEND);
        } else {
            if (!$this->option('force')) {
                $this->comment('Secret key already exist. Use the --force option to overwrite it.');

                return;
            }

            file_put_contents(
                $path,
                str_replace(
                    'JWT_SECRET=' . $this->laravel['config']['jwt.secret'],
                    'JWT_SECRET=' . $key,
                    file_get_contents($path)
                )
            );
        }

        $this->displayKey($key);
    }

    /**
     * Display the key.
     *
     * @param  string $key
     * @return void
     */
    protected function displayKey($key)
    {
        $this->laravel['config']['jwt.secret'] = $key;

        $this->info("jwt-auth secret [$key] set successfully.");
    }
}
