<?php

namespace Xaamin\Jwt;

use Xaamin\Jwt\Jwt;
use Xaamin\Jwt\Factory;
use Xaamin\Jwt\Signer\Native;
use Illuminate\Support\ServiceProvider;
use Xaamin\Jwt\Console\GenerateKeysCommand;
use Xaamin\Jwt\Console\GenerateSecretCommand;
use Xaamin\Jwt\Middleware\RefreshTokenMiddleware;
use Xaamin\Jwt\Middleware\ValidateTokenMiddleware;

class JwtServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
        if (app()->runningInConsole()) {
            $this->publishes([
                __DIR__ . '/../config/jwt.php' => base_path('config/jwt.php'),
            ], 'config');

            $this->registerCommands();
        } else {
            if (app() instanceof \Illuminate\Foundation\Application) {
                // Laravel
                $router = $this->app['router'];
                $router->aliasMiddleware('jwt.check', ValidateTokenMiddleware::class);
                $router->aliasMiddleware('jwt.refresh', RefreshTokenMiddleware::class);
            } else {
                // Lumen
            }
        }
    }

    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/jwt.php', 'jwt');

        $this->registerJwtSingleton();
    }

    protected function registerCommands()
    {
        $this->commands([
            GenerateSecretCommand::class,
            GenerateKeysCommand::class
        ]);
    }

    protected function registerJwtSingleton()
    {
        $this->app->singleton(Jwt::class, function ($app) {
            /** @var string[] */
            $requiredClaims = config('jwt.required_claims', []);
            $passphrase = strval(config('jwt.passphrase'));
            $algo = strval(config('jwt.algorithm'));
            $leeway = intval(config('jwt.refresh_ttl'));
            /** @var string|null */
            $issuer = config('jwt.issuer');
            /** @var int|null */
            $ttl = config('jwt.ttl');
            /** @var int|null */
            $refreshTtl = config('jwt.refresh_ttl');
            /** @var array<string,string> */
            $keys = config('jwt.keys') ?? [];

            $passphrase = !empty($keys) && !empty($keys['passphrase']) ? $keys['passphrase'] : $passphrase;

            $factory = new Factory();
            $signer = new Native($passphrase, $algo, $keys);

            $jwt = new Jwt($signer, $factory);

            $jwt->setTtl($ttl);
            $jwt->setLeeway($leeway);
            $jwt->setIssuer($issuer);
            $jwt->setRefreshTtl($refreshTtl);
            $jwt->setRequiredClaims($requiredClaims);

            return $jwt;
        });
    }
}
