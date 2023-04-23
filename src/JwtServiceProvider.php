<?php

namespace Xaamin\Jwt;

use Xaamin\Jwt\Jwt;
use Xaamin\Jwt\Factory;
use Xaamin\Jwt\Signer\Native;
use Illuminate\Support\ServiceProvider;
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
            ], 'jwt-config');
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

        $this->app->singleton(Jwt::class, function ($app) {
            $passphrase = config('jwt.passphrase');
            $algo = config('jwt.algorithm');
            $keys = array_filter(config('jwt.keys'));

            $passphrase = !empty($keys) && !empty($keys['passphrase']) ? $keys['passphrase'] : $passphrase;

            $factory = new Factory();
            $signer = new Native($passphrase, $algo, $keys);

            return new Jwt($signer, $factory);
        });
    }
}
