<?php

namespace Xaamin\Jwt;

use Xaamin\Jwt\Jwt;
use Xaamin\Jwt\Factory;
use Xaamin\Jwt\Signer\Native;
use Illuminate\Support\ServiceProvider;

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
        }
    }

    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton(Jwt::class, function ($app) {
            $passphrase = config('jwt.passphrase');
            $algo = config('jwt.algorithm');
            $keys = config('jwt.keys');

            $factory = new Factory();
            $signer = new Native($passphrase, $algo, $keys);

            return new Jwt($signer, $factory);
        });
    }
}
