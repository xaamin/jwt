<?php

namespace Xaamin\Jwt\Providers\Laravel;

use Xaamin\Jwt\Jwt;
use Xaamin\Jwt\Factory;
use Xaamin\Jwt\Signer\Native;
use Illuminate\Support\ServiceProvider;
use Xaamin\Jwt\Validation\PayloadValidation;

class JwtServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap any application services.
     *
     * @return void
     */
    public function boot()
    {
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
