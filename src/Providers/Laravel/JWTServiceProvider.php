<?php
namespace Xaamin\JWT\Providers\Laravel;

use Config;
use Xaamin\JWT\JWT;
use Xaamin\JWT\Factory;
use Xaamin\JWT\Signer\Native;
use Xaamin\JWT\Validation\PayloadValidation;
use Illuminate\Support\ServiceProvider;

class JWTServiceProvider extends ServiceProvider
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
        $this->app->singleton('Xaamin\JWT\JWT', function ($app) {
            $secret = Config::get('jwt.secret');
            $algo = Config::get('jwt.algorithm');
            $keys = Config::get('jwt.keys');

            $payloadValidation = new PayloadValidation;
            $factory = new Factory($payloadValidation);            
            $signer = new Native($secret, $algo, $keys);

            return new JWT($signer, $factory);
        });
    }
}
